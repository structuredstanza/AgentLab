"use client";

import * as React from "react";

import Link from "next/link";

import {
  ActivityIcon,
  ArrowUpRightIcon,
  BugIcon,
  ClockIcon,
  NetworkIcon,
  ShieldCheckIcon,
  TargetIcon,
  ZapIcon,
} from "lucide-react";
import { useTranslations } from "next-intl";
import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts";

import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { type ChartConfig, ChartContainer, ChartTooltip, ChartTooltipContent } from "@/components/ui/chart";
import { Progress } from "@/components/ui/progress";
import { api } from "@/lib/api";
import { formatAllocationReset, markUsageStale } from "@/lib/subscription-usage";
import type {
  Activity,
  Agent,
  ConvTokenSummary,
  Finding,
  InterceptPending,
  LLMProfile,
  LLMProfileUsage,
  MCPServer,
  Settings,
  SkillItem,
  Stats,
  Task,
  TokenTotal,
  Tool,
  TrafficExchange,
  UsageStats,
} from "@/lib/types";
import { cn } from "@/lib/utils";

// ── helpers ──────────────────────────────────────────────────────────────────

// Compact relative time. Returns the "{n}{unit}" fragment, or null when there is
// no timestamp; the caller wraps it with the localized "{value} ago" suffix.
function fmtRel(ts?: string | number): string | null {
  if (!ts) return null;
  const ms = Date.now() - (typeof ts === "number" ? ts * 1000 : Date.parse(ts as string));
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
}

function fmtTokens(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1000) return (n / 1000).toFixed(1) + "k";
  return String(n);
}

// HTTP status is a real semantic class, not decoration: 2xx ok, 3xx redirect,
// 4xx client error, 5xx server error.
function statusColor(code: number): string {
  if (code < 300) return "text-success";
  if (code < 400) return "text-info";
  if (code < 500) return "text-warning";
  return "text-destructive";
}

function statusBg(code: number): string {
  if (code < 300) return "bg-success";
  if (code < 400) return "bg-info";
  if (code < 500) return "bg-warning";
  return "bg-destructive";
}

// ── sub-components ────────────────────────────────────────────────────────────

function LiveDot({ className }: { className?: string }) {
  return <span className={cn("inline-block size-1.5 shrink-0 rounded-full bg-success", className)} />;
}

// Open metric block: a hairline rule above the number instead of a nested card.
function Metric({
  icon: Icon,
  label,
  value,
  detail,
}: {
  icon: React.ElementType;
  label: string;
  value: React.ReactNode;
  detail: React.ReactNode;
}) {
  return (
    <div className="min-w-0 border-border border-t pt-2.5">
      <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
        <Icon className="size-3" /> {label}
      </div>
      <div className="mt-1 font-semibold text-2xl tabular-nums tracking-tight">{value}</div>
      <div className="mt-0.5 flex flex-wrap gap-x-2.5 gap-y-0.5 text-[10px]">{detail}</div>
    </div>
  );
}

function SectionTitle({
  icon: Icon,
  children,
  sub,
}: {
  icon: React.ElementType;
  children: React.ReactNode;
  sub?: React.ReactNode;
}) {
  return (
    <div className="mb-3 flex items-center justify-between">
      <div className="flex items-center gap-1.5 font-semibold text-xs">
        <Icon className="size-3.5 text-muted-foreground" />
        {children}
      </div>
      {sub && <span className="text-[10px] text-muted-foreground">{sub}</span>}
    </div>
  );
}

// ── page ─────────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const t = useTranslations("dashboard");
  const tStatus = useTranslations("status");
  const rel = (ts?: string | number) => {
    const v = fmtRel(ts);
    return v === null ? "—" : t("ago", { value: v });
  };
  const dailyTrendConfig = React.useMemo(
    () =>
      ({
        input: { label: t("chartInput"), color: "var(--chart-1)" },
        output: { label: t("chartOutput"), color: "var(--chart-2)" },
        cacheRead: { label: t("chartCacheRead"), color: "var(--chart-3)" },
      }) satisfies ChartConfig,
    [t],
  );

  // data state
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [findings, setFindings] = React.useState<Finding[]>([]);
  const [stats, setStats] = React.useState<Stats | null>(null);
  const [settings, setSettings] = React.useState<Settings | null>(null);
  const [pending, setPending] = React.useState<InterceptPending[]>([]);
  const [activity, setActivity] = React.useState<Activity[]>([]);
  const [tokens, setTokens] = React.useState<TokenTotal | null>(null);
  const [convTokens, setConvTokens] = React.useState<ConvTokenSummary[]>([]);
  const [usageStats, setUsageStats] = React.useState<UsageStats | null>(null);
  const [assetCounts, setAssetCounts] = React.useState<Record<string, number>>({});
  const [traffic, setTraffic] = React.useState<TrafficExchange[]>([]);
  const [agents, setAgents] = React.useState<Agent[]>([]);
  const [mcpServers, setMcpServers] = React.useState<MCPServer[]>([]);
  const [skills, setSkills] = React.useState<SkillItem[]>([]);
  const [tools, setTools] = React.useState<Tool[]>([]);
  const [llmProfiles, setLLMProfiles] = React.useState<LLMProfile[]>([]);
  const [subscriptionUsage, setSubscriptionUsage] = React.useState<LLMProfileUsage[]>([]);

  // The task list is the most expensive dashboard source. Poll it independently
  // so a large history cannot hold back every other dashboard panel.
  React.useEffect(() => {
    let alive = true;
    let loading = false;
    let signature = "";
    const load = async () => {
      if (loading) return;
      loading = true;
      try {
        const tr = await api.tasks();
        if (!alive) return;
        const nextSignature = JSON.stringify(tr.tasks);
        if (nextSignature !== signature) {
          signature = nextSignature;
          setTasks(tr.tasks);
        }
      } catch {
        /* transient errors — next poll retries */
      } finally {
        loading = false;
      }
    };
    void load();
    const t = setInterval(load, 5000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);
  // Subscription usage polling: polls every 120s and pauses when document is hidden.
  React.useEffect(() => {
    let alive = true;
    let timer: number | undefined;

    const fetchUsage = async () => {
      if (document.hidden) return;
      try {
        const res = await api.llmUsage();
        if (alive && res?.profiles) {
          setSubscriptionUsage(res.profiles);
        }
      } catch {
        if (alive) setSubscriptionUsage((current) => current.map(markUsageStale));
      }
    };

    void fetchUsage();

    const startInterval = () => {
      clearInterval(timer);
      timer = window.setInterval(() => {
        if (!document.hidden) {
          void fetchUsage();
        }
      }, 120_000);
    };

    startInterval();

    const handleVisibility = () => {
      if (!document.hidden) {
        void fetchUsage();
        startInterval();
      } else {
        clearInterval(timer);
        timer = undefined;
      }
    };

    document.addEventListener("visibilitychange", handleVisibility);

    return () => {
      alive = false;
      clearInterval(timer);
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, []);

  const visibleSubscriptions = React.useMemo(
    () => subscriptionUsage.filter((p) => p.connected || Boolean(p.error)),
    [subscriptionUsage],
  );

  // The remaining fast sources stay batched so one poll causes a single render.
  React.useEffect(() => {
    let alive = true;
    let loading = false;
    const load = async () => {
      if (loading) return;
      loading = true;
      try {
        const [findings, stats, settings, pending, activity, tokens, conversationTokens] = await Promise.all([
          api.findings(),
          api.stats(),
          api.settings(),
          api.interceptPending(),
          api.activity(undefined, { limit: 30 }),
          api.tokenStats(),
          api.conversationTokens(),
        ]);
        if (!alive) return;
        setFindings(findings);
        setStats(stats);
        setSettings(settings);
        setPending(pending);
        setActivity(activity.items);
        setTokens(tokens.total ?? null);
        setConvTokens(conversationTokens);
      } catch {
        // Preserve stale data and retry on the next interval.
      } finally {
        loading = false;
      }
    };
    void load();
    const timer = setInterval(load, 5000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, []);

  // slow poll: traffic, assets, system-static (every 15s)
  React.useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const [traf, counts, agentList, mcpList, skillList, toolList, profileList, usage] = await Promise.all([
          api.traffic(0, 50),
          api.assetCounts(),
          api.agents(),
          api.mcpServers(),
          api.skills(),
          api.tools(),
          api.llmProfiles(),
          api.usageStats(365),
        ]);
        if (!alive) return;
        setTraffic(traf.exchanges ?? []);
        setAssetCounts(counts ?? {});
        setAgents(agentList);
        setMcpServers(mcpList);
        setSkills(skillList);
        setTools(toolList);
        setLLMProfiles(profileList);
        setUsageStats(usage);
      } catch {
        /* transient errors */
      }
    };
    void load();
    const t = setInterval(load, 15000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  // ── derived ───────────────────────────────────────────────────────────────

  const tasksByStatus = React.useMemo(() => {
    const m: Record<string, number> = {};
    for (const t of tasks) m[t.status] = (m[t.status] ?? 0) + 1;
    return m;
  }, [tasks]);

  const findingsBySev = React.useMemo(() => {
    const m = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
      if (f.severity in m) m[f.severity as keyof typeof m]++;
    }
    return m;
  }, [findings]);

  const sortedTasks = React.useMemo(
    () =>
      [...tasks]
        .sort((a, b) => (b.last_activity_unix ?? b.created_unix ?? 0) - (a.last_activity_unix ?? a.created_unix ?? 0))
        .slice(0, 5),
    [tasks],
  );

  const recentFindings = React.useMemo(
    () => [...findings].sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts)).slice(0, 8),
    [findings],
  );

  const recentActivity = React.useMemo(
    () =>
      [...activity]
        .filter((a) => a.kind !== "usage")
        .sort((a, b) => b.seq - a.seq)
        .slice(0, 6),
    [activity],
  );

  const totalAssets = React.useMemo(() => Object.values(assetCounts).reduce((a, b) => a + b, 0), [assetCounts]);

  // asset type breakdown
  const assetByType = React.useMemo(() => {
    return Object.entries(assetCounts)
      .filter(([, n]) => n > 0)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 8);
  }, [assetCounts]);

  const assetMax = assetByType[0]?.[1] ?? 1;

  // traffic status code breakdown
  const trafficByCodes = React.useMemo(() => {
    const m: Record<number, number> = {};
    for (const e of traffic) {
      const bucket = Math.floor(e.status / 100) * 100;
      m[bucket] = (m[bucket] ?? 0) + 1;
    }
    return Object.entries(m)
      .sort(([a], [b]) => Number(a) - Number(b))
      .map(([code, n]) => ({ code: Number(code), n }));
  }, [traffic]);

  const trafficMax = Math.max(...trafficByCodes.map((x) => x.n), 1);
  const recentTraffic = [...traffic].sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts)).slice(0, 5);

  // system
  const activeProfile = llmProfiles.find((p) => p.is_default);
  const enabledTools = tools.filter((t) => t.enabled);
  const pendingCount = pending.length;

  // ── token stats per LLM profile ──────────────────────────────────────────
  // tasks whose llm_profile_id is null/undefined used the active default profile
  const defaultProfileId = activeProfile ? Number(activeProfile.id) : null;

  // Data source toggle: legacy = activity (task.tokens + sessions), new = llm_usage metering ledger.
  const [tokenVersion, setTokenVersion] = React.useState<"old" | "new">("old");
  // selected profile tab: "all" = all profiles; number = specific profile id
  const [tokenTab, setTokenTab] = React.useState<number | null | "all">("all");
  // day range for the daily bar chart
  const [tokenDays, setTokenDays] = React.useState<7 | 30 | 90 | 180 | 365>(30);

  // Profile name → id, used to map llm_usage's profile_name onto the existing profile tabs.
  const profileIdByName = React.useMemo(() => {
    const m = new Map<string, number>();
    for (const p of llmProfiles) m.set(p.name, Number(p.id));
    return m;
  }, [llmProfiles]);

  type Bucket = {
    input: number;
    output: number;
    cacheRead: number;
    cacheWrite: number;
    taskCount: number;
    costEur?: number | null;
  };

  // Legacy: bucket by profile (from activity's task.tokens + session usage).
  const tokenByProfileOld = React.useMemo<Map<number | null, Bucket>>(() => {
    const m = new Map<number | null, Bucket>();
    const fold = (key: number | null, inp: number, out: number, cr: number, cw: number, addTask: boolean) => {
      const prev = m.get(key) ?? { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, taskCount: 0 };
      m.set(key, {
        input: prev.input + inp,
        output: prev.output + out,
        cacheRead: prev.cacheRead + cr,
        cacheWrite: prev.cacheWrite + cw,
        taskCount: prev.taskCount + (addTask ? 1 : 0),
      });
    };
    for (const t of tasks) {
      fold(
        t.llm_profile_id ?? defaultProfileId,
        t.tokens?.input_tokens ?? 0,
        t.tokens?.output_tokens ?? 0,
        t.tokens?.cache_read_tokens ?? 0,
        t.tokens?.cache_write_tokens ?? 0,
        true,
      );
    }
    for (const c of convTokens) {
      fold(
        c.llm_profile_id ?? defaultProfileId,
        c.input_tokens,
        c.output_tokens,
        c.cache_read_tokens,
        c.cache_write_tokens,
        false,
      );
    }
    return m;
  }, [tasks, convTokens, defaultProfileId]);

  // New: bucket by profile (from the llm_usage global aggregate, precise per call).
  const tokenByProfileNew = React.useMemo<Map<number | null, Bucket>>(() => {
    const m = new Map<number | null, Bucket>();
    for (const p of usageStats?.by_profile ?? []) {
      // No matching existing profile (renamed/deleted/empty name) → falls into the default bucket, still counted under "All".
      const key = profileIdByName.get(p.profile_name) ?? defaultProfileId;
      const prev = m.get(key) ?? { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, taskCount: 0, costEur: null };
      m.set(key, {
        input: prev.input + p.input_tokens,
        output: prev.output + p.output_tokens,
        cacheRead: prev.cacheRead + p.cache_read_tokens,
        cacheWrite: prev.cacheWrite + p.cache_write_tokens,
        taskCount: prev.taskCount + p.tasks,
        costEur: p.cost_eur != null ? (prev.costEur ?? 0) + p.cost_eur : prev.costEur,
      });
    }
    return m;
  }, [usageStats, profileIdByName, defaultProfileId]);

  const tokenByProfile = tokenVersion === "new" ? tokenByProfileNew : tokenByProfileOld;

  const displayedTokens = React.useMemo(() => {
    if (tokenTab === "all") {
      let input = 0,
        output = 0,
        cacheRead = 0,
        cacheWrite = 0,
        taskCount = 0;
      let costEur: number | null = null;
      for (const v of tokenByProfile.values()) {
        input += v.input;
        output += v.output;
        cacheRead += v.cacheRead;
        cacheWrite += v.cacheWrite;
        taskCount += v.taskCount;
        if (v.costEur != null) {
          costEur = (costEur ?? 0) + v.costEur;
        }
      }
      return { input, output, cacheRead, cacheWrite, taskCount, costEur };
    }
    const v = tokenByProfile.get(tokenTab as number | null);
    return v
      ? {
          input: v.input,
          output: v.output,
          cacheRead: v.cacheRead,
          cacheWrite: v.cacheWrite,
          taskCount: v.taskCount,
          costEur: v.costEur ?? null,
        }
      : { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, taskCount: 0, costEur: null };
  }, [tokenTab, tokenByProfile]);

  // Legacy daily: buckets the total tasks/sessions by their creation date (approximate, not actual daily consumption).
  const dailyTokenDataOld = React.useMemo(() => {
    const now = new Date();
    now.setDate(now.getDate() - tokenDays);
    const cutoff = now.toISOString().slice(0, 10);
    const m = new Map<string, { input: number; output: number; cacheRead: number }>();
    const fold = (date: string, inp: number, out: number, cr: number) => {
      if (date < cutoff) return;
      const prev = m.get(date) ?? { input: 0, output: 0, cacheRead: 0 };
      m.set(date, { input: prev.input + inp, output: prev.output + out, cacheRead: prev.cacheRead + cr });
    };
    for (const t of tasks) {
      if (tokenTab !== "all" && (t.llm_profile_id ?? defaultProfileId) !== tokenTab) continue;
      fold(
        t.created_at.slice(0, 10),
        t.tokens?.input_tokens ?? 0,
        t.tokens?.output_tokens ?? 0,
        t.tokens?.cache_read_tokens ?? 0,
      );
    }
    for (const c of convTokens) {
      if (tokenTab !== "all" && (c.llm_profile_id ?? defaultProfileId) !== tokenTab) continue;
      fold(c.created_at.slice(0, 10), c.input_tokens, c.output_tokens, c.cache_read_tokens);
    }
    return [...m.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([date, v]) => ({ date: date.slice(5), ...v }));
  }, [tasks, convTokens, tokenDays, tokenTab, defaultProfileId]);

  // New daily: real daily consumption from llm_usage (ts is the actual invocation time).
  const dailyTokenDataNew = React.useMemo(() => {
    const now = new Date();
    now.setDate(now.getDate() - tokenDays);
    const cutoff = now.toISOString().slice(0, 10);
    const m = new Map<string, { input: number; output: number; cacheRead: number }>();
    for (const d of usageStats?.daily ?? []) {
      if (d.date < cutoff) continue;
      if (tokenTab !== "all" && (profileIdByName.get(d.profile_name) ?? defaultProfileId) !== tokenTab) continue;
      const prev = m.get(d.date) ?? { input: 0, output: 0, cacheRead: 0 };
      m.set(d.date, {
        input: prev.input + d.input_tokens,
        output: prev.output + d.output_tokens,
        cacheRead: prev.cacheRead + d.cache_read_tokens,
      });
    }
    return [...m.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([date, v]) => ({ date: date.slice(5), ...v }));
  }, [usageStats, tokenDays, tokenTab, profileIdByName, defaultProfileId]);

  const dailyTokenData = tokenVersion === "new" ? dailyTokenDataNew : dailyTokenDataOld;

  // activity kind label
  function kindLabel(a: Activity): string {
    if (a.kind === "tool_use") return a.tool ?? "tool_use";
    if (a.kind === "tool_result") return "tool_result";
    return a.kind;
  }

  // Worker identity is metadata, not a status: the planner is the only role
  // that produces intents, so it gets the one emphasis tone.
  function workerBg(w: string): string {
    if (w === "planner") return "border-primary/40 bg-primary/10 text-primary";
    if (w === "mainagent") return "border-border bg-muted/30 text-foreground";
    return "border-border text-muted-foreground";
  }

  // ── render ────────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-1 flex-col gap-4 pb-6">
      {/* ── Header ── */}
      <div>
        <div>
          <h1 className="font-semibold text-lg tracking-tight">{t("title")}</h1>
          <p className="text-muted-foreground text-xs">{t("subtitle")}</p>
        </div>
      </div>

      {/* ── Row 1: key metrics as open blocks, not nested cards ── */}
      <div className="grid grid-cols-2 gap-x-4 gap-y-3 sm:grid-cols-3 lg:grid-cols-5">
        <Metric
          icon={TargetIcon}
          label={t("activeTasks")}
          value={
            <>
              {tasksByStatus.running ?? 0}
              <span className="font-normal text-muted-foreground text-xs"> / {tasks.length}</span>
            </>
          }
          detail={
            <>
              {(tasksByStatus.running ?? 0) > 0 && (
                <span className="text-info">
                  {t("statExplore")} {tasksByStatus.running}
                </span>
              )}
              {(tasksByStatus.paused ?? 0) > 0 && (
                <span className="text-warning">
                  {t("statPaused")} {tasksByStatus.paused}
                </span>
              )}
              {(tasksByStatus.done ?? 0) > 0 && (
                <span className="text-success">
                  {t("statDone")} {tasksByStatus.done}
                </span>
              )}
              {tasks.length === 0 && <span className="text-muted-foreground">{t("noTasks")}</span>}
            </>
          }
        />

        <Metric
          icon={BugIcon}
          label={t("confirmedFindings")}
          value={findings.length}
          detail={
            <>
              <span className="font-medium text-destructive">
                {tStatus("severity.critical")} {findingsBySev.critical}
              </span>
              <span className="text-destructive/80">
                {tStatus("severity.high")} {findingsBySev.high}
              </span>
              <span className="text-warning">
                {tStatus("severity.medium")} {findingsBySev.medium}
              </span>
              <span className="text-muted-foreground">
                {tStatus("severity.low")} {findingsBySev.low}
              </span>
            </>
          }
        />

        <Metric
          icon={NetworkIcon}
          label={t("assetNodes")}
          value={totalAssets}
          detail={<span className="text-muted-foreground">{t("crossTaskShared")}</span>}
        />

        <Metric
          icon={ActivityIcon}
          label={t("trafficExchanges")}
          value={traffic.length}
          detail={
            settings?.traffic_capture ? (
              <span className="flex items-center gap-1.5 text-muted-foreground">
                <LiveDot />
                {t("recording")}
              </span>
            ) : (
              <span className="text-muted-foreground">{t("captureOff")}</span>
            )
          }
        />

        <Metric
          icon={ZapIcon}
          label={t("tokenUsage")}
          value={
            <>
              {fmtTokens(displayedTokens.input + displayedTokens.output) || "—"}
              {displayedTokens.costEur != null && displayedTokens.costEur > 0 ? (
                <span className="ml-2 font-medium text-sm text-success tabular-nums">
                  (€{displayedTokens.costEur.toFixed(2)})
                </span>
              ) : null}
            </>
          }
          detail={
            <span className="text-muted-foreground">
              {t("statTokenDetail", {
                input: fmtTokens(displayedTokens.input),
                cache: fmtTokens(displayedTokens.cacheRead),
                output: fmtTokens(displayedTokens.output),
              })}
            </span>
          }
        />
      </div>

      {/* ── Row 2: LLM Token Consumption ── */}
      <section className="border-border border-t pt-4">
        {/* Header */}
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-1.5 font-semibold text-xs">
            <ZapIcon className="size-3.5 text-muted-foreground" />
            {t("tokenConsumption")}
            {/* Data source switch: legacy = activity statistics (includes historical tasks); new = llm_usage metering ledger (more accurate, but only covers the period since it was enabled) */}
            <div className="ml-1 flex gap-0.5 border border-border p-0.5">
              {(
                [
                  { v: "old", label: t("verOld") },
                  { v: "new", label: t("verNew") },
                ] as const
              ).map(({ v, label }) => (
                <button
                  type="button"
                  key={v}
                  onClick={() => setTokenVersion(v)}
                  title={v === "new" ? t("tooltipNew") : t("tooltipOld")}
                  className={cn(
                    "px-2 py-0.5 font-medium text-[9px] transition-colors",
                    tokenVersion === v
                      ? "bg-primary text-primary-foreground"
                      : "text-muted-foreground hover:text-foreground",
                  )}
                >
                  {label}
                </button>
              ))}
            </div>
            <span className="font-normal text-[10px] text-muted-foreground">
              {tokenVersion === "new" ? t("srcNew") : t("srcOld")}
            </span>
          </div>
          {/* Profile tabs */}
          <div className="flex flex-wrap items-center gap-1">
            <button
              type="button"
              onClick={() => setTokenTab("all")}
              className={cn(
                "px-2.5 py-1 font-medium text-[10px] transition-colors",
                tokenTab === "all"
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:bg-muted/40 hover:text-foreground",
              )}
            >
              {t("all")}
            </button>
            {llmProfiles.map((p) => {
              const key = Number(p.id);
              const hasData = tokenByProfile.has(key) || (p.is_default && tokenByProfile.has(defaultProfileId));
              const resolvedKey = tokenByProfile.has(key) ? key : p.is_default ? defaultProfileId : key;
              return (
                <button
                  type="button"
                  key={p.id}
                  onClick={() => setTokenTab(resolvedKey)}
                  className={cn(
                    "flex items-center gap-1 px-2.5 py-1 font-medium text-[10px] transition-colors",
                    tokenTab === resolvedKey
                      ? "bg-primary text-primary-foreground"
                      : "text-muted-foreground hover:bg-muted/40 hover:text-foreground",
                    !hasData && "opacity-40",
                  )}
                >
                  {p.name}
                  {p.is_default && (
                    <span
                      className={cn(
                        "px-1 py-0 text-[8px]",
                        tokenTab === resolvedKey
                          ? "bg-background/20 text-primary-foreground"
                          : "border border-border text-muted-foreground",
                      )}
                    >
                      {t("default")}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Body: metrics left + bar chart right */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[220px_1fr]">
          {/* Left: key metrics */}
          <div className="flex flex-col gap-4">
            {/* Total */}
            <div>
              <div className="text-[10px] text-muted-foreground">{t("totalInOut")}</div>
              <div className="flex items-baseline gap-2">
                <span className="mt-0.5 font-bold text-3xl tabular-nums tracking-tight">
                  {fmtTokens(displayedTokens.input + displayedTokens.output) || "—"}
                </span>
                {displayedTokens.costEur != null && displayedTokens.costEur > 0 ? (
                  <span className="font-semibold text-base text-muted-foreground tabular-nums">
                    (€{displayedTokens.costEur.toFixed(2)})
                  </span>
                ) : null}
              </div>
              <div className="mt-0.5 text-[10px] text-muted-foreground">
                {t("taskCount", { count: displayedTokens.taskCount })}
              </div>
            </div>

            {/* Per-type bars */}
            <div className="space-y-3">
              {(() => {
                // input already includes cache; split into three non-overlapping parts: uncached input + cache hits + output = total.
                const total = displayedTokens.input + displayedTokens.output;
                return [
                  {
                    label: t("inputUncached"),
                    value: displayedTokens.input - displayedTokens.cacheRead,
                    barColor: dailyTrendConfig.input.color!,
                  },
                  {
                    label: t("cacheHit"),
                    value: displayedTokens.cacheRead,
                    barColor: dailyTrendConfig.cacheRead.color!,
                  },
                  {
                    label: t("output"),
                    value: displayedTokens.output,
                    barColor: dailyTrendConfig.output.color!,
                  },
                ].map(({ label, value, barColor }) => {
                  const pct = total > 0 ? (value / total) * 100 : 0;
                  return (
                    <div key={label}>
                      <div className="mb-1 flex items-center justify-between text-[10px]">
                        <span className="flex items-center gap-1.5 text-muted-foreground">
                          <span className="inline-block size-2" style={{ background: barColor }} />
                          {label}
                        </span>
                        <span className="font-mono font-semibold tabular-nums">{fmtTokens(value)}</span>
                      </div>
                      <div className="h-1.5 overflow-hidden bg-muted">
                        <div
                          className="h-full transition-all duration-500"
                          style={{ width: `${pct}%`, background: barColor }}
                        />
                      </div>
                    </div>
                  );
                });
              })()}
            </div>

            {/* Cache hit rate */}
            {(() => {
              // input already includes cache → hit rate = cache hits / total input.
              const denominator = displayedTokens.input;
              const hitPct = denominator > 0 ? Math.round((displayedTokens.cacheRead / denominator) * 100) : 0;
              return (
                <div className="flex items-center justify-between border-border border-t pt-2 text-[10px]">
                  <span className="text-muted-foreground">{t("cacheHitRate")}</span>
                  <span className={cn("font-semibold tabular-nums", hitPct > 50 ? "text-success" : "text-warning")}>
                    {hitPct}%
                  </span>
                </div>
              );
            })()}
          </div>

          {/* Right: daily bar chart */}
          <div className="flex min-h-0 flex-col">
            <div className="mb-2 flex items-center justify-between">
              <div className="flex gap-3 text-[9px] text-muted-foreground">
                {(["input", "output", "cacheRead"] as const).map((k) => (
                  <span key={k} className="flex items-center gap-1">
                    <span
                      className="inline-block size-2 rounded-sm"
                      style={{ background: dailyTrendConfig[k].color }}
                    />
                    {dailyTrendConfig[k].label}
                  </span>
                ))}
              </div>
              <div className="flex gap-0.5 border border-border p-0.5">
                {(
                  [
                    { days: 7, label: t("range7") },
                    { days: 30, label: t("range30") },
                    { days: 90, label: t("range90") },
                    { days: 180, label: t("range180") },
                    { days: 365, label: t("range365") },
                  ] as const
                ).map(({ days, label }) => (
                  <button
                    type="button"
                    key={days}
                    onClick={() => setTokenDays(days)}
                    className={cn(
                      "px-2.5 py-0.5 font-medium text-[9px] transition-colors",
                      tokenDays === days
                        ? "bg-primary text-primary-foreground"
                        : "text-muted-foreground hover:text-foreground",
                    )}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            {dailyTokenData.length === 0 ? (
              <div
                className="flex flex-1 items-center justify-center border border-border text-muted-foreground text-xs"
                style={{ minHeight: 180 }}
              >
                {t("noData")}
              </div>
            ) : (
              <ChartContainer config={dailyTrendConfig} className="h-[200px] w-full">
                <BarChart data={dailyTokenData} margin={{ top: 4, right: 4, bottom: 0, left: 0 }} maxBarSize={40}>
                  <CartesianGrid vertical={false} />
                  <XAxis
                    dataKey="date"
                    tickLine={false}
                    axisLine={false}
                    tick={{ fontSize: 10 }}
                    tickMargin={6}
                    interval="preserveStartEnd"
                  />
                  <YAxis
                    tickFormatter={(v) => fmtTokens(Number(v))}
                    tickLine={false}
                    axisLine={false}
                    tick={{ fontSize: 10 }}
                    width={44}
                  />
                  <ChartTooltip
                    cursor={false}
                    content={
                      <ChartTooltipContent
                        indicator="line"
                        formatter={(value, name) => (
                          <div className="flex w-full items-center justify-between gap-4">
                            <span>
                              {(dailyTrendConfig as Record<string, { label: string }>)[String(name)]?.label ??
                                String(name)}
                            </span>
                            <span className="font-mono font-semibold tabular-nums">{fmtTokens(Number(value))}</span>
                          </div>
                        )}
                      />
                    }
                  />
                  <Bar dataKey="input" stackId="1" fill="var(--color-input)" radius={[0, 0, 0, 0]} />
                  <Bar dataKey="output" stackId="1" fill="var(--color-output)" radius={[0, 0, 0, 0]} />
                  <Bar dataKey="cacheRead" stackId="1" fill="var(--color-cacheRead)" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </div>
        </div>
      </section>

      {/* ── Subscription Allocations ── */}
      <section className="border-border border-t pt-4">
        <div className="mb-3 flex items-center justify-between">
          <div className="flex items-center gap-1.5 font-semibold text-xs">
            <ZapIcon className="size-3.5 text-muted-foreground" />
            {t("subscriptions")}
          </div>
          <Link
            href="/system/llm"
            className="flex items-center gap-0.5 text-[10px] text-muted-foreground hover:text-foreground"
          >
            {t("manageSubscriptions")} <ArrowUpRightIcon className="size-3" />
          </Link>
        </div>

        {visibleSubscriptions.length === 0 ? (
          <div className="py-4 text-center text-muted-foreground text-xs">{t("noSubscriptions")}</div>
        ) : (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">
            {visibleSubscriptions.map((sub) => (
              <div key={sub.profile_id} className="flex flex-col gap-2 border-border border-l pl-3 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-semibold">{sub.name}</span>
                  <div className="flex shrink-0 items-center gap-1">
                    {sub.plan && (
                      <Badge variant="outline" className="text-[9px] text-muted-foreground">
                        {sub.plan}
                      </Badge>
                    )}
                    {sub.stale && (
                      <Badge variant="outline" className="border-warning/40 bg-warning/10 text-[9px] text-warning">
                        {t("staleData")}
                      </Badge>
                    )}
                    {sub.error && (
                      <Badge variant="destructive" className="text-[9px]">
                        {t("usageError")}
                      </Badge>
                    )}
                  </div>
                </div>

                <div className="mt-1 flex flex-col gap-2">
                  {sub.windows.length === 0 ? (
                    <p className="text-[10px] text-muted-foreground">
                      {t(sub.error ? "usageUnavailable" : "noQuotaWindows")}
                    </p>
                  ) : (
                    sub.windows.map((w) => {
                      const remainingPct = Math.round(w.remaining_fraction * 100);
                      const resetsText = formatAllocationReset(w.resets_at);
                      return (
                        <div key={w.id} className="grid gap-1">
                          <div className="flex items-center justify-between text-[11px]">
                            <span className="text-muted-foreground">{w.label}</span>
                            <span className="font-medium font-mono tabular-nums">
                              {t("remaining", { pct: remainingPct })}
                            </span>
                          </div>
                          <div
                            role="progressbar"
                            aria-valuenow={remainingPct}
                            aria-valuemin={0}
                            aria-valuemax={100}
                            aria-label={`${sub.name} ${w.label}: ${remainingPct}% remaining`}
                            className="h-1.5 w-full overflow-hidden bg-muted"
                          >
                            <div
                              className={cn(
                                "h-full transition-all duration-300",
                                remainingPct > 20 ? "bg-success" : remainingPct > 5 ? "bg-warning" : "bg-destructive",
                              )}
                              style={{ width: `${Math.max(0, Math.min(100, remainingPct))}%` }}
                            />
                          </div>
                          {resetsText && (
                            <span className="text-[9px] text-muted-foreground">
                              {t("resetsAt", { time: resetsText })}
                            </span>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* ── Row 3: Activity Stream | Discovery ── */}
      <div className="grid grid-cols-1 gap-x-6 gap-y-4 border-border border-t pt-4 lg:grid-cols-2">
        {/* Activity Stream */}
        <section className="min-w-0">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-1.5 font-semibold text-xs">
              <ActivityIcon className="size-3.5 text-muted-foreground" />
              {t("activityStream")}
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-muted-foreground">
                {t("eventCount", { count: activity.filter((a) => a.kind !== "usage").length })}
              </span>
              <Link
                href="/function/tasks"
                className="flex items-center gap-0.5 text-[10px] text-muted-foreground hover:text-foreground"
              >
                {t("viewTasks")} <ArrowUpRightIcon className="size-3" />
              </Link>
            </div>
          </div>

          <div className="mb-2.5 flex flex-wrap gap-1.5">
            {(["tool_use", "tool_result", "text", "thinking", "result"] as const).map((kind) => {
              const count = activity.filter((a) => a.kind === kind).length;
              if (count === 0) return null;
              return (
                <span key={kind} className="border border-border px-1.5 py-0.5 text-[9px] text-muted-foreground">
                  {kind} <strong className="text-foreground/70">{count}</strong>
                </span>
              );
            })}
          </div>

          <div className="divide-y">
            {recentActivity.length === 0 ? (
              <div className="py-4 text-center text-muted-foreground text-xs">{t("noActivity")}</div>
            ) : (
              recentActivity.map((a) => (
                <div key={a.seq} className="flex gap-2.5 py-2">
                  <span
                    className={cn("shrink-0 self-start border px-1.5 py-0.5 font-mono text-[9px]", workerBg(a.worker))}
                  >
                    {a.worker}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="font-medium text-[11px]">{kindLabel(a)}</div>
                    <div className="mt-0.5 truncate text-[10px] text-muted-foreground">{a.summary}</div>
                  </div>
                  <div className="shrink-0 text-right">
                    <Badge variant="outline" className="px-1.5 py-0 text-[9px] text-muted-foreground">
                      {a.kind}
                    </Badge>
                    <div className="mt-0.5 text-[9px] text-muted-foreground tabular-nums">{rel(a.ts)}</div>
                  </div>
                </div>
              ))
            )}
          </div>
        </section>

        {/* Discovery */}
        <section className="min-w-0">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-1.5 font-semibold text-xs">
              <BugIcon className="size-3.5 text-muted-foreground" />
              {t("findings")}
            </div>
            <Link
              href="/function/findings"
              className="flex items-center gap-0.5 text-[10px] text-muted-foreground hover:text-foreground"
            >
              {t("all")} <ArrowUpRightIcon className="size-3" />
            </Link>
          </div>

          <div className="divide-y">
            {recentFindings.length === 0 ? (
              <div className="py-4 text-center text-muted-foreground text-xs">{t("noFindings")}</div>
            ) : (
              recentFindings.map((f) => (
                <div key={f.id} className="flex items-start gap-2 py-2">
                  <StatusBadge
                    domain="severity"
                    value={f.severity}
                    className="mt-0.5 shrink-0 px-1.5 py-0 text-[10px]"
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="font-semibold text-[11px]">{f.vulnclass}</span>
                      {f.task_description && (
                        <span className="truncate text-[10px] text-muted-foreground">{f.task_description}</span>
                      )}
                    </div>
                    <div className="mt-0.5 line-clamp-2 text-[10px] text-muted-foreground leading-snug">
                      {f.summary}
                    </div>
                  </div>
                  <span className="shrink-0 text-[9px] text-muted-foreground tabular-nums">{rel(f.ts)}</span>
                </div>
              ))
            )}
          </div>
        </section>
      </div>

      {/* ── Row 4: Task Table ── */}
      <section className="min-w-0 border-border border-t pt-4">
        <div className="flex items-center justify-between pb-2">
          <div className="flex items-center gap-1.5 font-semibold text-xs">
            <ClockIcon className="size-3.5 text-muted-foreground" />
            {t("tasks")}
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-muted-foreground">{t("taskCount", { count: tasks.length })}</span>
            <Link
              href="/function/tasks"
              className="flex items-center gap-0.5 text-[10px] text-muted-foreground hover:text-foreground"
            >
              {t("all")} <ArrowUpRightIcon className="size-3" />
            </Link>
          </div>
        </div>
        {/* Narrow viewports scroll the table instead of compressing the columns. */}
        <div className="overflow-x-auto">
          <table className="w-full min-w-[36rem] border-collapse text-xs">
            <thead>
              <tr className="border-b">
                {[
                  t("colTask"),
                  t("colStatus"),
                  t("colEngine"),
                  t("colGoalProgress"),
                  t("colInFlight"),
                  t("colLastActivity"),
                ].map((h) => (
                  <th
                    key={h}
                    className="px-4 py-2 text-left font-semibold text-[9px] text-muted-foreground uppercase tracking-widest first:pl-4"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sortedTasks.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-muted-foreground text-xs">
                    {t("noTasks")}
                  </td>
                </tr>
              ) : (
                sortedTasks.map((t) => {
                  const goalsPct = t.goals_total ? Math.round(((t.goals_met ?? 0) / t.goals_total) * 100) : null;
                  return (
                    <tr key={t.id} className="border-b transition-colors last:border-0 hover:bg-muted/30">
                      <td className="max-w-xs px-4 py-3">
                        <Link href={`/function/tasks/detail?id=${t.id}`} className="group flex flex-col">
                          <span className="truncate font-medium group-hover:underline">{t.description}</span>
                          <span className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground">{t.id}</span>
                        </Link>
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge domain="task" value={t.status} dot className="px-1.5 py-0 text-[10px]" />
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge
                          domain="engine"
                          value={t.engine_mode ?? "idle"}
                          className="px-1.5 py-0 text-[10px]"
                        />
                      </td>
                      <td className="px-4 py-3">
                        {goalsPct !== null ? (
                          <div className="flex items-center gap-2">
                            <Progress value={goalsPct} className="h-1 w-14" />
                            <span className="text-muted-foreground tabular-nums">
                              {t.goals_met ?? 0}/{t.goals_total}
                            </span>
                          </div>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 tabular-nums">
                        {(t.in_flight ?? 0) > 0 ? (
                          <span className="font-semibold">{t.in_flight}</span>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-muted-foreground tabular-nums">
                        {rel(t.last_activity_unix ?? t.created_unix)}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* ── Row 5: Asset Distribution | Traffic Status Codes | Interception & Pending Approval ── */}
      <div className="grid grid-cols-1 gap-x-6 gap-y-4 border-border border-t pt-4 lg:grid-cols-3">
        {/* Asset distribution */}
        <section className="min-w-0">
          <SectionTitle icon={NetworkIcon} sub={t("byType")}>
            {t("assetDistribution")}
          </SectionTitle>

          {assetByType.length === 0 ? (
            <div className="py-6 text-center text-muted-foreground text-xs">{t("noAssetData")}</div>
          ) : (
            <div className="flex flex-col gap-2">
              {assetByType.map(([type, count]) => (
                <div key={type} className="flex items-center gap-2 text-xs">
                  <span className="w-16 shrink-0 truncate text-[10px] text-muted-foreground">
                    {t.has(`assetType.${type}`) ? t(`assetType.${type}`) : type}
                  </span>
                  <div className="h-1.5 flex-1 overflow-hidden bg-muted">
                    <div className="h-full bg-primary" style={{ width: `${(count / assetMax) * 100}%` }} />
                  </div>
                  <span className="w-8 text-right tabular-nums">{count}</span>
                </div>
              ))}
            </div>
          )}

          <div className="mt-3 border-border border-t pt-3 text-[10px] text-muted-foreground">
            {t("totalNodes", { count: totalAssets })}
          </div>
        </section>

        {/* Traffic status codes */}
        <section className="min-w-0">
          <SectionTitle icon={ActivityIcon} sub={t("requestCount", { count: traffic.length })}>
            {t("trafficStatusCodes")}
          </SectionTitle>

          {/* bar chart */}
          {trafficByCodes.length === 0 ? (
            <div className="py-6 text-center text-muted-foreground text-xs">{t("noTrafficData")}</div>
          ) : (
            <>
              <div className="mb-3 flex items-end gap-2" style={{ height: 52 }}>
                {trafficByCodes.map(({ code, n }) => (
                  <div key={code} className="flex flex-1 flex-col items-center gap-1">
                    <span className="text-[9px] text-muted-foreground tabular-nums">{n}</span>
                    <div
                      className={cn("min-h-1 w-full", statusBg(code))}
                      style={{ height: Math.max(4, (n / trafficMax) * 36) }}
                    />
                    <span className={cn("font-mono text-[9px]", statusColor(code))}>{code}</span>
                  </div>
                ))}
              </div>

              <div className="border-border border-t pt-2.5">
                <div className="mb-1.5 text-[10px] text-muted-foreground">{t("recentRequests")}</div>
                <div className="flex flex-col gap-1.5">
                  {recentTraffic.map((e) => (
                    <div key={e.id} className="flex items-center gap-1.5 text-[10px]">
                      <span className="shrink-0 border border-border px-1 py-0 font-mono text-[9px] text-muted-foreground">
                        {e.method}
                      </span>
                      <span className="min-w-0 flex-1 truncate text-muted-foreground">
                        {e.host}
                        {e.url.replace(/^https?:\/\/[^/]+/, "").substring(0, 30)}
                      </span>
                      <span className={cn("shrink-0 font-mono text-[9px]", statusColor(e.status))}>{e.status}</span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </section>

        {/* System status & pending approval */}
        <section className="min-w-0">
          <SectionTitle icon={ShieldCheckIcon}>{t("systemStatus")}</SectionTitle>

          <dl className="flex flex-col text-[10px]">
            <div className="flex items-center justify-between border-border border-b py-1.5">
              <dt className="text-muted-foreground">{t("llmConfig")}</dt>
              <dd>
                <Badge
                  variant="outline"
                  className={cn(
                    "text-[10px]",
                    stats?.llm_configured
                      ? "border-success/40 bg-success/10 text-success"
                      : "border-destructive/40 bg-destructive/10 text-destructive",
                  )}
                >
                  {stats?.llm_configured ? t("configured") : t("notConfigured")}
                </Badge>
              </dd>
            </div>

            <div className="flex items-center justify-between border-border border-b py-1.5">
              <dt className="text-muted-foreground">{t("trafficCapture")}</dt>
              <dd>
                <Badge
                  variant="outline"
                  className={cn(
                    "text-[10px]",
                    settings?.traffic_capture ? "border-info/40 bg-info/10 text-info" : "text-muted-foreground",
                  )}
                >
                  {settings?.traffic_capture ? t("on") : t("off")}
                </Badge>
              </dd>
            </div>

            {activeProfile && (
              <div className="flex items-center justify-between border-border border-b py-1.5">
                <dt className="text-muted-foreground">{t("activeModel")}</dt>
                <dd className="max-w-[60%] truncate font-mono">{activeProfile.model}</dd>
              </div>
            )}
          </dl>

          {/* pending approvals */}
          {pendingCount > 0 && (
            <div className="mt-3">
              <div className="mb-1.5 font-medium text-[10px] text-warning">
                {t("pendingApprovals", { count: pendingCount })}
              </div>
              <div className="flex flex-col">
                {pending.slice(0, 3).map((p) => (
                  <Link
                    key={p.id}
                    href="/system/intercept/approvals"
                    className="flex items-center justify-between border-warning/25 border-l py-1.5 pl-2 hover:bg-warning/5"
                  >
                    <div className="min-w-0">
                      <div className="font-medium text-[10px]">{p.tool_name}</div>
                      <div className="text-[9px] text-muted-foreground">{p.agent_name}</div>
                    </div>
                    <ArrowUpRightIcon className="size-3 shrink-0 text-warning" />
                  </Link>
                ))}
                {pendingCount > 3 && (
                  <Link
                    href="/system/intercept/approvals"
                    className="mt-1.5 text-center text-[10px] text-muted-foreground hover:text-foreground"
                  >
                    {t("morePending", { count: pendingCount - 3 })}
                  </Link>
                )}
              </div>
            </div>
          )}

          {pendingCount === 0 && (
            <div className="mt-3 border border-border py-3 text-center text-[10px] text-muted-foreground">
              <ShieldCheckIcon className="mx-auto mb-1 size-4 text-success/50" />
              {t("noPendingIntercepts")}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
