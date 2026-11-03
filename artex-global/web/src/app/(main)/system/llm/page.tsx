"use client";

import * as React from "react";

import {
  AlertCircleIcon,
  ArrowDownIcon,
  ArrowUpIcon,
  Loader2Icon,
  PlugZapIcon,
  PlusIcon,
  RefreshCwIcon,
  RotateCcwIcon,
  SaveIcon,
  StarIcon,
  Trash2Icon,
  ZapIcon,
} from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { getDateLocale } from "@/i18n/datetime";
import { api, type LLMOAuthPoll } from "@/lib/api";
import { formatAllocationReset, markUsageStale } from "@/lib/subscription-usage";
import type {
  LLMAuthMethod,
  LLMPoolMember,
  LLMPoolStatus,
  LLMProfile,
  LLMProfileUsage,
  LLMRefusalFallbackStep,
  LLMRetryOverride,
} from "@/lib/types";
import { cn } from "@/lib/utils";

import { ProfileRetryFields, RetryPolicyPanel, ZERO_OVERRIDE } from "./_components/retry";

// The thinking toggle (thinking.type) and the reasoning intensity (reasoning_effort) are two fully independent fields,
// each set on its own. Some APIs have no thinking field and only enable thinking through the effort parameter, so they must be decoupled.
// An empty string stored in the database means the field is NOT sent. Radix Select does not accept an empty value, so the UI uses "none"
// The sentinel means "do not send"; it is converted to and from "" on read and write (NONE / fromStore / toStore).
const NONE = "none";
const OAUTH_FORMAT: Partial<Record<LLMAuthMethod, LLMProfile["format"]>> = {
  claude_code: "anthropic",
  codex: "openai-responses",
  antigravity: "antigravity",
};

// Poll interval for a native proxy login session. The response carries no interval, so this is a fixed short delay.
const OAUTH_POLL_MS = 2000;
const OAUTH_PROVIDER: Record<Exclude<LLMAuthMethod, "api_key">, string> = {
  claude_code: "Claude Code",
  codex: "OpenAI Codex",
  antigravity: "Google Antigravity",
};
const fromStore = (v?: string) => (v ? v : NONE);
const toStore = (v: string) => (v === NONE ? "" : v);

function cooldownText(secs: number) {
  if (secs <= 0) return "";
  if (secs < 60) return `${secs}s`;
  return `${Math.ceil(secs / 60)}min`;
}

// The "is it healthy" status of a config shown on the card. A config with no Key set cannot send any request at all, so this should be reported before the circuit breaker state.
// Other statuses come from the circuit-breaker records produced by polling (while polling is off, no new records are generated, so "healthy" here means no known failures).
// Copy goes through i18n (llmPage.health.*), so the caller injects t as a parameter.
type Health = { label: string; cls: string; hint?: string };

// ─────────────────────────────────────────────────────────────────────────────
// Polling config drawer
// ─────────────────────────────────────────────────────────────────────────────

function PoolSheet({
  open,
  onOpenChange,
  pool,
  onReload,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  pool: LLMPoolStatus | null;
  onReload: () => Promise<void>;
}) {
  const t = useTranslations("llmPage");
  const [busy, setBusy] = React.useState(false);
  const [refusalFallback, setRefusalFallback] = React.useState(false);
  // The cooldown countdown is the remaining seconds computed by the backend. Only poll for it periodically while the drawer is open and some config is unhealthy, so that it ticks.
  React.useEffect(() => {
    if (!open || !pool?.enabled || !pool.chain.some((m) => m.state !== "ok")) return;
    const t = setInterval(() => void onReload(), 10_000);
    return () => clearInterval(t);
  }, [open, pool, onReload]);

  React.useEffect(() => {
    if (open) void api.settings().then((settings) => setRefusalFallback(settings.llm_refusal_fallback_enabled ?? false));
  }, [open]);

  async function toggle(patch: { llm_pool_enabled?: boolean; llm_pool_bind_fallback?: boolean; llm_refusal_fallback_enabled?: boolean }) {
    if (busy) return;
    setBusy(true);
    try {
      await api.setSettings(patch);
      await onReload();
      if (patch.llm_refusal_fallback_enabled !== undefined) setRefusalFallback(patch.llm_refusal_fallback_enabled);
      if (patch.llm_pool_enabled !== undefined) {
        toast.success(patch.llm_pool_enabled ? t("pool.toast.enabled") : t("pool.toast.disabled"));
      } else {
        toast.success(t("pool.toast.fallbackUpdated"));
      }
    } catch (e) {
      toast.error(t("pool.toast.setFailed", { msg: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  }

  async function recover(id?: string) {
    try {
      await api.resetLLMPool(id);
      await onReload();
      toast.success(id ? t("pool.toast.recoveredOne") : t("pool.toast.recoveredAll"));
    } catch (e) {
      toast.error(t("pool.toast.recoverFailed", { msg: (e as Error).message }));
    }
  }

  const enabled = pool?.enabled ?? false;
  const chain = pool?.chain ?? [];
  // Members that participate in polling (excluding those marked "do not participate in polling"). The order is the actual order in which the backend attempts them.
  const inChain = chain.filter((m) => m.active || !m.excluded);
  const tripped = chain.filter((m) => m.state === "tripped");

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="flex flex-col gap-0 p-0 data-[side=right]:sm:max-w-lg">
        <SheetHeader className="px-4">
          <SheetTitle className="flex items-center gap-2">
            <ZapIcon className="size-4" /> {t("pool.title")}
          </SheetTitle>
          <SheetDescription>{t.rich("pool.desc", { b: (c) => <b>{c}</b> })}</SheetDescription>
        </SheetHeader>

        <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4 pb-6">
          <div className="flex items-center justify-between gap-4 rounded-lg border p-3">
            <div className="grid gap-0.5">
              <Label className="text-sm">{t("pool.enable.label")}</Label>
              <p className="text-muted-foreground text-xs">{t("pool.enable.hint")}</p>
            </div>
            <Switch
              checked={enabled}
              disabled={busy}
              onCheckedChange={(v) => void toggle({ llm_pool_enabled: v })}
              aria-label={t("pool.enable.aria")}
            />
          </div>
          <div className="flex items-center justify-between gap-4 rounded-lg border p-3">
            <div className="grid gap-0.5">
              <Label className="text-sm">{t("pool.refusalFallback.label")}</Label>
              <p className="text-muted-foreground text-xs">{t("pool.refusalFallback.hint")}</p>
            </div>
            <Switch
              checked={refusalFallback}
              disabled={busy}
              onCheckedChange={(v) => void toggle({ llm_refusal_fallback_enabled: v })}
              aria-label={t("pool.refusalFallback.aria")}
            />
          </div>

          {enabled && (
            <>
              <div className="flex items-center justify-between gap-4 rounded-lg border p-3">
                <div className="grid gap-0.5">
                  <Label className="text-sm">{t("pool.bindFallback.label")}</Label>
                  <p className="text-muted-foreground text-xs">{t("pool.bindFallback.hint")}</p>
                </div>
                <Switch
                  checked={pool?.bind_fallback ?? false}
                  disabled={busy}
                  onCheckedChange={(v) => void toggle({ llm_pool_bind_fallback: v })}
                  aria-label={t("pool.bindFallback.aria")}
                />
              </div>

              <Separator />

              <div className="grid gap-2">
                <div className="flex items-center justify-between">
                  <Label className="text-sm">{t("pool.order.label")}</Label>
                  {tripped.length > 0 && (
                    <Button size="sm" variant="ghost" onClick={() => void recover()}>
                      <RotateCcwIcon /> {t("pool.recoverAll")}
                    </Button>
                  )}
                </div>
                {inChain.length < 2 && (
                  <p className="text-muted-foreground text-xs">{t("pool.order.tooFew", { n: inChain.length })}</p>
                )}
                {chain.map((m) => {
                  const excluded = m.excluded && !m.active;
                  const order = excluded ? null : inChain.findIndex((x) => x.profile_id === m.profile_id) + 1;
                  return (
                    <div
                      key={m.profile_id}
                      className={cn(
                        "grid gap-1 rounded-lg border p-2.5 text-sm",
                        excluded && "opacity-55",
                        m.state === "tripped" && "border-destructive/40",
                      )}
                    >
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                        <span className="w-5 shrink-0 text-center font-mono text-muted-foreground text-xs">
                          {order ?? "—"}
                        </span>
                        <span className="font-medium">{m.name}</span>
                        {m.active && (
                          <Badge variant="outline" className="border-amber-400/50 text-amber-500">
                            {t("pool.badge.active")}
                          </Badge>
                        )}
                        {excluded && <Badge variant="outline">{t("pool.badge.excluded")}</Badge>}
                        <div className="ml-auto flex items-center gap-2">
                          {m.state === "tripped" && m.cooldown_secs > 0 && (
                            <span className="text-muted-foreground text-xs">
                              {t("pool.cooldown", { cooldown: cooldownText(m.cooldown_secs) })}
                            </span>
                          )}
                          {m.state === "degraded" && (
                            <span className="text-muted-foreground text-xs">
                              {t("pool.consecutiveFails", { fails: m.fails })}
                            </span>
                          )}
                          {m.state !== "ok" && (
                            <Button
                              size="icon"
                              variant="ghost"
                              className="size-7"
                              aria-label={t("pool.recoverNow.aria")}
                              title={t("pool.recoverNow.title")}
                              onClick={() => void recover(m.profile_id)}
                            >
                              <RotateCcwIcon className="size-3.5" />
                            </Button>
                          )}
                        </div>
                      </div>
                      <div className="flex flex-wrap items-center gap-x-3 pl-7 text-muted-foreground text-xs">
                        <code className="truncate font-mono">{m.model}</code>
                        {!m.active && <span>{t("pool.priority", { priority: m.priority })}</span>}
                      </div>
                      {m.last_error && (
                        <p className="truncate pl-7 font-mono text-muted-foreground text-xs" title={m.last_error}>
                          {m.last_error}
                        </p>
                      )}
                    </div>
                  );
                })}
                {chain.length === 0 && (
                  <div className="rounded-lg border border-dashed p-4 text-center text-muted-foreground text-sm">
                    {t("pool.empty")}
                  </div>
                )}
              </div>

              <div className="rounded-lg border border-dashed p-3 text-muted-foreground text-xs leading-relaxed">
                {t("pool.note")}
              </div>
            </>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Model config drawer (create and edit share the same form)
// ─────────────────────────────────────────────────────────────────────────────

function ProfileSheet({
  profile,
  open,
  onOpenChange,
  onSaved,
}: {
  profile: LLMProfile | null; // null = create new
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onSaved: (id: string) => void;
}) {
  const t = useTranslations("llmPage");
  const isNew = !profile;
  const [name, setName] = React.useState("");
  const [format, setFormat] = React.useState<LLMProfile["format"]>("anthropic");
  const [model, setModel] = React.useState("");
  const [baseUrl, setBaseUrl] = React.useState("");
  const [proxy, setProxy] = React.useState("");
  const [apiKey, setApiKey] = React.useState("");
  const [keyHint, setKeyHint] = React.useState("");
  const [rps, setRps] = React.useState("0");
  const [rpm, setRpm] = React.useState("0");
  const [cw, setCw] = React.useState("0"); // Context window (K tokens); 0 = default 200K
  const [thinkingType, setThinkingType] = React.useState(NONE);
  const [effort, setEffort] = React.useState(NONE);
  const [priority, setPriority] = React.useState("0"); // Polling priority; the larger, the earlier
  const [poolExclude, setPoolExclude] = React.useState(false);
  const [streaming, setStreaming] = React.useState(true); // true = streaming (default); false = non-streaming
  const [maxTokens, setMaxTokens] = React.useState("0"); // Output cap per reply; 0 = do not send
  const [maxTokensField, setMaxTokensField] = React.useState(NONE); // Field name used for the cap; NONE = max_tokens
  const [sessionHeaderKey, setSessionHeaderKey] = React.useState(""); // Custom session header name; empty = do not send
  const [retry, setRetry] = React.useState<LLMRetryOverride>(ZERO_OVERRIDE); // Retry override for this config; all 0 = follow global
  const [testing, setTesting] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [models, setModels] = React.useState<string[]>([]);
  const [loadingModels, setLoadingModels] = React.useState(false);
  const [modelsOpen, setModelsOpen] = React.useState(false);
  // Effort metadata per native catalog model ID. A model without an entry keeps the full effort list.
  const [modelEfforts, setModelEfforts] = React.useState<Record<string, string[]>>({});
  const [authMethod, setAuthMethod] = React.useState<LLMAuthMethod>("api_key");
  // The active native proxy login session shown in the drawer. Its server session is cancelled when the drawer closes, the profile changes, the auth method switches, or the component unmounts.
  const [oauthSessionId, setOauthSessionId] = React.useState<string | null>(null);
  const [oauthPoll, setOauthPoll] = React.useState<LLMOAuthPoll | null>(null);
  const [oauthBusy, setOauthBusy] = React.useState(false);
  const [oauthInput, setOauthInput] = React.useState("");
  const [grantReady, setGrantReady] = React.useState(false);
  const [grantEmail, setGrantEmail] = React.useState("");
  const [grantExpiry, setGrantExpiry] = React.useState("");
  const [refusalFallback, setRefusalFallback] = React.useState<LLMRefusalFallbackStep[]>([]);
  const [masterFallbackEnabled, setMasterFallbackEnabled] = React.useState(true);
  const [usage, setUsage] = React.useState<LLMProfileUsage | null>(null);
  const [loadingUsage, setLoadingUsage] = React.useState(false);
  // Mirrors the live session for cleanup paths, which must not read stale state.
  const oauthRef = React.useRef<{ profileId: number; sessionId: string } | null>(null);
  // Bumped on every cancel so a start request that resolves after cancellation is discarded.
  const oauthGenRef = React.useRef(0);
  // Bumped on each catalog load and each drawer reset; a response from a superseded load is discarded.
  const modelsGenRef = React.useRef(0);
  // Read by the poll loop so a parent re-render with a new onSaved identity does not restart polling.
  const onSavedRef = React.useRef(onSaved);
  React.useEffect(() => {
    onSavedRef.current = onSaved;
  }, [onSaved]);

  // The labels for the three option groups (thinking toggle, max-token field name, and thinking intensity) go through i18n, so the component builds them from the current language.
  const THINKING_TYPES: { value: string; label: string }[] = [
    { value: NONE, label: t("profile.thinkingType.opt.none") },
    { value: "disabled", label: t("profile.thinkingType.opt.disabled") },
    { value: "enabled", label: t("profile.thinkingType.opt.enabled") },
    { value: "adaptive", label: t("profile.thinkingType.opt.adaptive") },
  ];
  const MAX_TOKENS_FIELDS: { value: string; label: string }[] = [
    { value: NONE, label: t("profile.maxTokensField.opt.default") },
    { value: "max_completion_tokens", label: "max_completion_tokens" },
  ];
  const EFFORT_LEVELS: { value: string; label: string }[] = [
    { value: NONE, label: t("profile.effort.opt.none") },
    { value: "low", label: "low" },
    { value: "medium", label: "medium" },
    { value: "high", label: "high" },
    { value: "xhigh", label: "xhigh" },
    { value: "max", label: "max" },
  ];
  // SDK models with catalog metadata offer only their supported efforts plus the default; absent metadata keeps the full list.
  const sdkEfforts = authMethod !== "api_key" ? modelEfforts[model.trim()] : undefined;
  const effortOptions =
    sdkEfforts === undefined
      ? EFFORT_LEVELS
      : [{ value: NONE, label: t("profile.effort.opt.none") }, ...sdkEfforts.map((v) => ({ value: v, label: v }))];
  const effortUnsupported = sdkEfforts !== undefined && effort !== NONE && !sdkEfforts.includes(effort);
  // A saved value is never clamped: it stays visible and blocks save until the user picks a supported choice.
  const effortItems = effortUnsupported ? [...effortOptions, { value: effort, label: effort }] : effortOptions;
  const effortError = effortUnsupported
    ? t("profile.effort.unsupported", {
        value: effort,
        model: model.trim(),
        choices: effortOptions.map((o) => o.label).join(", "),
      })
    : "";

  // Each time the drawer opens, the form is filled from the passed-in profile (or reset to defaults for a new one). Closing and reopening the drawer
  // is a clean start, leaving no ghost of the previous configuration behind.
  React.useEffect(() => {
    if (!open) return;
    setName(profile?.name ?? "");
    setFormat(profile?.format ?? "anthropic");
    setAuthMethod(profile?.auth_method ?? "api_key");
    setModel(profile?.model ?? "");
    setBaseUrl(profile?.base_url ?? "");
    setProxy(profile?.proxy ?? "");
    setRps(String(profile?.rate_per_second ?? 0));
    setRpm(String(profile?.rate_per_minute ?? 0));
    setCw(String(profile?.context_window_k ?? 0));
    setThinkingType(fromStore(profile?.thinking_type));
    setEffort(fromStore(profile?.reasoning_effort));
    setPriority(String(profile?.priority ?? 0));
    setPoolExclude(profile?.pool_exclude ?? false);
    setStreaming(profile?.streaming ?? true);
    setMaxTokens(String(profile?.max_tokens ?? 0));
    setMaxTokensField(fromStore(profile?.max_tokens_field));
    setSessionHeaderKey(profile?.session_header_key ?? "");
    setRetry(profile?.retry ?? ZERO_OVERRIDE);
    setApiKey("");
    setKeyHint(profile?.api_key_hint ?? "");
    setModels([]);
    setModelEfforts({});
    modelsGenRef.current++;
    setLoadingModels(false);
    setModelsOpen(false);
    setGrantReady(profile?.has_grant ?? false);
    setGrantEmail(profile?.grant_email ?? "");
    setGrantExpiry(profile?.grant_expiry ?? "");
    setRefusalFallback(profile?.refusal_fallback ? [...profile.refusal_fallback] : []);
    setUsage(null);
  }, [open, profile]);

  const profileId = profile ? Number(profile.id) : undefined;
  React.useEffect(() => {
    if (!open) return;
    void api.settings().then((s) => setMasterFallbackEnabled(s.llm_refusal_fallback_enabled ?? false)).catch(() => {});
  }, [open]);

  const loadUsage = React.useCallback(async (quiet = false) => {
    if (!profileId || authMethod === "api_key") return;
    setLoadingUsage(true);
    try {
      const u = await api.profileUsage(profileId);
      setUsage(u);
    } catch (e) {
      setUsage((current) => (current ? markUsageStale(current) : current));
      if (!quiet) toast.error(t("profile.allocation.fetchFailed", { msg: (e as Error).message }));
    } finally {
      setLoadingUsage(false);
    }
  }, [profileId, authMethod, t]);

  React.useEffect(() => {
    if (open && profileId && authMethod !== "api_key") {
      void loadUsage(true);
    }
  }, [open, profileId, authMethod, loadUsage]);

  const addFallbackStep = () => {
    if (refusalFallback.length >= 8) return;
    const effectiveEffort = (value: string) => value || (effort === NONE ? "" : effort);
    const used = new Set([
      JSON.stringify([model.trim(), effectiveEffort("")]),
      ...refusalFallback.map((step) => JSON.stringify([step.model.trim(), effectiveEffort(step.reasoning_effort)])),
    ]);
    const next = authMethod === "api_key"
      ? { model: "", reasoning_effort: "" }
      : models.flatMap((candidate) => [
          { model: candidate, reasoning_effort: "" },
          ...(modelEfforts[candidate] ?? EFFORT_LEVELS.filter((item) => item.value !== NONE).map((item) => item.value))
            .map((value) => ({ model: candidate, reasoning_effort: value })),
        ]).find((step) => !used.has(JSON.stringify([step.model.trim(), effectiveEffort(step.reasoning_effort)]))) ??
        { model: "", reasoning_effort: "" };
    setRefusalFallback([...refusalFallback, next]);
  };

  const removeFallbackStep = (index: number) => {
    setRefusalFallback(refusalFallback.filter((_, i) => i !== index));
  };

  const moveFallbackStep = (index: number, direction: "up" | "down") => {
    const targetIndex = direction === "up" ? index - 1 : index + 1;
    if (targetIndex < 0 || targetIndex >= refusalFallback.length) return;
    const next = [...refusalFallback];
    const [moved] = next.splice(index, 1);
    next.splice(targetIndex, 0, moved);
    setRefusalFallback(next);
  };

  const updateFallbackStep = (index: number, patch: Partial<LLMRefusalFallbackStep>) => {
    setRefusalFallback(
      refusalFallback.map((step, i) => {
        if (i !== index) return step;
        const updated = { ...step, ...patch };
        if (patch.model !== undefined && authMethod !== "api_key") {
          const supported = modelEfforts[patch.model.trim()];
          if (supported && updated.reasoning_effort && !supported.includes(updated.reasoning_effort)) {
            updated.reasoning_effort = "";
          }
        }
        return updated;
      }),
    );
  };

  // Catalog listing needs no login; loading on open lets saved effort values be checked against the model's supported list.
  React.useEffect(() => {
    if (open && profileId && profile?.auth_method === authMethod && profile.format === format && authMethod !== "api_key")
      void loadModels(true);
    // Runs on open and on auth/format change. Skipped until the form matches the saved profile, so a render with stale fields never fetches.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, profileId, authMethod, format]);

  // Each load takes a new generation; a response from a superseded load is dropped. Quiet (auto) loads never toast.
  async function loadModels(quiet = false) {
    const gen = ++modelsGenRef.current;
    setLoadingModels(true);
    setModels([]);
    setModelEfforts({});
    try {
      const r = await api.fetchLLMModels(format, baseUrl, apiKey, proxy, profileId);
      if (gen !== modelsGenRef.current) return;
      if (r.ok && r.models && r.models.length > 0) {
        setModels(r.models.map((m) => m.id));
        setModelEfforts(
          Object.fromEntries(r.models.flatMap((m): [string, string[]][] => (m.supported_efforts ? [[m.id, m.supported_efforts]] : []))),
        );
        if (!quiet) {
          setModelsOpen(true);
          toast.success(t("profile.toast.modelsLoaded", { n: r.models.length }));
        }
      } else if (!quiet) {
        toast.error(t("profile.toast.loadModelsFailed", { error: r.error ?? t("profile.toast.noModels") }));
      }
    } catch (e) {
      if (!quiet && gen === modelsGenRef.current) toast.error(t("profile.toast.loadModelsError", { msg: (e as Error).message }));
    } finally {
      if (gen === modelsGenRef.current) setLoadingModels(false);
    }
  }

  async function testConnection() {
    if (testing || (authMethod !== "api_key" && !grantReady)) return;
    setTesting(true);
    try {
      // The test uses the thinking parameters the configuration will actually run with, so a model that doesn't support the field fails here
      // instead of blowing up later when a task runs. Pass the profile id: if the Key input is left empty, the stored Key is used.
      const r = await api.testLLM(
        format,
        model,
        baseUrl,
        apiKey,
        proxy,
        toStore(thinkingType),
        toStore(effort),
        profileId,
        authMethod === "api_key" ? streaming : false,
        sessionHeaderKey.trim(),
        authMethod,
      );
      // The reply content is shown as well: seeing that the model actually responded is what makes this equivalent to a successful run in a session.
      if (r.ok)
        toast.success(t("profile.toast.testOk", { latency: r.latency_ms ?? "?", model: r.model ?? model }), {
          description: r.reply ? t("profile.toast.testReply", { reply: r.reply }) : undefined,
        });
      else toast.error(t("profile.toast.testFailed", { error: r.error ?? t("profile.toast.unknown") }));
    } catch (e) {
      toast.error(t("profile.toast.testError", { msg: (e as Error).message }));
    } finally {
      setTesting(false);
    }
  }

  async function save() {
    if (!name.trim() || !model.trim()) {
      toast.error(t("profile.toast.nameModelRequired"));
      return;
    }
    if (effortError) {
      toast.error(effortError);
      return;
    }
    const effectiveEffort = (value: string) => value || (effort === NONE ? "" : effort);
    const seenFallbackChoices = new Set<string>([
      JSON.stringify([model.trim(), effectiveEffort("")]),
    ]);
    for (const step of refusalFallback) {
      const trimmedStep = step.model.trim();
      if (!trimmedStep) continue;
      const choice = JSON.stringify([trimmedStep, effectiveEffort(step.reasoning_effort)]);
      if (seenFallbackChoices.has(choice)) {
        toast.error(t("profile.refusalFallback.duplicateError"));
        return;
      }
      seenFallbackChoices.add(choice);
    }
    if (saving) return;
    setSaving(true);
    try {
      const { id } = await api.saveLLMProfile({
        ...(profile ? { id: Number(profile.id) } : {}),
        name: name.trim(),
        format,
        auth_method: authMethod,
        model: model.trim(),
        base_url: baseUrl.trim(),
        proxy: proxy.trim(),
        api_key: apiKey,
        rate_per_second: Number(rps) || 0,
        rate_per_minute: Number(rpm) || 0,
        context_window_k: Number(cw) || 0,
        thinking_type: toStore(thinkingType),
        reasoning_effort: toStore(effort),
        priority: Number(priority) || 0,
        pool_exclude: poolExclude,
        streaming: authMethod === "api_key" ? streaming : false,
        max_tokens: Math.max(0, Number(maxTokens) || 0),
        // The field-name toggle only matters for openai (Chat Completions); every other format falls back to the default;
        // the backend performs the same normalization again, and this is just so the UI never sends self-contradictory values.
        max_tokens_field: format === "openai" ? toStore(maxTokensField) : "",
        session_header_key: sessionHeaderKey.trim(),
        retry,
        refusal_fallback: refusalFallback.filter((s) => s.model.trim()),
      });
      if (isNew) toast.success(t("profile.toast.created", { name: name.trim() }));
      else toast.success(profile?.is_default ? t("profile.toast.savedActive") : t("profile.toast.saved"));
      onSaved(String(id));
      onOpenChange(false);
    } catch (e) {
      toast.error(t("profile.toast.saveFailed", { msg: (e as Error).message }));
    } finally {
      setSaving(false);
    }
  }

  // Ends local login state and cancels the server session if one is live. Safe to call when idle.
  const cancelOAuth = React.useCallback(() => {
    const live = oauthRef.current;
    oauthRef.current = null;
    oauthGenRef.current += 1;
    setOauthSessionId(null);
    setOauthPoll(null);
    setOauthInput("");
    setOauthBusy(false);
    if (live) api.cancelLLMOAuthSession(live.profileId, live.sessionId).catch(() => {});
  }, []);

  // Closing the drawer, switching profile, or unmounting cancels any live login.
  React.useEffect(() => () => cancelOAuth(), [open, profileId, cancelOAuth]);

  async function startOAuth() {
    if (!profileId) {
      toast.error(t("profile.oauth.saveFirst"));
      return;
    }
    if (oauthBusy || oauthRef.current) return;
    const gen = oauthGenRef.current;
    setOauthBusy(true);
    try {
      const flow = await api.startLLMOAuth(profileId);
      if (gen !== oauthGenRef.current) {
        // Drawer closed or profile changed while starting: release the server session immediately.
        api.cancelLLMOAuthSession(profileId, flow.session_id).catch(() => {});
        return;
      }
      oauthRef.current = { profileId, sessionId: flow.session_id };
      setOauthSessionId(flow.session_id);
    } catch {
      if (gen === oauthGenRef.current) toast.error(t("profile.oauth.loginFailed"));
    } finally {
      if (gen === oauthGenRef.current) setOauthBusy(false);
    }
  }

  React.useEffect(() => {
    if (!oauthSessionId || !profileId) return;
    let cancelled = false;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const result = await api.pollLLMOAuth(profileId, oauthSessionId);
        if (cancelled) return;
        if (result.status === "pending") {
          setOauthPoll(result);
          timer = window.setTimeout(poll, OAUTH_POLL_MS);
          return;
        }
        // Terminal states end the session. A failed or cancelled login keeps any existing grant.
        oauthRef.current = null;
        setOauthSessionId(null);
        setOauthPoll(null);
        setOauthInput("");
        setOauthBusy(false);
        if (result.status === "complete") {
          setGrantReady(true);
          setGrantEmail(result.email ?? "");
          setGrantExpiry(result.expires_at ?? "");
          toast.success(t("profile.oauth.loginComplete"));
          onSavedRef.current(String(profileId));
        } else if (result.status === "error") {
          toast.error(result.error || t("profile.oauth.loginFailed"));
        }
      } catch {
        if (!cancelled) {
          cancelOAuth();
          toast.error(t("profile.oauth.loginFailed"));
        }
      }
    };
    void poll();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [oauthSessionId, profileId, t, cancelOAuth]);

  async function submitOAuthInput(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const live = oauthRef.current;
    const prompt = oauthPoll?.prompt;
    if (!live || !prompt || oauthBusy) return;
    if (!prompt.allow_empty && !oauthInput.trim()) {
      toast.error(t("profile.oauth.promptRequired"));
      return;
    }
    const gen = oauthGenRef.current;
    setOauthBusy(true);
    try {
      // Sent exactly as typed. The poll loop stays authoritative for any following prompt.
      await api.inputLLMOAuth(live.profileId, live.sessionId, oauthInput);
      if (gen !== oauthGenRef.current) return;
      setOauthInput("");
      setOauthPoll((p) => (p ? { ...p, prompt: undefined } : p));
    } catch {
      if (gen === oauthGenRef.current) toast.error(t("profile.oauth.loginFailed"));
    } finally {
      if (gen === oauthGenRef.current) setOauthBusy(false);
    }
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="flex flex-col gap-0 p-0 data-[side=right]:min-w-[420px] data-[side=right]:sm:max-w-xl"
      >
        <SheetHeader className="px-4">
          <SheetTitle className="flex items-center gap-2">
            {isNew ? t("profile.titleNew") : t("profile.titleEdit", { name: profile?.name ?? "" })}
            {profile?.is_default && (
              <Badge variant="outline" className="border-amber-400/50 text-amber-500">
                {t("profile.activeBadge")}
              </Badge>
            )}
          </SheetTitle>
          <SheetDescription>{isNew ? t("profile.descNew") : t("profile.descEdit")}</SheetDescription>
        </SheetHeader>

        <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4 pb-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="p-name">{t("profile.name.label")}</Label>
              <Input
                id="p-name"
                placeholder={t("profile.name.placeholder")}
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="p-format">{t("profile.format.label")}</Label>
              <Select
                value={format}
                onValueChange={(v) => {
                  const next = v as LLMProfile["format"];
                  setFormat(next);
                  if (next === "ollama" && !baseUrl.trim()) {
                    setBaseUrl("http://127.0.0.1:11434/v1");
                  }
                }}
                disabled={authMethod !== "api_key"}
              >
                <SelectTrigger id="p-format">
                  <SelectValue placeholder={t("profile.format.placeholder")} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="anthropic">Anthropic</SelectItem>
                  <SelectItem value="openai">OpenAI (Chat Completions)</SelectItem>
                  <SelectItem value="openai-responses">OpenAI (Responses API)</SelectItem>
                  <SelectItem value="ollama">Ollama (local, no key needed)</SelectItem>
                  {authMethod === "antigravity" && <SelectItem value="antigravity">Google Gemini</SelectItem>}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="grid gap-2">
            <Label htmlFor="p-auth-method">{t("profile.authMethod.label")}</Label>
            <Select
              value={authMethod}
              onValueChange={(v) => {
                const next = v as LLMAuthMethod;
                setAuthMethod(next);
                if (next !== "api_key") {
                  // The SDK owns the endpoint, networking, proxy, session header, retries, and output field. Staged values are dropped here, not silently ignored at save.
                  setApiKey("");
                  setBaseUrl("");
                  setProxy("");
                  setSessionHeaderKey("");
                  setMaxTokensField(NONE);
                  setRetry(ZERO_OVERRIDE);
                }
                setGrantReady(next === authMethod && grantReady);
                setGrantEmail(next === authMethod ? grantEmail : "");
                setGrantExpiry(next === authMethod ? grantExpiry : "");
                cancelOAuth();
                if (next !== "api_key") setFormat(OAUTH_FORMAT[next] ?? "anthropic");
                else if (format === "antigravity") setFormat("anthropic");
              }}
            >
              <SelectTrigger id="p-auth-method">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="api_key">{t("profile.authMethod.opt.api_key")}</SelectItem>
                <SelectItem value="claude_code">{t("profile.authMethod.opt.claude_code")}</SelectItem>
                <SelectItem value="codex">{t("profile.authMethod.opt.codex")}</SelectItem>
                <SelectItem value="antigravity">{t("profile.authMethod.opt.antigravity")}</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="grid gap-2">
            <Label htmlFor="p-model">{t("profile.model.label")}</Label>
            <div className="flex gap-2">
              <Input
                id="p-model"
                className="font-mono"
                placeholder={format === "ollama" ? "llama3.2" : "claude-opus-4-8"}
                value={model}
                onChange={(e) => setModel(e.target.value)}
              />
              {/* modal: This Popover's content is portaled to <body>, outside the Sheet's scroll lock,
                  so without modal the list renders but cannot be scrolled. modal makes it hold the topmost scroll lock itself. */}
              <Popover open={modelsOpen} onOpenChange={setModelsOpen} modal>
                <PopoverTrigger asChild>
                  <Button
                    type="button"
                    variant="outline"
                    size="icon"
                    className="shrink-0"
                    disabled={loadingModels}
                    onClick={() => loadModels()}
                    title={t("profile.model.loadTitle")}
                  >
                    {loadingModels ? <Loader2Icon className="animate-spin" /> : <RefreshCwIcon />}
                  </Button>
                </PopoverTrigger>
                {models.length > 0 && (
                  <PopoverContent className="max-h-72 w-72 gap-0 overflow-y-auto overscroll-contain p-1" align="end">
                    {models.map((m) => (
                      <button
                        key={m}
                        type="button"
                        className="w-full shrink-0 rounded-md px-2 py-1.5 text-left font-mono text-xs hover:bg-accent hover:text-accent-foreground"
                        onClick={() => {
                          setModel(m);
                          setModelsOpen(false);
                        }}
                      >
                        {m}
                      </button>
                    ))}
                  </PopoverContent>
                )}
              </Popover>
            </div>
          </div>

          {authMethod === "api_key" ? (
            <>
              <div className="grid gap-2">
                <Label htmlFor="p-base-url">{t("profile.baseUrl.label")}</Label>
                <Input
                  id="p-base-url"
                  className="font-mono"
                  placeholder={format === "ollama" ? "http://127.0.0.1:11434/v1" : "https://api.openai.com/v1"}
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="p-proxy">{t("profile.proxy.label")}</Label>
                <Input
                  id="p-proxy"
                  className="font-mono"
                  placeholder="socks5://user:pass@127.0.0.1:1080 · http://127.0.0.1:8080"
                  value={proxy}
                  onChange={(e) => setProxy(e.target.value)}
                />
                <p className="text-muted-foreground text-xs">{t("profile.proxy.hint")}</p>
              </div>

              <div className="grid gap-2">
                <Label htmlFor="p-session-header">{t("profile.sessionHeader.label")}</Label>
                <Input
                  id="p-session-header"
                  className="font-mono"
                  placeholder={t("profile.sessionHeader.placeholder")}
                  value={sessionHeaderKey}
                  onChange={(e) => setSessionHeaderKey(e.target.value)}
                />
                <p className="text-muted-foreground text-xs">
                  {t.rich("profile.sessionHeader.hint", { b: (c) => <b>{c}</b> })}
                </p>
              </div>
            </>
          ) : (
            <p className="text-muted-foreground text-xs">{t("profile.oauth.sdkManaged")}</p>
          )}

          {authMethod === "api_key" ? (
            <div className="grid gap-2">
              <Label htmlFor="p-api-key">{format === "ollama" ? t("profile.apiKey.labelOllama") : t("profile.apiKey.label")}</Label>
              <Input
                id="p-api-key"
                type="password"
                placeholder={format === "ollama" ? t("profile.apiKey.placeholderOllama") : keyHint ? t("profile.apiKey.placeholderSet", { hint: keyHint }) : "sk-…"}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
              />
            </div>
          ) : (
            <>
              <div className="grid gap-3 rounded-lg border p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <Label>{t("profile.oauth.status")}</Label>
                <Badge variant="outline">{t(grantReady ? "profile.oauth.connected" : "profile.oauth.notConnected")}</Badge>
              </div>
              {grantEmail && <p className="text-muted-foreground text-xs">{t("profile.oauth.email", { email: grantEmail })}</p>}
              {grantExpiry && (
                <p className="text-muted-foreground text-xs">
                  {t("profile.oauth.expiry", { expiry: new Date(grantExpiry).toLocaleString(getDateLocale()) })}
                </p>
              )}
              {profile?.oauth_error && (
                <p className="text-destructive text-xs">{t("profile.oauth.sdkUnavailable", { error: profile.oauth_error })}</p>
              )}
              <p className="text-muted-foreground text-xs">{t("profile.oauth.credentialsNote")}</p>
              {oauthSessionId ? (
                <div className="grid gap-2 rounded-md bg-muted p-3 text-sm">
                  <p>{t("profile.oauth.waiting")}</p>
                  {oauthPoll?.instructions && <p>{oauthPoll.instructions}</p>}
                  {oauthPoll?.progress && <p className="text-muted-foreground text-xs">{oauthPoll.progress}</p>}
                  {oauthPoll?.authorization_url && (
                    <a
                      href={oauthPoll.authorization_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary underline underline-offset-4"
                    >
                      {t("profile.oauth.openProvider")}
                    </a>
                  )}
                  {oauthPoll?.prompt && (
                    <form className="grid gap-2" onSubmit={submitOAuthInput}>
                      <Label htmlFor="p-oauth-input">{oauthPoll.prompt.message}</Label>
                      <Input
                        id="p-oauth-input"
                        type={oauthPoll.prompt.secret ? "password" : "text"}
                        autoComplete="off"
                        placeholder={oauthPoll.prompt.placeholder}
                        value={oauthInput}
                        onChange={(e) => setOauthInput(e.target.value)}
                      />
                      <div>
                        <Button type="submit" disabled={oauthBusy}>
                          {t("profile.oauth.submit")}
                        </Button>
                      </div>
                    </form>
                  )}
                  {oauthPoll?.expires_at && (
                    <p className="text-muted-foreground text-xs">
                      {t("profile.oauth.expires", { expiry: new Date(oauthPoll.expires_at).toLocaleString(getDateLocale()) })}
                    </p>
                  )}
                  <div>
                    <Button type="button" variant="outline" onClick={cancelOAuth}>
                      {t("profile.oauth.cancel")}
                    </Button>
                  </div>
                </div>
              ) : (
                <Button type="button" variant="outline" onClick={startOAuth} disabled={oauthBusy} className="justify-self-start">
                  {oauthBusy ? <Loader2Icon className="animate-spin" /> : <PlugZapIcon />}
                  {t("profile.oauth.signIn", { provider: OAUTH_PROVIDER[authMethod] })}
                </Button>
              )}
            </div>
            {profileId && (
              <div className="grid gap-3 rounded-lg border p-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Label className="text-sm">{t("profile.allocation.title")}</Label>
                    {usage?.plan && (
                      <Badge variant="outline" className="text-[10px] text-muted-foreground">
                        {usage.plan}
                      </Badge>
                    )}
                    {usage?.stale && (
                      <Badge variant="outline" className="border-amber-500/30 bg-amber-500/10 text-amber-500 text-[10px]">
                        {t("profile.allocation.stale")}
                      </Badge>
                    )}
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="h-7 px-2 text-xs"
                    onClick={() => void loadUsage()}
                    disabled={loadingUsage}
                  >
                    {loadingUsage ? (
                      <Loader2Icon className="size-3.5 animate-spin mr-1" />
                    ) : (
                      <RefreshCwIcon className="size-3.5 mr-1" />
                    )}
                    {t("profile.allocation.refresh")}
                  </Button>
                </div>

                {usage?.error && (
                  <p className="text-destructive text-xs">{t("profile.allocation.fetchFailed", { msg: usage.error })}</p>
                )}
                {!usage?.connected ? (
                  usage?.error ? null : (
                    <p className="text-muted-foreground text-xs italic">{t("profile.allocation.notConnected")}</p>
                  )
                ) : usage.windows.length === 0 ? (
                  usage.error ? null : (
                    <p className="text-muted-foreground text-xs">{t("profile.allocation.noWindows")}</p>
                  )
                ) : (
                  <div className="grid gap-3">
                    {usage.windows.map((w) => {
                      const remainingPct = Math.round(w.remaining_fraction * 100);
                      const resetsText = formatAllocationReset(w.resets_at);
                      return (
                        <div key={w.id} className="grid gap-1">
                          <div className="flex items-center justify-between text-xs">
                            <span className="font-medium text-foreground">{w.label}</span>
                            <span className="font-mono tabular-nums text-muted-foreground">
                              {t("profile.allocation.remaining", { pct: remainingPct })}
                            </span>
                          </div>
                          <div
                            role="progressbar"
                            aria-valuenow={remainingPct}
                            aria-valuemin={0}
                            aria-valuemax={100}
                            aria-label={`${w.label}: ${remainingPct}% remaining`}
                            className="h-2 w-full overflow-hidden rounded-full bg-muted"
                          >
                            <div
                              className={cn(
                                 "h-full rounded-full transition-all duration-300",
                                 remainingPct > 20
                                   ? "bg-emerald-500"
                                   : remainingPct > 5
                                     ? "bg-amber-500"
                                     : "bg-destructive",
                              )}
                              style={{ width: `${Math.max(0, Math.min(100, remainingPct))}%` }}
                            />
                          </div>
                          {resetsText && (
                            <span className="text-[10px] text-muted-foreground">
                              {t("profile.allocation.resetsAt", { time: resetsText })}
                            </span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}
            </>
          )}

          <div className="grid gap-4 sm:grid-cols-3">
            <div className="grid gap-2">
              <Label htmlFor="p-rps">{t("profile.rps")}</Label>
              <Input id="p-rps" type="number" min={0} value={rps} onChange={(e) => setRps(e.target.value)} />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="p-rpm">{t("profile.rpm")}</Label>
              <Input id="p-rpm" type="number" min={0} value={rpm} onChange={(e) => setRpm(e.target.value)} />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="p-cw">{t("profile.cw")}</Label>
              <Input
                id="p-cw"
                type="number"
                min={0}
                max={1000}
                value={cw}
                onChange={(e) => setCw(e.target.value)}
                placeholder="200"
              />
            </div>
          </div>
          <p className="-mt-2 text-muted-foreground text-xs">{t("profile.rateHint")}</p>

          <div className="grid gap-3 rounded-lg border p-3">
            <div className="flex items-center justify-between gap-4">
              <div className="grid gap-0.5">
                <Label htmlFor="p-priority" className="text-sm">
                  {t("profile.priority.label")}
                </Label>
                <p className="text-muted-foreground text-xs">{t("profile.priority.hint")}</p>
              </div>
              <Input
                id="p-priority"
                type="number"
                className="w-24 shrink-0"
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
              />
            </div>
            <div className="flex items-center justify-between gap-4 border-t pt-3">
              <div className="grid gap-0.5">
                <Label className="text-sm">{t("profile.exclude.label")}</Label>
                <p className="text-muted-foreground text-xs">{t("profile.exclude.hint")}</p>
              </div>
              <Switch checked={poolExclude} onCheckedChange={setPoolExclude} aria-label={t("profile.exclude.aria")} />
            </div>
            <div className="flex items-center justify-between gap-4 border-t pt-3">
              <div className="grid gap-0.5">
                <Label className="text-sm">{t("profile.streaming.label")}</Label>
                <p className="text-muted-foreground text-xs">
                  {t(authMethod === "api_key" ? "profile.streaming.hint" : "profile.streaming.oauthHint")}
                </p>
              </div>
              <Switch
                checked={authMethod === "api_key" ? streaming : false}
                disabled={authMethod !== "api_key"}
                onCheckedChange={setStreaming}
                aria-label={t("profile.streaming.aria")}
              />
            </div>
          </div>

          <div className="grid gap-3 rounded-lg border p-3">
            <div className="flex items-center justify-between gap-4">
              <div className="grid gap-0.5">
                <Label htmlFor="p-max-tokens" className="text-sm">
                  {t("profile.maxTokens.label")}
                </Label>
                <p className="text-muted-foreground text-xs">{t("profile.maxTokens.hint")}</p>
              </div>
              <Input
                id="p-max-tokens"
                type="number"
                min={0}
                className="w-28 shrink-0"
                value={maxTokens}
                onChange={(e) => setMaxTokens(e.target.value)}
                placeholder="0"
              />
            </div>
            <div className="flex items-center justify-between gap-4 border-t pt-3">
              <div className="grid gap-0.5">
                <Label htmlFor="p-max-tokens-field" className="text-sm">{t("profile.maxTokensField.label")}</Label>
                <p className="text-muted-foreground text-xs">{t(`profile.maxTokensFieldHint.${format}`)}</p>
              </div>
              <Select
                value={authMethod === "api_key" && format === "openai" ? maxTokensField : NONE}
                onValueChange={setMaxTokensField}
                disabled={authMethod !== "api_key" || format !== "openai"}
              >
                <SelectTrigger id="p-max-tokens-field" className="w-56 shrink-0">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {MAX_TOKENS_FIELDS.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="grid gap-3 rounded-lg border p-3">
            <div className="flex items-center justify-between gap-4">
              <div className="grid gap-0.5">
                <Label htmlFor="p-thinking-type" className="text-sm">{t("profile.thinkingType.label")}</Label>
                <p className="text-muted-foreground text-xs">{t("profile.thinkingType.hint")}</p>
              </div>
              <Select value={thinkingType} onValueChange={setThinkingType}>
                <SelectTrigger id="p-thinking-type" className="w-32 shrink-0">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {THINKING_TYPES.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center justify-between gap-4 border-t pt-3">
              <div className="grid gap-0.5">
                <Label htmlFor="p-effort" className="text-sm">{t("profile.effort.label")}</Label>
                <p className="text-muted-foreground text-xs">{t("profile.effort.hint")}</p>
              </div>
              <Select value={effort} onValueChange={setEffort}>
                <SelectTrigger id="p-effort" className="w-32 shrink-0">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {effortItems.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {effortError && <p className="text-destructive text-xs">{effortError}</p>}
          </div>
          <div className="grid gap-3 rounded-lg border p-3">
            <div className="flex items-center justify-between gap-2">
              <Label className="text-sm">{t("profile.refusalFallback.title")}</Label>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={addFallbackStep}
                disabled={refusalFallback.length >= 8}
              >
                <PlusIcon className="size-3.5" />
                {t("profile.refusalFallback.add")}
              </Button>
            </div>
            <p className="text-muted-foreground text-xs">{t("profile.refusalFallback.desc")}</p>

            {!masterFallbackEnabled && (
              <div className="flex items-start gap-2 rounded-md bg-amber-500/10 border border-amber-500/20 p-2.5 text-xs text-amber-500">
                <AlertCircleIcon className="size-4 shrink-0 mt-0.5" />
                <span>{t("profile.refusalFallback.masterOffNote")}</span>
              </div>
            )}

            {refusalFallback.length === 0 ? (
              <p className="text-muted-foreground text-xs italic">{t("profile.refusalFallback.empty")}</p>
            ) : (
              <div className="flex flex-col gap-2">
                {refusalFallback.map((step, idx) => {
                  const stepModelEfforts = authMethod !== "api_key" ? modelEfforts[step.model.trim()] : undefined;
                  const stepEffortOptions = [
                    { value: NONE, label: t("profile.refusalFallback.effortInherit") },
                    ...(stepModelEfforts === undefined
                      ? EFFORT_LEVELS.filter((item) => item.value !== NONE)
                      : stepModelEfforts.map((value) => ({ value, label: value }))),
                  ];
                  return (
                    <div
                      key={idx}
                      className="flex flex-wrap sm:flex-nowrap items-center gap-2 rounded-md border bg-muted/20 p-2 text-xs"
                    >
                      <span className="w-5 shrink-0 font-mono text-center text-muted-foreground">
                        {idx + 1}
                      </span>
                      <div className="flex-1 min-w-[140px]">
                        {authMethod !== "api_key" && models.length > 0 ? (
                          <Select
                            value={step.model || NONE}
                            onValueChange={(val) => updateFallbackStep(idx, { model: val === NONE ? "" : val })}
                          >
                            <SelectTrigger className="h-8 font-mono text-xs" aria-label={t("profile.refusalFallback.model")}>
                              <SelectValue placeholder={t("profile.refusalFallback.model")} />
                            </SelectTrigger>
                            <SelectContent>
                              {models.map((m) => (
                                <SelectItem key={m} value={m}>
                                  {m} {m === model.trim() ? "(primary)" : ""}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        ) : (
                          <Input
                            className="h-8 font-mono text-xs"
                            placeholder={t("profile.refusalFallback.modelPlaceholder")}
                            value={step.model}
                            onChange={(e) => updateFallbackStep(idx, { model: e.target.value })}
                          />
                        )}
                      </div>
                      <div className="w-32 shrink-0">
                        <Select
                          value={step.reasoning_effort ? step.reasoning_effort : NONE}
                          onValueChange={(val) =>
                            updateFallbackStep(idx, { reasoning_effort: val === NONE ? "" : val })
                          }
                        >
                          <SelectTrigger className="h-8 text-xs" aria-label={t("profile.refusalFallback.effort")}>
                            <SelectValue placeholder={t("profile.refusalFallback.effort")} />
                          </SelectTrigger>
                          <SelectContent>
                            {stepEffortOptions.map((opt) => (
                              <SelectItem key={opt.value} value={opt.value}>
                                {opt.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          className="size-7"
                          disabled={idx === 0}
                          onClick={() => moveFallbackStep(idx, "up")}
                          title={t("profile.refusalFallback.moveUp")}
                        >
                          <ArrowUpIcon className="size-3.5" />
                        </Button>
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          className="size-7"
                          disabled={idx === refusalFallback.length - 1}
                          onClick={() => moveFallbackStep(idx, "down")}
                          title={t("profile.refusalFallback.moveDown")}
                        >
                          <ArrowDownIcon className="size-3.5" />
                        </Button>
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          className="size-7 text-muted-foreground hover:text-destructive"
                          onClick={() => removeFallbackStep(idx)}
                          title={t("profile.refusalFallback.remove")}
                        >
                          <Trash2Icon className="size-3.5" />
                        </Button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {authMethod === "api_key" && <ProfileRetryFields value={retry} onChange={setRetry} />}
        </div>

        <div className="flex gap-2 border-t px-4 py-3">
          <Button
            variant="outline"
            onClick={testConnection}
            disabled={testing || (authMethod !== "api_key" && !grantReady)}
          >
            {testing ? <Loader2Icon className="animate-spin" /> : <PlugZapIcon />}
            {testing ? t("profile.testing") : t("profile.testConnection")}
          </Button>
          <Button onClick={save} disabled={saving} className="flex-1">
            {saving && <Loader2Icon className="animate-spin" />}
            {!saving && (isNew ? <PlusIcon /> : <SaveIcon />)}
            {isNew ? t("profile.create") : t("profile.save")}
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );
}

// ─────────────────────────────────────────────────────────────────────────────

export default function LLMPage() {
  const t = useTranslations("llmPage");
  const [profiles, setProfiles] = React.useState<LLMProfile[]>([]);
  const [pool, setPool] = React.useState<LLMPoolStatus | null>(null);
  const [poolOpen, setPoolOpen] = React.useState(false);
  // The drawer's open state and its content are stored separately: editing stays unchanged while closed, otherwise the title would change during the close animation from
  // editing = null means new.
  const [editOpen, setEditOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<LLMProfile | null>(null);
  const openEditor = React.useCallback((p: LLMProfile | null) => {
    setEditing(p);
    setEditOpen(true);
  }, []);

  // Whether a profile is healthy, shown on its card. A profile without a Key cannot send any requests at all, so this should be reported before the circuit breaker state.
  const healthOf = React.useCallback(
    (p: LLMProfile, m?: LLMPoolMember): Health => {
      if (p.auth_method === "api_key" ? (!p.api_key_hint && p.format !== "ollama") : !p.has_grant) {
        const keylessOAuth = p.auth_method !== "api_key";
        return {
          label: t(keylessOAuth ? "health.noOAuth.label" : "health.noKey.label"),
          cls: "border-muted-foreground/40 text-muted-foreground",
          hint: t(keylessOAuth ? "health.noOAuth.hint" : "health.noKey.hint"),
        };
      }
      if (m?.state === "tripped") {
        return {
          label:
            m.cooldown_secs > 0
              ? t("health.trippedCooldown", { cooldown: cooldownText(m.cooldown_secs) })
              : t("health.tripped"),
          cls: "border-destructive/50 text-destructive",
          hint: m.last_error,
        };
      }
      if (m?.state === "degraded") {
        return {
          label: t("health.degraded", { fails: m.fails }),
          cls: "border-amber-500/50 text-amber-600 dark:text-amber-400",
          hint: m.last_error,
        };
      }
      return { label: t("health.ok"), cls: "border-emerald-500/50 text-emerald-600 dark:text-emerald-400" };
    },
    [t],
  );

  const loadPool = React.useCallback(async () => {
    try {
      setPool(await api.llmPool());
    } catch {
      /* ignore */
    }
  }, []);

  const load = React.useCallback(async () => {
    try {
      setProfiles(await api.llmProfiles());
    } catch {
      /* ignore */
    }
    await loadPool();
  }, [loadPool]);

  React.useEffect(() => {
    void load();
  }, [load]);

  // The health badge on the card takes its polling state by profile id.
  const health = React.useMemo(() => {
    const m = new Map<string, LLMPoolMember>();
    for (const c of pool?.chain ?? []) m.set(c.profile_id, c);
    return m;
  }, [pool]);

  async function activate(id: string, name: string) {
    try {
      await api.activateLLMProfile(id);
      toast.success(t("page.toast.activated", { name }));
      await load();
    } catch (e) {
      toast.error(t("page.toast.activateFailed", { msg: (e as Error).message }));
    }
  }

  async function remove(p: LLMProfile) {
    if (p.is_default) {
      toast.error(t("page.toast.cannotDeleteActive"));
      return;
    }
    try {
      await api.deleteLLMProfile(p.id);
      toast.success(t("page.toast.deleted", { name: p.name }));
      await load();
    } catch (e) {
      toast.error(t("page.toast.deleteFailed", { msg: (e as Error).message }));
    }
  }

  const poolOn = pool?.enabled ?? false;

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="font-semibold text-xl tracking-tight">LLM</h1>
          <p className="text-muted-foreground text-sm">{t("page.subtitle")}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" onClick={() => setPoolOpen(true)}>
            <ZapIcon /> {t("page.poolConfig")}
            {poolOn && (
              <Badge variant="outline" className="ml-1 border-emerald-500/50 text-emerald-600 dark:text-emerald-400">
                {t("page.enabled")}
              </Badge>
            )}
          </Button>
          <Button size="sm" variant="outline" onClick={() => openEditor(null)}>
            <PlusIcon /> {t("page.new")}
          </Button>
        </div>
      </div>

      <Tabs defaultValue="profiles" className="flex-1">
        <TabsList>
          <TabsTrigger value="profiles">{t("page.tab.profiles")}</TabsTrigger>
          <TabsTrigger value="retry">{t("page.tab.retry")}</TabsTrigger>
        </TabsList>

        <TabsContent value="profiles" className="mt-4">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
            {profiles.map((p) => {
              const h = healthOf(p, health.get(p.id));
              return (
                // biome-ignore lint/a11y/useSemanticElements: the card contains its own action buttons, and a native <button> would nest buttons (invalid HTML)
                <Card
                  key={p.id}
                  role="button"
                  tabIndex={0}
                  onClick={() => openEditor(p)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      openEditor(p);
                    }
                  }}
                  className={cn(
                    "cursor-pointer gap-0 py-4 outline-none transition-colors hover:border-foreground/30",
                    p.is_default && "border-amber-400/50 bg-amber-400/5",
                  )}
                >
                  <CardContent className="grid gap-2 px-4">
                    <div className="flex items-start gap-2">
                      <StarIcon
                        className={cn(
                          "mt-0.5 size-4 shrink-0",
                          p.is_default ? "fill-amber-400 text-amber-400" : "text-muted-foreground",
                        )}
                      />
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="truncate font-medium text-sm">{p.name}</span>
                          <Badge variant="outline" className="uppercase">
                            {p.format}
                          </Badge>
                          <Badge variant="outline" className={cn("ml-auto", h.cls)} title={h.hint}>
                            {h.label}
                          </Badge>
                        </div>
                        <code className="mt-1 block truncate font-mono text-muted-foreground text-xs">{p.model}</code>
                      </div>
                    </div>

                    <div className="flex flex-wrap gap-x-3 gap-y-0.5 pl-6 text-muted-foreground text-xs">
                      {p.auth_method === "api_key" ? (
                        p.api_key_hint && <span>{p.api_key_hint}</span>
                      ) : (
                        <span>{p.has_grant ? (p.grant_email ?? t("profile.oauth.connected")) : t("profile.oauth.notConnected")}</span>
                      )}
                      <span>
                        {p.rate_per_second}/s · {p.rate_per_minute}/min
                      </span>
                      {p.proxy && <span className="truncate">{t("card.proxy", { proxy: p.proxy })}</span>}
                      {p.reasoning_effort && (
                        <span>
                          {t("card.thinking", {
                            effort: p.reasoning_effort === "off" ? t("card.thinkingOff") : p.reasoning_effort,
                          })}
                        </span>
                      )}
                      {/* The two polling-related fields only matter while polling is enabled; when it is off, they take up no space in the layout */}
                      {poolOn &&
                        !p.is_default &&
                        (p.pool_exclude ? (
                          <span>{t("card.excluded")}</span>
                        ) : (
                          <span>{t("card.priority", { priority: p.priority ?? 0 })}</span>
                        ))}
                    </div>

                    <div className="mt-1 flex gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        className="flex-1"
                        disabled={p.is_default}
                        onClick={(e) => {
                          e.stopPropagation();
                          void activate(p.id, p.name);
                        }}
                      >
                        {p.is_default ? t("card.active") : t("card.activate")}
                      </Button>
                      <Button
                        size="icon"
                        variant="outline"
                        aria-label={t("card.deleteAria")}
                        onClick={(e) => {
                          e.stopPropagation();
                          void remove(p);
                        }}
                      >
                        <Trash2Icon className="text-destructive" />
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
            {profiles.length === 0 && (
              <div className="col-span-full rounded-lg border border-dashed p-10 text-center text-muted-foreground text-sm">
                {t("page.empty")}
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="retry" className="mt-4">
          <RetryPolicyPanel />
        </TabsContent>
      </Tabs>

      <ProfileSheet profile={editing} open={editOpen} onOpenChange={setEditOpen} onSaved={load} />
      <PoolSheet open={poolOpen} onOpenChange={setPoolOpen} pool={pool} onReload={loadPool} />
    </div>
  );
}
