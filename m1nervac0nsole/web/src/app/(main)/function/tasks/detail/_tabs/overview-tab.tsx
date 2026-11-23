"use client";

import * as React from "react";

import {
  ActivityIcon,
  AlertTriangleIcon,
  BugIcon,
  CheckIcon,
  ClockIcon,
  CoinsIcon,
  ListChecksIcon,
  PencilIcon,
  PlusIcon,
  RefreshCwIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  TargetIcon,
  Trash2Icon,
  XIcon,
} from "lucide-react";
import { useTranslations } from "next-intl";

import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Progress } from "@/components/ui/progress";
import { Switch } from "@/components/ui/switch";
import { getDateLocale } from "@/i18n/datetime";
import { api } from "@/lib/api";
import {
  type AssetInterceptKind,
  type AssetInterceptRule,
  type Finding,
  type ModelTokenStat,
  SPEED_PROFILES,
  type SpeedProfile,
  type Stats,
  type Task,
  type TaskConstraint,
  type TaskGoal,
  type TaskNode,
  type TaskScopeRow,
  type TaskScopeRule,
} from "@/lib/types";

// Display token counts concisely (12345 → 12.3k, 2000000 → 2M).
function fmtTokens(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(n >= 10_000_000 ? 0 : 1) + "M";
  if (n >= 1000) return (n / 1000).toFixed(n >= 10000 ? 0 : 1) + "k";
  return String(n);
}

// Cache hit rate = cache reads / input (InputTokens already includes the cache_read subset, so the ratio ranges from 0 to 100%).
function cacheHitRate(cacheRead: number, input: number): string {
  if (input <= 0) return "—";
  return Math.round((cacheRead / input) * 100) + "%";
}

// Display values for one test-scope entry: domain / band / company.
function scopeValue(row: TaskScopeRow, companyFallback: (id: number | string) => string): string {
  if (row.value) return row.value;
  if (row.domain) return row.domain;
  if (row.net) return row.net;
  if (row.company_id) return row.company_name?.trim() ? row.company_name : companyFallback(row.company_id);
  return "—";
}

function StatCard({
  label,
  value,
  sub,
  icon: Icon,
}: {
  label: string;
  value: React.ReactNode;
  sub?: string;
  icon: React.ElementType;
}) {
  return (
    <div className="min-w-0 border-border border-t pt-2">
      <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
        <Icon className="size-3.5" /> {label}
      </div>
      <div className="font-semibold text-2xl tabular-nums">{value}</div>
      {sub && <div className="text-muted-foreground text-xs">{sub}</div>}
    </div>
  );
}

export function OverviewTab({ taskId }: { taskId: string }) {
  const t = useTranslations("taskDetail.overviewTab");
  const [task, setTask] = React.useState<Task | null>(null);
  const [stats, setStats] = React.useState<Stats | null>(null);
  const [intents, setIntents] = React.useState<TaskNode[]>([]);
  const [findings, setFindings] = React.useState<Finding[]>([]);
  const [coverage, setCoverage] = React.useState<{
    enabled: boolean;
    scope_rows: number;
    denominator: number;
    tested: number;
    pct: number | null;
    by_type: { type: string; total: number; tested: number }[];
  } | null>(null);
  // Intent id currently being re-run (batch uses "__all__"). Used to disable the button and show a spinner.
  const [rerunning, setRerunning] = React.useState<Set<string>>(new Set());
  // Test scope list + add-form state.
  const [scope, setScope] = React.useState<TaskScopeRow[]>([]);
  const [scopeKind, setScopeKind] = React.useState<TaskScopeRow["kind"]>("root_domain");
  const [scopeValueInput, setScopeValueInput] = React.useState("");
  const [scopeBusy, setScopeBusy] = React.useState(false);
  const [scopeErr, setScopeErr] = React.useState("");
  // Rules are the explicit layer over the rows above; they decide first.
  const [scopeRules, setScopeRules] = React.useState<TaskScopeRule[]>([]);
  const [ruleEffect, setRuleEffect] = React.useState<"include" | "exclude">("exclude");
  const [rulePattern, setRulePattern] = React.useState("");
  const [ruleNote, setRuleNote] = React.useState("");
  const [ruleBusy, setRuleBusy] = React.useState(false);
  const [ruleErr, setRuleErr] = React.useState("");
  const [editingRuleId, setEditingRuleId] = React.useState<number | null>(null);
  // Rule id whose Approve / Revoke call is in flight.
  const [authorizingRuleId, setAuthorizingRuleId] = React.useState<number | null>(null);
  // Per-model token usage (taken from the always-on llm_usage metering ledger, so it is accurate per call).
  const [modelTokens, setModelTokens] = React.useState<ModelTokenStat[]>([]);
  // Goal management: goal list + add form + inline edit state.
  const [goals, setGoals] = React.useState<TaskGoal[]>([]);
  const [goalText, setGoalText] = React.useState("");
  const [goalVuln, setGoalVuln] = React.useState("");
  const [goalBusy, setGoalBusy] = React.useState(false);
  const [goalErr, setGoalErr] = React.useState("");
  const [editingGoalId, setEditingGoalId] = React.useState<string | null>(null);
  const [editText, setEditText] = React.useState("");
  const [editVuln, setEditVuln] = React.useState("");
  // Constraint management: constraint list + add form + inline edit state.
  const [constraints, setConstraints] = React.useState<TaskConstraint[]>([]);
  const [conText, setConText] = React.useState("");
  const [conKind, setConKind] = React.useState<TaskConstraint["kind"]>("deny");
  const [conBusy, setConBusy] = React.useState(false);
  const [conErr, setConErr] = React.useState("");
  const [editingConId, setEditingConId] = React.useState<string | null>(null);
  const [editConText, setEditConText] = React.useState("");
  const [editConKind, setEditConKind] = React.useState<TaskConstraint["kind"]>("deny");
  const tsp = useTranslations("speedProfile");
  const [speedErr, setSpeedErr] = React.useState("");

  const changeSpeedProfile = async (next: SpeedProfile) => {
    setSpeedErr("");
    try {
      await api.setTaskSpeedProfile(taskId, next);
      setTask((prev) => (prev ? { ...prev, speed_profile: next } : prev));
    } catch (e) {
      setSpeedErr(tsp("saveFailed", { error: e instanceof Error ? e.message : "" }));
    }
  };

  const loadTokens = React.useCallback(async () => {
    try {
      const resp = await api.tokensByModel(taskId);
      setModelTokens(resp.models);
    } catch {
      // Ignore: if there is no PG, the API returns an error and the card is naturally empty.
    }
  }, [taskId]);

  const loadScopeRules = React.useCallback(async () => {
    try {
      setScopeRules(await api.taskScopeRules(taskId));
    } catch {
      // Same as the rows: no asset store means an empty card, not an error.
    }
  }, [taskId]);

  const loadScope = React.useCallback(async () => {
    try {
      const resp = await api.taskScope(taskId);
      setScope(resp.scope);
    } catch {
      // Ignore: if there is no asset store, the API returns 503 and the scope card is naturally empty.
    }
  }, [taskId]);

  // Rules load beside the rows; both come from the same boundary.
  React.useEffect(() => {
    void loadScopeRules();
  }, [loadScopeRules]);

  const addScopeRule = async () => {
    const pattern = rulePattern.trim();
    if (!pattern) return;
    setRuleBusy(true);
    setRuleErr("");
    try {
      if (editingRuleId !== null) {
        await api.updateTaskScopeRule(taskId, editingRuleId, ruleEffect, pattern, ruleNote.trim());
      } else {
        await api.addTaskScopeRule(taskId, ruleEffect, pattern, ruleNote.trim());
      }
      setEditingRuleId(null);
      setRulePattern("");
      setRuleNote("");
      await loadScopeRules();
    } catch (e) {
      setRuleErr(e instanceof Error ? e.message : t("addFailed"));
    } finally {
      setRuleBusy(false);
    }
  };

  const startEditRule = (rule: TaskScopeRule) => {
    setEditingRuleId(rule.id);
    setRuleEffect(rule.effect);
    setRulePattern(rule.pattern);
    setRuleNote(rule.note);
  };

  const cancelEditRule = () => {
    setEditingRuleId(null);
    setRulePattern("");
    setRuleNote("");
  };

  const removeScopeRule = async (id: number) => {
    setScopeRules((prev) => prev.filter((r) => r.id !== id));
    try {
      await api.deleteTaskScopeRule(taskId, id);
    } catch {
      await loadScopeRules(); // Delete failed: re-fetch to restore.
    }
  };

  // Approval is what turns a written include rule into a grant the gateway
  // honours; a revoke takes it back without deleting the row.
  const setRuleAuthorized = async (rule: TaskScopeRule, authorized: boolean) => {
    setAuthorizingRuleId(rule.id);
    setRuleErr("");
    try {
      await api.setTaskRuleAuthorized(taskId, rule.id, authorized);
      await loadScopeRules();
    } catch (e) {
      setRuleErr(e instanceof Error ? e.message : t("scope.authorizeFailed"));
    } finally {
      setAuthorizingRuleId(null);
    }
  };

  const loadGoals = React.useCallback(async () => {
    try {
      const resp = await api.taskGoals(taskId);
      setGoals(resp.goals);
    } catch {
      // Ignore: transient error; retry on the next poll.
    }
  }, [taskId]);

  const addGoal = async () => {
    const text = goalText.trim();
    if (!text) return;
    setGoalBusy(true);
    setGoalErr("");
    try {
      await api.addGoal(taskId, text, goalVuln.trim() || undefined);
      setGoalText("");
      setGoalVuln("");
      await loadGoals();
    } catch (e) {
      setGoalErr(e instanceof Error ? e.message : t("addFailed"));
    } finally {
      setGoalBusy(false);
    }
  };

  const startEditGoal = (g: TaskGoal) => {
    setEditingGoalId(g.id);
    setEditText(g.text);
    setEditVuln(g.vulnclass ?? "");
  };

  const cancelEditGoal = () => {
    setEditingGoalId(null);
    setEditText("");
    setEditVuln("");
  };

  const saveEditGoal = async (g: TaskGoal) => {
    const text = editText.trim();
    if (!text) return;
    setGoalBusy(true);
    setGoalErr("");
    try {
      await api.updateGoal(taskId, g.id, text, editVuln.trim() || undefined);
      cancelEditGoal();
      await loadGoals();
    } catch (e) {
      setGoalErr(e instanceof Error ? e.message : t("saveFailed"));
    } finally {
      setGoalBusy(false);
    }
  };

  const removeGoal = async (g: TaskGoal) => {
    setGoals((prev) => prev.filter((x) => x.id !== g.id));
    try {
      await api.deleteGoal(taskId, g.id);
    } catch {
      await loadGoals(); // Delete failed: re-fetch to restore.
    }
  };

  const loadConstraints = React.useCallback(async () => {
    try {
      const resp = await api.taskConstraints(taskId);
      setConstraints(resp.constraints);
    } catch {
      // Ignore: transient error; retry on the next poll.
    }
  }, [taskId]);

  const addConstraint = async () => {
    const text = conText.trim();
    if (!text) return;
    setConBusy(true);
    setConErr("");
    try {
      await api.addConstraint(taskId, text, conKind);
      setConText("");
      await loadConstraints();
    } catch (e) {
      setConErr(e instanceof Error ? e.message : t("addFailed"));
    } finally {
      setConBusy(false);
    }
  };

  const startEditConstraint = (c: TaskConstraint) => {
    setEditingConId(c.id);
    setEditConText(c.text);
    setEditConKind(c.kind);
  };

  const cancelEditConstraint = () => {
    setEditingConId(null);
    setEditConText("");
    setEditConKind("deny");
  };

  const saveEditConstraint = async (c: TaskConstraint) => {
    const text = editConText.trim();
    if (!text) return;
    setConBusy(true);
    setConErr("");
    try {
      await api.updateConstraint(taskId, c.id, text, editConKind);
      cancelEditConstraint();
      await loadConstraints();
    } catch (e) {
      setConErr(e instanceof Error ? e.message : t("saveFailed"));
    } finally {
      setConBusy(false);
    }
  };

  const removeConstraint = async (c: TaskConstraint) => {
    setConstraints((prev) => prev.filter((x) => x.id !== c.id));
    try {
      await api.deleteConstraint(taskId, c.id);
    } catch {
      await loadConstraints(); // Delete failed: re-fetch to restore.
    }
  };

  const addScope = async () => {
    const value = scopeValueInput.trim();
    if (!value) return;
    setScopeBusy(true);
    setScopeErr("");
    try {
      await api.addTaskScope(taskId, scopeKind, value);
      setScopeValueInput("");
      await loadScope();
    } catch (e) {
      setScopeErr(e instanceof Error ? e.message : t("addFailed"));
    } finally {
      setScopeBusy(false);
    }
  };

  const removeScope = async (row: TaskScopeRow) => {
    setScope((prev) => prev.filter((s) => s.id !== row.id));
    try {
      await api.deleteTaskScope(taskId, row.id);
    } catch {
      await loadScope(); // Delete failed: re-fetch to restore.
    }
  };

  const markRerun = (key: string, on: boolean) =>
    setRerunning((prev) => {
      const next = new Set(prev);
      if (on) next.add(key);
      else next.delete(key);
      return next;
    });

  // Re-run a single item: revert it to open (optimistically update the local state; the 3-second poll corrects it). The worker picks it up again and runs it from the beginning.
  const rerunOne = async (id: string) => {
    markRerun(id, true);
    try {
      await api.rerunIntent(taskId, id);
      setIntents((prev) => prev.map((i) => (i.id === id ? { ...i, state: "open" } : i)));
    } catch {
      // Ignore failure: it will still show as blocked on the next poll, so the user can press the button again.
    } finally {
      markRerun(id, false);
    }
  };

  // Re-run all blocked items of the current job in bulk.
  const rerunAll = async () => {
    markRerun("__all__", true);
    try {
      await api.rerunBlocked(taskId);
      setIntents((prev) => prev.map((i) => (i.state === "blocked" ? { ...i, state: "open" } : i)));
    } catch {
      // ignore
    } finally {
      markRerun("__all__", false);
    }
  };

  React.useEffect(() => {
    let cancelled = false;
    let loading = false;
    let first = true;

    const load = async () => {
      if (loading) return;
      loading = true;
      try {
        const [taskResp, statsResp, intentsResp] = await Promise.all([
          api.task(taskId),
          api.stats(taskId),
          api.intents(taskId),
        ]);
        if (cancelled) return;
        const activeTask = statsResp.active_task;
        setTask(
          activeTask
            ? {
                ...taskResp,
                in_flight: activeTask.in_flight,
                goals_total: activeTask.goals_total,
                goals_met: activeTask.goals_met,
                engine_mode: statsResp.engine_mode ?? activeTask.engine_mode,
                paused: activeTask.paused,
              }
            : taskResp,
        );
        setStats(statsResp);
        setIntents(intentsResp);
        // The findings list carries every evidence body, so it is refetched only
        // while the task can still produce one, plus once when the tab opens.
        if (first || taskResp.status === "running") {
          const findingsResp = await api.findings(taskId);
          if (cancelled) return;
          setFindings(findingsResp);
        }
        first = false;
        // coverage is independent + may 503 when no asset store — fetch separately so
        // its failure never blocks the others.
        api
          .taskCoverage(taskId)
          .then((c) => {
            if (!cancelled) setCoverage(c);
          })
          .catch(() => {
            // A transient coverage failure is retried by the next poll.
          });
      } catch {
        // transient errors are ignored; the next poll will retry
      } finally {
        loading = false;
      }
    };

    void load();
    void loadScope();
    void loadTokens();
    void loadGoals();
    void loadConstraints();
    const timer = setInterval(() => {
      void load();
      void loadTokens();
      void loadGoals();
      void loadConstraints();
    }, 3000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [taskId, loadScope, loadTokens, loadGoals, loadConstraints]);

  const running = intents.filter((i) => i.state === "running");
  const open = intents.filter((i) => i.state === "open");
  const blocked = intents.filter((i) => i.state === "blocked");
  const taskFindings = findings.filter((f) => f.task_id === taskId);
  const goalsPct = task?.goals_total ? Math.round(((task.goals_met ?? 0) / task.goals_total) * 100) : 0;
  // Token totals (summed across all models); used in the card header summary.
  const tokenTotals = modelTokens.reduce(
    (acc, m) => {
      acc.input += m.input_tokens;
      acc.output += m.output_tokens;
      acc.cacheRead += m.cache_read_tokens;
      acc.cacheWrite += m.cache_write_tokens;
      acc.calls += m.calls;
      return acc;
    },
    { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, calls: 0 },
  );

  return (
    <div className="flex flex-col gap-4">
      {/* The original task description and goal entered at creation. Kept at the top so it can be reviewed at any time. */}
      <section className="min-w-0 border-border border-t pt-3">
        <div className="mb-2">
          <h2 className="flex items-center gap-2 font-medium text-sm">
            <TargetIcon className="size-4 text-muted-foreground" /> {t("desc.title")}
          </h2>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="flex flex-col gap-1.5">
            <div className="font-medium text-muted-foreground text-xs">{t("desc.descLabel")}</div>
            <p className="whitespace-pre-wrap break-words text-sm">{task?.description?.trim() || "—"}</p>
          </div>
          <div className="flex flex-col gap-1.5">
            <div className="font-medium text-muted-foreground text-xs">{t("desc.goalLabel")}</div>
            <p className="whitespace-pre-wrap break-words text-sm">{task?.goal?.trim() || "—"}</p>
          </div>
        </div>
      </section>
      <section className="min-w-0 border-border border-t pt-3">
        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor="task-speed-profile" className="font-medium text-sm">
            {tsp("label")}
          </label>
          <NativeSelect
            id="task-speed-profile"
            size="sm"
            value={task?.speed_profile ?? "standard"}
            onChange={(e) => void changeSpeedProfile(e.target.value as SpeedProfile)}
          >
            {SPEED_PROFILES.map((p) => (
              <NativeSelectOption key={p} value={p}>
                {tsp(`${p}.name`)}
              </NativeSelectOption>
            ))}
          </NativeSelect>
          <span className="text-muted-foreground text-xs">{tsp(`${task?.speed_profile ?? "standard"}.hint`)}</span>
          {speedErr && <span className="text-destructive text-xs">{speedErr}</span>}
        </div>
      </section>
      {/* Goal management: view, add, edit, and delete the exploration goals of the current task.
          Adding and editing notify the planner and resume the task; deletion notifies only the planner (no resume).
          A goal = a final deliverable or verifiable result, not an attack stage or a reconnaissance action. */}
      <section className="min-w-0 border-border border-t pt-3">
        <div className="mb-2">
          <h2 className="flex items-center gap-2 font-medium text-sm">
            <ListChecksIcon className="size-4 text-muted-foreground" /> {t("goals.title")}
            <span className="font-normal text-muted-foreground text-xs">
              {t("goals.hint", { count: goals.length })}
            </span>
          </h2>
        </div>
        <div className="flex flex-col gap-3">
          {/* Add form */}
          <div className="flex flex-wrap items-center gap-2">
            <Input
              className="h-7 min-w-56 flex-1 text-sm"
              placeholder={t("goals.addPlaceholder")}
              value={goalText}
              onChange={(e) => setGoalText(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void addGoal();
              }}
              disabled={goalBusy}
            />
            <Input
              className="h-7 w-32 text-sm"
              placeholder={t("goals.vulnPlaceholder")}
              value={goalVuln}
              onChange={(e) => setGoalVuln(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void addGoal();
              }}
              disabled={goalBusy}
            />
            <Button size="sm" variant="outline" disabled={goalBusy || !goalText.trim()} onClick={() => void addGoal()}>
              <PlusIcon className="size-3.5" /> {t("add")}
            </Button>
            {goalErr && <span className="text-destructive text-xs">{goalErr}</span>}
          </div>
          {/* Goal list */}
          {goals.length > 0 ? (
            <div className="flex flex-col gap-1.5">
              {goals.map((g) =>
                editingGoalId === g.id ? (
                  <div key={g.id} className="flex flex-wrap items-center gap-2 rounded-md border px-2.5 py-1.5">
                    <Input
                      className="h-7 min-w-56 flex-1 text-sm"
                      value={editText}
                      onChange={(e) => setEditText(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") void saveEditGoal(g);
                        if (e.key === "Escape") cancelEditGoal();
                      }}
                      disabled={goalBusy}
                      autoFocus
                    />
                    <Input
                      className="h-7 w-32 text-sm"
                      placeholder={t("goals.vulnPlaceholder")}
                      value={editVuln}
                      onChange={(e) => setEditVuln(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") void saveEditGoal(g);
                        if (e.key === "Escape") cancelEditGoal();
                      }}
                      disabled={goalBusy}
                    />
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 shrink-0 px-1.5"
                      disabled={goalBusy || !editText.trim()}
                      onClick={() => void saveEditGoal(g)}
                    >
                      <CheckIcon className="size-3.5 text-success" />
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 shrink-0 px-1.5"
                      disabled={goalBusy}
                      onClick={cancelEditGoal}
                    >
                      <XIcon className="size-3.5" />
                    </Button>
                  </div>
                ) : (
                  <div key={g.id} className="flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-sm">
                    <StatusBadge domain="goal" value={g.state} />
                    <span className="min-w-0 flex-1 break-words">{g.text}</span>
                    {g.vulnclass && (
                      <span className="shrink-0 rounded bg-muted px-1.5 py-0.5 text-muted-foreground text-xs">
                        {g.vulnclass}
                      </span>
                    )}
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 shrink-0 px-1.5"
                      disabled={goalBusy}
                      onClick={() => startEditGoal(g)}
                    >
                      <PencilIcon className="size-3.5" />
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 shrink-0 px-1.5"
                      disabled={goalBusy}
                      onClick={() => void removeGoal(g)}
                    >
                      <Trash2Icon className="size-3.5 text-destructive" />
                    </Button>
                  </div>
                ),
              )}
            </div>
          ) : (
            <p className="text-muted-foreground text-sm">{t("goals.empty")}</p>
          )}
        </div>
      </section>
      {/* Manage behavioral constraints: allow=permit / deny=prohibit. Constraints are injected into the planner/worker system
          prompts in the next planning cycle to set exploration boundaries (injection can be enabled or disabled separately
          for planner/worker in system settings). Changes do not interrupt execution immediately; the next planning cycle reads them naturally. */}
      <section className="min-w-0 border-border border-t pt-3">
        <div className="mb-2">
          <h2 className="flex items-center gap-2 font-medium text-sm">
            <ShieldAlertIcon className="size-4 text-warning" /> {t("constraints.title")}
            <span className="font-normal text-muted-foreground text-xs">
              {t("constraints.hint", { count: constraints.length })}
            </span>
          </h2>
        </div>
        <div className="flex flex-col gap-3">
          {/* Add form */}
          <div className="flex flex-wrap items-center gap-2">
            <NativeSelect
              size="sm"
              value={conKind}
              onChange={(e) => setConKind(e.target.value as TaskConstraint["kind"])}
            >
              <NativeSelectOption value="deny">{t("constraints.deny")}</NativeSelectOption>
              <NativeSelectOption value="allow">{t("constraints.allow")}</NativeSelectOption>
            </NativeSelect>
            <Input
              className="h-7 min-w-56 flex-1 text-sm"
              placeholder={t("constraints.addPlaceholder")}
              value={conText}
              onChange={(e) => setConText(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void addConstraint();
              }}
              disabled={conBusy}
            />
            <Button
              size="sm"
              variant="outline"
              disabled={conBusy || !conText.trim()}
              onClick={() => void addConstraint()}
            >
              <PlusIcon className="size-3.5" /> {t("add")}
            </Button>
            {conErr && <span className="text-destructive text-xs">{conErr}</span>}
          </div>
          {/* Constraint list */}
          {constraints.length > 0 ? (
            <div className="flex flex-col gap-1.5">
              {constraints.map((c) =>
                editingConId === c.id ? (
                  <div key={c.id} className="flex flex-wrap items-center gap-2 rounded-md border px-2.5 py-1.5">
                    <NativeSelect
                      size="sm"
                      value={editConKind}
                      onChange={(e) => setEditConKind(e.target.value as TaskConstraint["kind"])}
                    >
                      <NativeSelectOption value="deny">{t("constraints.deny")}</NativeSelectOption>
                      <NativeSelectOption value="allow">{t("constraints.allow")}</NativeSelectOption>
                    </NativeSelect>
                    <Input
                      className="h-7 min-w-56 flex-1 text-sm"
                      value={editConText}
                      onChange={(e) => setEditConText(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") void saveEditConstraint(c);
                        if (e.key === "Escape") cancelEditConstraint();
                      }}
                      disabled={conBusy}
                      autoFocus
                    />
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 shrink-0 px-1.5"
                      disabled={conBusy || !editConText.trim()}
                      onClick={() => void saveEditConstraint(c)}
                    >
                      <CheckIcon className="size-3.5 text-success" />
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 shrink-0 px-1.5"
                      disabled={conBusy}
                      onClick={cancelEditConstraint}
                    >
                      <XIcon className="size-3.5" />
                    </Button>
                  </div>
                ) : (
                  <div key={c.id} className="flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-sm">
                    <span
                      className={`shrink-0 rounded px-1.5 py-0.5 text-xs ${
                        c.kind === "allow"
                          ? "border border-success/40 bg-success/10 text-success"
                          : "border border-destructive/40 bg-destructive/10 text-destructive"
                      }`}
                    >
                      {c.kind === "allow" ? t("constraints.allow") : t("constraints.deny")}
                    </span>
                    <span className="min-w-0 flex-1 break-words">{c.text}</span>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 shrink-0 px-1.5"
                      disabled={conBusy}
                      onClick={() => startEditConstraint(c)}
                    >
                      <PencilIcon className="size-3.5" />
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 shrink-0 px-1.5"
                      disabled={conBusy}
                      onClick={() => void removeConstraint(c)}
                    >
                      <Trash2Icon className="size-3.5 text-destructive" />
                    </Button>
                  </div>
                ),
              )}
            </div>
          ) : (
            <p className="text-muted-foreground text-sm">{t("constraints.empty")}</p>
          )}
        </div>
      </section>
      <TaskInterceptRulesCard taskId={taskId} />
      {coverage && coverage.enabled && coverage.scope_rows > 0 && (
        <section className="min-w-0 border-border border-t pt-3">
          <div className="mb-2">
            <h2 className="flex items-center gap-2 font-medium text-sm">
              <TargetIcon className="size-4 text-success" /> {t("coverage.title")}
              <span className="font-normal text-muted-foreground text-xs">{t("coverage.rough")}</span>
            </h2>
          </div>
          <div className="flex flex-col gap-3">
            <div className="flex items-baseline gap-3">
              <span className="font-semibold text-2xl tabular-nums">
                {coverage.pct != null ? Math.round(coverage.pct * 100) + "%" : "—"}
              </span>
              <span className="text-muted-foreground text-sm">
                {t("coverage.testedOf", { tested: coverage.tested, total: coverage.denominator })}
              </span>
            </div>
            {coverage.pct != null && <Progress value={Math.round(coverage.pct * 100)} />}
            {coverage.by_type.length > 0 && (
              <div className="flex flex-wrap gap-1.5 text-xs">
                {coverage.by_type.map((b) => (
                  <span key={b.type} className="rounded bg-muted px-1.5 py-0.5">
                    <span className="text-muted-foreground">{b.type}</span>{" "}
                    <span className="font-medium tabular-nums">
                      {b.tested}/{b.total}
                    </span>
                  </span>
                ))}
              </div>
            )}
          </div>
        </section>
      )}
      {/* LLM Token usage: grouped by model; data comes from llm_records (LLM recording must be enabled). */}
      <section className="min-w-0 border-border border-t pt-3">
        <div className="mb-2">
          <h2 className="flex items-center gap-2 font-medium text-sm">
            <CoinsIcon className="size-4 text-warning" /> {t("tokens.title")}
            <span className="font-normal text-muted-foreground text-xs">
              {t("tokens.hint", { calls: tokenTotals.calls })}
            </span>
          </h2>
        </div>
        <div className="flex flex-col gap-3">
          {modelTokens.length > 0 ? (
            <>
              {/* Total summary */}
              <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 text-sm">
                <span className="tabular-nums">
                  <span className="text-muted-foreground">{t("tokens.input")} </span>
                  <span className="font-semibold">{fmtTokens(tokenTotals.input)}</span>
                </span>
                <span className="tabular-nums">
                  <span className="text-muted-foreground">{t("tokens.output")} </span>
                  <span className="font-semibold">{fmtTokens(tokenTotals.output)}</span>
                </span>
                <span className="tabular-nums">
                  <span className="text-muted-foreground">{t("tokens.cacheRead")} </span>
                  <span className="font-semibold">{fmtTokens(tokenTotals.cacheRead)}</span>
                </span>
                <span className="tabular-nums">
                  <span className="text-muted-foreground">{t("tokens.cacheHitRate")} </span>
                  <span className="font-semibold text-success">
                    {cacheHitRate(tokenTotals.cacheRead, tokenTotals.input)}
                  </span>
                </span>
              </div>
              {/* Per-model spec table */}
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left text-muted-foreground text-xs">
                      <th className="py-1.5 pr-3 font-medium">{t("tokens.colModel")}</th>
                      <th className="py-1.5 pr-3 text-right font-medium">{t("tokens.colCalls")}</th>
                      <th className="py-1.5 pr-3 text-right font-medium">{t("tokens.input")}</th>
                      <th className="py-1.5 pr-3 text-right font-medium">{t("tokens.output")}</th>
                      <th className="py-1.5 pr-3 text-right font-medium">{t("tokens.cacheRead")}</th>
                      <th className="py-1.5 text-right font-medium">{t("tokens.colHitRate")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {modelTokens.map((m) => (
                      <tr key={m.model} className="border-b last:border-0">
                        <td className="max-w-[16rem] truncate py-1.5 pr-3 font-mono text-xs" title={m.model}>
                          {m.model}
                        </td>
                        <td className="py-1.5 pr-3 text-right tabular-nums">{m.calls}</td>
                        <td className="py-1.5 pr-3 text-right tabular-nums">{fmtTokens(m.input_tokens)}</td>
                        <td className="py-1.5 pr-3 text-right tabular-nums">{fmtTokens(m.output_tokens)}</td>
                        <td className="py-1.5 pr-3 text-right tabular-nums">{fmtTokens(m.cache_read_tokens)}</td>
                        <td className="py-1.5 text-right text-success tabular-nums">
                          {cacheHitRate(m.cache_read_tokens, m.input_tokens)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <p className="text-muted-foreground text-sm">{t("tokens.empty")}</p>
          )}
        </div>
      </section>
      {/* Test scope: coverage denominator + permission boundaries. Can be added or removed directly. */}
      <section className="min-w-0 border-border border-t pt-3">
        <div className="mb-2">
          <h2 className="flex items-center gap-2 font-medium text-sm">
            <ShieldCheckIcon className="size-4 text-success" /> {t("scope.title")}
            <span className="font-normal text-muted-foreground text-xs">
              {t("scope.hint", { count: scope.length })}
            </span>
          </h2>
        </div>
        <div className="flex flex-col gap-3">
          {/* Add form */}
          <div className="flex flex-wrap items-center gap-2">
            <NativeSelect
              size="sm"
              value={scopeKind}
              onChange={(e) => setScopeKind(e.target.value as TaskScopeRow["kind"])}
            >
              <NativeSelectOption value="root_domain">{t("scope.kind.root_domain")}</NativeSelectOption>
              <NativeSelectOption value="subdomain">{t("scope.kind.subdomain")}</NativeSelectOption>
              <NativeSelectOption value="ip">{t("scope.kind.ip")}</NativeSelectOption>
              <NativeSelectOption value="cidr">{t("scope.kind.cidr")}</NativeSelectOption>
              <NativeSelectOption value="icp">{t("scope.kind.icp")}</NativeSelectOption>
              <NativeSelectOption value="keyword">{t("scope.kind.keyword")}</NativeSelectOption>
              <NativeSelectOption value="company">{t("scope.kind.company")}</NativeSelectOption>
            </NativeSelect>
            <Input
              className="h-7 w-56 text-sm"
              placeholder={
                scopeKind === "company"
                  ? t("scope.placeholder.company")
                  : scopeKind === "ip" || scopeKind === "cidr"
                    ? t("scope.placeholder.ipCidr")
                    : scopeKind === "icp"
                      ? t("scope.placeholder.icp")
                      : scopeKind === "keyword"
                        ? t("scope.placeholder.keyword")
                        : t("scope.placeholder.domain")
              }
              value={scopeValueInput}
              onChange={(e) => setScopeValueInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void addScope();
              }}
              disabled={scopeBusy}
            />
            <Button
              size="sm"
              variant="outline"
              disabled={scopeBusy || !scopeValueInput.trim()}
              onClick={() => void addScope()}
            >
              <PlusIcon className="size-3.5" /> {t("add")}
            </Button>
            {scopeErr && <span className="text-destructive text-xs">{scopeErr}</span>}
          </div>
          {/* Scope list */}
          {scope.length > 0 ? (
            <div className="flex flex-col gap-1.5">
              {scope.map((row) => (
                <div key={row.id} className="flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-sm">
                  <span className="shrink-0 rounded bg-muted px-1.5 py-0.5 text-muted-foreground text-xs">
                    {t(`scope.kind.${row.kind}`)}
                  </span>
                  <span className="min-w-0 flex-1 truncate font-mono text-xs">
                    {scopeValue(row, (id) => t("scope.companyFallback", { id }))}
                  </span>
                  <span className="shrink-0 text-muted-foreground text-xs">{t(`scope.source.${row.source}`)}</span>
                  {row.task_id.toString() === taskId ? (
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 shrink-0 px-1.5"
                      onClick={() => void removeScope(row)}
                    >
                      <Trash2Icon className="size-3.5 text-destructive" />
                    </Button>
                  ) : (
                    <span className="shrink-0 text-muted-foreground text-xs">{t("scope.inherited")}</span>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-muted-foreground text-sm">{t("scope.empty")}</p>
          )}

          {/* Rules: the operator's explicit layer. A matching rule decides before
              any row above, so an include can carve one host out of a broad
              exclusion. */}
          <div className="mt-3 flex flex-col gap-1.5 border-border border-t pt-3">
            <div className="flex items-center gap-2">
              <span className="font-medium text-xs">{t("scope.rulesTitle")}</span>
              <span className="text-muted-foreground text-xs">{t("scope.rulesHint")}</span>
            </div>
            {scopeRules.map((rule) => {
              // An exclude restricts without approval; an include grants only
              // once approved, so its unapproved state says so plainly.
              const state = rule.effect === "exclude" ? "restriction" : rule.authorized ? "authorized" : "pending";
              return (
                <div key={rule.id} className="flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-sm">
                  <span
                    className={`shrink-0 rounded px-1.5 py-0.5 text-xs ${
                      rule.effect === "exclude"
                        ? "bg-destructive/10 text-destructive"
                        : "bg-muted text-muted-foreground"
                    }`}
                  >
                    {t(`scope.effect.${rule.effect}`)}
                  </span>
                  <span className="min-w-0 flex-1 truncate font-mono text-xs">{rule.pattern}</span>
                  <span
                    title={t(`scope.stateHint.${state}`)}
                    className={`shrink-0 rounded px-1.5 py-0.5 text-xs ${
                      state === "authorized" ? "bg-success/10 text-success" : "bg-muted text-muted-foreground"
                    }`}
                  >
                    {t(`scope.state.${state}`)}
                  </span>
                  {rule.effect === "include" && (
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-6 shrink-0 px-1.5 text-xs"
                      disabled={authorizingRuleId === rule.id}
                      onClick={() => void setRuleAuthorized(rule, !rule.authorized)}
                    >
                      {rule.authorized ? t("scope.revoke") : t("scope.approve")}
                    </Button>
                  )}
                  {rule.note && (
                    <span className="shrink-0 max-w-[30%] truncate text-muted-foreground text-xs">{rule.note}</span>
                  )}
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 shrink-0 px-1.5"
                    onClick={() => void removeScopeRule(rule.id)}
                  >
                    <Trash2Icon className="size-3.5 text-destructive" />
                  </Button>
                </div>
              );
            })}
            <div className="flex flex-wrap items-center gap-2">
              <select
                aria-label={t("scope.effectLabel")}
                className="h-8 rounded-md border bg-transparent px-2 text-xs"
                value={ruleEffect}
                onChange={(e) => setRuleEffect(e.target.value as "include" | "exclude")}
              >
                <option value="exclude">{t("scope.effect.exclude")}</option>
                <option value="include">{t("scope.effect.include")}</option>
              </select>
              <Input
                aria-label={t("scope.patternLabel")}
                className="h-8 w-56 font-mono text-xs"
                placeholder={t("scope.patternPlaceholder")}
                value={rulePattern}
                onChange={(e) => setRulePattern(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") void addScopeRule();
                }}
                disabled={ruleBusy}
              />
              <Input
                aria-label={t("scope.noteLabel")}
                className="h-8 w-48 text-xs"
                placeholder={t("scope.notePlaceholder")}
                value={ruleNote}
                onChange={(e) => setRuleNote(e.target.value)}
                disabled={ruleBusy}
              />
              <Button
                size="sm"
                variant="outline"
                disabled={ruleBusy || !rulePattern.trim()}
                onClick={() => void addScopeRule()}
              >
                <PlusIcon className="size-3.5" /> {editingRuleId !== null ? t("save") : t("add")}
              </Button>
              {editingRuleId !== null && (
                <Button size="sm" variant="ghost" onClick={cancelEditRule}>
                  {t("cancel")}
                </Button>
              )}
              {ruleErr && <span className="text-destructive text-xs">{ruleErr}</span>}
            </div>
          </div>
        </div>
      </section>
      {/* Heartbeat */}
      <section className="min-w-0 border-border border-t pt-3">
        <div className="mb-2">
          <h2 className="flex items-center gap-2 font-medium text-sm">
            <ActivityIcon className="size-4 text-info" /> {t("heartbeat.title")}
          </h2>
        </div>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <div>
            <div className="text-muted-foreground text-xs">{t("heartbeat.engineState")}</div>
            <StatusBadge
              domain="engine"
              value={stats?.engine_mode ?? task?.engine_mode ?? "idle"}
              dot
              className="mt-1"
            />
          </div>
          <div>
            <div className="text-muted-foreground text-xs">{t("heartbeat.runningWorker")}</div>
            <div className="mt-1 font-semibold text-lg tabular-nums">{running.length}</div>
          </div>
          <div>
            <div className="text-muted-foreground text-xs">{t("heartbeat.lastActivity")}</div>
            <div className="mt-1 inline-flex items-center gap-1 text-sm">
              <ClockIcon className="size-3.5" />
              {task?.last_activity ? new Date(task.last_activity).toLocaleTimeString(getDateLocale()) : "—"}
            </div>
          </div>
          <div>
            <div className="text-muted-foreground text-xs">
              {t("heartbeat.goals", { met: task?.goals_met ?? 0, total: task?.goals_total ?? 0 })}
            </div>
            <Progress value={goalsPct} className="mt-2" />
          </div>
          {task?.completed_unix && task.completed_unix > 0 ? (
            <div>
              <div className="text-muted-foreground text-xs">{t("heartbeat.completedAt")}</div>
              <div className="mt-1 inline-flex items-center gap-1 text-sm">
                <ClockIcon className="size-3.5" />
                {new Date(task.completed_unix * 1000).toLocaleString(getDateLocale())}
              </div>
            </div>
          ) : null}
        </div>
      </section>

      {/* Work set */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <section className="min-w-0 border-border border-t pt-3">
          <div className="mb-2">
            <h2 className="flex items-center gap-2 text-sm">
              <TargetIcon className="size-4" /> {t("running.title")}
            </h2>
          </div>
          <div className="flex flex-col gap-2">
            {running.slice(0, 6).map((i) => (
              <div key={i.id} className="flex items-center gap-2 text-sm">
                <StatusBadge domain="intent" value={i.state} />
                <span className="min-w-0 flex-1 truncate">{i.payload}</span>
              </div>
            ))}
            {running.length === 0 && <p className="text-muted-foreground text-sm">{t("running.empty")}</p>}
          </div>
        </section>

        <section className="min-w-0 border-border border-t pt-3">
          <div className="mb-2">
            <h2 className="flex items-center gap-2 text-sm">
              <AlertTriangleIcon className="size-4 text-warning" /> {t("attention.title")}
            </h2>
          </div>
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <div className="font-semibold text-2xl text-destructive tabular-nums">{taskFindings.length}</div>
              <div className="text-muted-foreground text-xs">{t("attention.confirmedVuln")}</div>
            </div>
            <div>
              <div className="font-semibold text-2xl text-info tabular-nums">{running.length}</div>
              <div className="text-muted-foreground text-xs">{t("attention.executing")}</div>
            </div>
            <div>
              <div className="font-semibold text-2xl tabular-nums">{open.length}</div>
              <div className="text-muted-foreground text-xs">{t("attention.frontierPending")}</div>
            </div>
            <div>
              <div className="font-semibold text-2xl text-destructive tabular-nums">{blocked.length}</div>
              <div className="text-muted-foreground text-xs">{t("attention.blockedIntent")}</div>
            </div>
          </div>
        </section>

        <section className="min-w-0 border-border border-t pt-3">
          <div className="mb-2">
            <h2 className="flex items-center gap-2 text-sm">
              <BugIcon className="size-4 text-destructive" /> {t("recent.title")}
            </h2>
          </div>
          <div className="flex flex-col gap-2">
            {taskFindings.slice(0, 6).map((f) => (
              <div key={f.id} className="flex items-center gap-2 text-sm">
                <StatusBadge domain="severity" value={f.severity} dot />
                <span className="min-w-0 flex-1 truncate">{f.summary}</span>
              </div>
            ))}
            {taskFindings.length === 0 && <p className="text-muted-foreground text-sm">{t("recent.empty")}</p>}
          </div>
        </section>
      </div>

      {/* Blocked intents — intents that were errored or blocked (e.g., due to an LLM network problem). They can be re-run all at once: setting them back to open
          lets the worker pick them up again and execute from the beginning (data already written to the graph is kept). If the task is in a terminal state or paused, it is automatically resumed. */}
      {blocked.length > 0 && (
        <section className="min-w-0 border-destructive/40 border-t pt-3">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <h2 className="flex items-center gap-2 text-sm">
              <AlertTriangleIcon className="size-4 text-destructive" /> {t("blocked.title")}
              <span className="font-normal text-muted-foreground text-xs">
                {t("blocked.hint", { count: blocked.length })}
              </span>
            </h2>
            <Button size="sm" variant="outline" disabled={rerunning.has("__all__")} onClick={() => void rerunAll()}>
              <RefreshCwIcon className={`size-3.5 ${rerunning.has("__all__") ? "animate-spin" : ""}`} />
              {t("blocked.rerunAll")}
            </Button>
          </div>
          <div className="flex flex-col gap-2">
            {blocked.slice(0, 20).map((i) => (
              <div key={i.id} className="flex items-center gap-2 text-sm">
                <StatusBadge domain="intent" value={i.state} />
                <span className="min-w-0 flex-1 truncate">{i.payload}</span>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-7 shrink-0 px-2 text-xs"
                  disabled={rerunning.has(i.id)}
                  onClick={() => void rerunOne(i.id)}
                >
                  <RefreshCwIcon className={`size-3 ${rerunning.has(i.id) ? "animate-spin" : ""}`} />
                  {t("blocked.rerun")}
                </Button>
              </div>
            ))}
            {blocked.length > 20 && (
              <p className="text-muted-foreground text-xs">{t("blocked.truncated", { rest: blocked.length - 20 })}</p>
            )}
          </div>
        </section>
      )}

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-3">
        <StatCard label={t("stat.pending")} value={open.length} icon={ShieldCheckIcon} sub={t("stat.pendingSub")} />
        <StatCard label={t("stat.confirmed")} value={taskFindings.length} icon={BugIcon} sub={t("stat.confirmedSub")} />
        <StatCard label={t("stat.total")} value={intents.length} icon={AlertTriangleIcon} sub={t("stat.totalSub")} />
      </div>
    </div>
  );
}

const TASK_RULE_KIND_OPTIONS: { value: AssetInterceptKind; placeholder: string }[] = [
  { value: "exact_domain", placeholder: "example.gov.cn" },
  { value: "exact_ip", placeholder: "203.0.113.10" },
  { value: "exact_url", placeholder: "https://example.com/login" },
  { value: "fuzzy_domain", placeholder: ".gov.cn" },
  { value: "fuzzy_ip", placeholder: "203.0.113." },
  { value: "fuzzy_url", placeholder: "/admin" },
  { value: "cidr", placeholder: "192.168.0.0/16" },
];

// TaskInterceptRulesCard manages the "per-task asset interception / allow rules" in the task detail overview:
// list + add + inline edit + delete + enable/disable toggle. Rules apply only to the current task and are not added to the global table.
function TaskInterceptRulesCard({ taskId }: { taskId: string }) {
  const t = useTranslations("taskDetail.overviewTab");
  const [rules, setRules] = React.useState<AssetInterceptRule[]>([]);
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState("");
  const [newAction, setNewAction] = React.useState<"block" | "allow">("block");
  const [newKind, setNewKind] = React.useState<AssetInterceptKind>("fuzzy_domain");
  const [newPattern, setNewPattern] = React.useState("");
  const [newNote, setNewNote] = React.useState("");
  const [editId, setEditId] = React.useState<number | null>(null);
  const [editAction, setEditAction] = React.useState<"block" | "allow">("block");
  const [editKind, setEditKind] = React.useState<AssetInterceptKind>("fuzzy_domain");
  const [editPattern, setEditPattern] = React.useState("");
  const [editNote, setEditNote] = React.useState("");

  const load = React.useCallback(async () => {
    try {
      setRules(await api.taskInterceptRules(taskId));
    } catch {
      // Ignore transient errors
    }
  }, [taskId]);

  React.useEffect(() => {
    void load();
  }, [load]);

  async function add() {
    if (!newPattern.trim()) return;
    setBusy(true);
    setErr("");
    try {
      await api.createTaskInterceptRule(taskId, {
        action: newAction,
        kind: newKind,
        pattern: newPattern.trim(),
        note: newNote.trim(),
        enabled: true,
      });
      setNewPattern("");
      setNewNote("");
      await load();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function startEdit(r: AssetInterceptRule) {
    setEditId(r.id);
    setEditAction(r.action ?? "block");
    setEditKind(r.kind);
    setEditPattern(r.pattern);
    setEditNote(r.note);
    setErr("");
  }

  async function saveEdit(r: AssetInterceptRule) {
    if (!editPattern.trim()) return;
    setBusy(true);
    setErr("");
    try {
      await api.updateTaskInterceptRule(taskId, r.id, {
        action: editAction,
        kind: editKind,
        pattern: editPattern.trim(),
        note: editNote.trim(),
        enabled: r.enabled,
      });
      setEditId(null);
      await load();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function remove(r: AssetInterceptRule) {
    setRules((prev) => prev.filter((x) => x.id !== r.id));
    try {
      await api.deleteTaskInterceptRule(taskId, r.id);
    } catch {
      await load();
    }
  }

  async function toggle(r: AssetInterceptRule) {
    setRules((prev) => prev.map((x) => (x.id === r.id ? { ...x, enabled: !x.enabled } : x)));
    try {
      await api.toggleTaskInterceptRule(taskId, r.id, !r.enabled);
    } catch {
      await load();
    }
  }

  const placeholder = TASK_RULE_KIND_OPTIONS.find((o) => o.value === newKind)?.placeholder ?? "";

  return (
    <section className="min-w-0 border-border border-t pt-3">
      <div className="mb-2">
        <h2 className="flex items-center gap-2 font-medium text-sm">
          <ShieldCheckIcon className="size-4 text-muted-foreground" /> {t("rule.title")}
          <span className="font-normal text-muted-foreground text-xs">{t("rule.hint", { count: rules.length })}</span>
        </h2>
      </div>
      <div className="flex flex-col gap-3">
        {/* Add form */}
        <div className="flex flex-wrap items-center gap-2">
          <NativeSelect size="sm" value={newAction} onChange={(e) => setNewAction(e.target.value as "block" | "allow")}>
            <NativeSelectOption value="block">{t("rule.block")}</NativeSelectOption>
            <NativeSelectOption value="allow">{t("rule.allow")}</NativeSelectOption>
          </NativeSelect>
          <NativeSelect size="sm" value={newKind} onChange={(e) => setNewKind(e.target.value as AssetInterceptKind)}>
            {TASK_RULE_KIND_OPTIONS.map((o) => (
              <NativeSelectOption key={o.value} value={o.value}>
                {t(`rule.kind.${o.value}`)}
              </NativeSelectOption>
            ))}
          </NativeSelect>
          <Input
            className="h-7 min-w-56 flex-1 text-sm"
            placeholder={placeholder}
            value={newPattern}
            onChange={(e) => setNewPattern(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void add();
            }}
            disabled={busy}
          />
          <Input
            className="h-7 w-36 text-sm"
            placeholder={t("rule.notePlaceholder")}
            value={newNote}
            onChange={(e) => setNewNote(e.target.value)}
            disabled={busy}
          />
          <Button size="sm" variant="outline" disabled={busy || !newPattern.trim()} onClick={() => void add()}>
            <PlusIcon className="size-3.5" /> {t("add")}
          </Button>
          {err && <span className="text-destructive text-xs">{err}</span>}
        </div>
        {/* Rule list */}
        {rules.length > 0 ? (
          <div className="flex flex-col gap-1.5">
            {rules.map((r) =>
              editId === r.id ? (
                <div key={r.id} className="flex flex-wrap items-center gap-2 rounded-md border px-2.5 py-1.5">
                  <NativeSelect
                    size="sm"
                    value={editAction}
                    onChange={(e) => setEditAction(e.target.value as "block" | "allow")}
                  >
                    <NativeSelectOption value="block">{t("rule.block")}</NativeSelectOption>
                    <NativeSelectOption value="allow">{t("rule.allow")}</NativeSelectOption>
                  </NativeSelect>
                  <NativeSelect
                    size="sm"
                    value={editKind}
                    onChange={(e) => setEditKind(e.target.value as AssetInterceptKind)}
                  >
                    {TASK_RULE_KIND_OPTIONS.map((o) => (
                      <NativeSelectOption key={o.value} value={o.value}>
                        {t(`rule.kind.${o.value}`)}
                      </NativeSelectOption>
                    ))}
                  </NativeSelect>
                  <Input
                    className="h-7 min-w-56 flex-1 text-sm"
                    value={editPattern}
                    onChange={(e) => setEditPattern(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") void saveEdit(r);
                      if (e.key === "Escape") setEditId(null);
                    }}
                    disabled={busy}
                    autoFocus
                  />
                  <Input
                    className="h-7 w-36 text-sm"
                    placeholder={t("rule.notePlaceholder")}
                    value={editNote}
                    onChange={(e) => setEditNote(e.target.value)}
                    disabled={busy}
                  />
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 shrink-0 px-1.5"
                    disabled={busy || !editPattern.trim()}
                    onClick={() => void saveEdit(r)}
                  >
                    <CheckIcon className="size-3.5 text-success" />
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 shrink-0 px-1.5"
                    disabled={busy}
                    onClick={() => setEditId(null)}
                  >
                    <XIcon className="size-3.5" />
                  </Button>
                </div>
              ) : (
                <div key={r.id} className="flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-sm">
                  <span
                    className={`shrink-0 rounded px-1.5 py-0.5 text-xs ${
                      r.action === "allow"
                        ? "border border-success/40 bg-success/10 text-success"
                        : "border border-destructive/40 bg-destructive/10 text-destructive"
                    }`}
                  >
                    {r.action === "allow" ? t("rule.allow") : t("rule.block")}
                  </span>
                  <span className="shrink-0 text-muted-foreground text-xs">{t(`rule.kind.${r.kind}`)}</span>
                  <code className="min-w-0 flex-1 truncate rounded bg-muted px-1.5 py-0.5 text-xs">{r.pattern}</code>
                  {r.note && (
                    <span className="max-w-[120px] shrink-0 truncate text-muted-foreground text-xs">{r.note}</span>
                  )}
                  <Switch checked={r.enabled} onCheckedChange={() => void toggle(r)} />
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 shrink-0 px-1.5"
                    disabled={busy}
                    onClick={() => startEdit(r)}
                  >
                    <PencilIcon className="size-3.5" />
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 shrink-0 px-1.5"
                    disabled={busy}
                    onClick={() => void remove(r)}
                  >
                    <Trash2Icon className="size-3.5 text-destructive" />
                  </Button>
                </div>
              ),
            )}
          </div>
        ) : (
          <p className="text-muted-foreground text-sm">{t("rule.empty")}</p>
        )}
      </div>
    </section>
  );
}
