// Centralised status → color semantics, reused across the whole app.
// Spec §8.3: intent / coverage / task / severity each have a consistent color set.
// User-facing labels live in the "status" message namespace (ko/zh); the maps
// here only carry the color tone, keyed by the same status value.

export type Tone = "neutral" | "blue" | "green" | "amber" | "red" | "rose" | "violet" | "slate";

// Tones map onto the console's semantic tokens so severity and run state stay
// readable on the black surface without a decorative palette.
export const toneClasses: Record<Tone, string> = {
  neutral: "bg-muted text-muted-foreground border-transparent",
  blue: "bg-info/15 text-info border-info/25",
  green: "bg-success/15 text-success border-success/25",
  amber: "bg-warning/15 text-warning border-warning/25",
  red: "bg-destructive/15 text-destructive border-destructive/25",
  // rose is used for "critical" — a solid, high-emphasis fill, visibly stronger than the soft destructive outline used for "high risk."
  rose: "bg-destructive text-destructive-foreground border-destructive",
  violet: "bg-primary/10 text-primary border-primary/30",
  slate: "border-border text-muted-foreground",
};

export const toneDot: Record<Tone, string> = {
  neutral: "bg-muted-foreground",
  blue: "bg-info",
  green: "bg-success",
  amber: "bg-warning",
  red: "bg-destructive",
  rose: "bg-destructive-foreground",
  violet: "bg-primary",
  slate: "bg-muted-foreground/60",
};

interface StatusMeta {
  tone: Tone;
}

const intent: Record<string, StatusMeta> = {
  open: { tone: "slate" },
  running: { tone: "blue" },
  paused: { tone: "amber" },
  done: { tone: "green" },
  // blocked = retries exhausted due to model/API/network failures; this intent was essentially never truly probed (not a target interception).
  blocked: { tone: "red" },
  // exhausted = the step/time budget was reached and the run was cut off midway, so only partial results were written back (not that the direction was fully explored).
  exhausted: { tone: "violet" },
  // stopped = legacy soft-deleted status (retained for historical data).
  stopped: { tone: "slate" },
  // deleted = the user soft-deleted this intent (the node and its lineage are kept; the deletion reason is in the delete_reason field).
  deleted: { tone: "slate" },
};

const task: Record<string, StatusMeta> = {
  created: { tone: "slate" },
  queued: { tone: "amber" },
  running: { tone: "blue" },
  paused: { tone: "amber" },
  // needs_operator = the planner stopped because only a human can unblock it
  // (an absent target, a missing credential). Recoverable, so not red.
  needs_operator: { tone: "violet" },
  done: { tone: "green" },
  failed: { tone: "red" },
  timeout: { tone: "amber" },
};

const severity: Record<string, StatusMeta> = {
  critical: { tone: "rose" },
  high: { tone: "red" },
  medium: { tone: "amber" },
  low: { tone: "slate" },
};

const finding: Record<string, StatusMeta> = {
  pending: { tone: "amber" },
  in_progress: { tone: "blue" },
  confirmed: { tone: "red" },
  resolved: { tone: "green" },
  fixed: { tone: "green" },
  false_positive: { tone: "slate" },
  ignored: { tone: "neutral" },
  duplicate: { tone: "neutral" },
  risk_accepted: { tone: "violet" },
};

const engine: Record<string, StatusMeta> = {
  exploring: { tone: "blue" },
  paused: { tone: "amber" },
  stalled: { tone: "red" },
  idle: { tone: "neutral" },
};

const goal: Record<string, StatusMeta> = {
  open: { tone: "blue" },
  met: { tone: "green" },
  abandoned: { tone: "slate" },
};

const audit: Record<string, StatusMeta> = {
  allow: { tone: "green" },
  block: { tone: "red" },
};

const node: Record<string, StatusMeta> = {
  observed: { tone: "slate" },
  confirmed: { tone: "green" },
  tombstoned: { tone: "neutral" },
};

// Push delivery status. sending uses blue rather than amber: it does not mean "something is wrong,"
// Rather, it means "already claimed and currently being sent," which must be distinguishable from the waiting semantics of pending.
const delivery: Record<string, StatusMeta> = {
  pending: { tone: "amber" },
  sending: { tone: "blue" },
  sent: { tone: "green" },
  failed: { tone: "red" },
  skipped: { tone: "neutral" },
};

const maps = {
  intent,
  task,
  severity,
  finding,
  engine,
  goal,
  audit,
  node,
  delivery,
} as const;

export type StatusDomain = keyof typeof maps;

export function statusMeta(domain: StatusDomain, key: string): StatusMeta {
  return maps[domain][key] ?? { tone: "neutral" };
}
