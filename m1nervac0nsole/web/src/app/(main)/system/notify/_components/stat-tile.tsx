// This file is referenced by client pages, but it is purely presentational/pure functions and does not call useTranslations directly.
// formatBacklog needs i18n unit labels, so the caller injects t into it (precedent: tasks/approval-records).
type Translator = (key: "unit.sec" | "unit.min" | "unit.hour", values: { n: number | string }) => string;

export function StatTile({ label, value, hint, tone }: { label: string; value: string; hint?: string; tone?: string }) {
  const bad = tone === "red";
  return (
    <div className="min-w-0 border-border border-t pt-2">
      <dt className="truncate text-[11px] text-muted-foreground">{label}</dt>
      <dd className={`font-semibold text-xl tabular-nums ${bad ? "text-destructive" : ""}`}>{value}</dd>
      {hint && <dd className={`text-[11px] ${bad ? "text-destructive" : "text-muted-foreground"}`}>{hint}</dd>}
    </div>
  );
}

// formatBacklog renders the backlog in milliseconds at a human-readable magnitude.
export function formatBacklog(ms: number, t: Translator): string {
  if (!ms) return "—";
  if (ms < 60_000) return t("unit.sec", { n: Math.round(ms / 1000) });
  if (ms < 3_600_000) return t("unit.min", { n: Math.round(ms / 60_000) });
  return t("unit.hour", { n: (ms / 3_600_000).toFixed(1) });
}
