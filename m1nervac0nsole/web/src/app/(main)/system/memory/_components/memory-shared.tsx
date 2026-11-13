"use client";

import { Loader2Icon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { getDateLocale } from "@/i18n/datetime";
import type { BulkKnowledgeResult, KnowledgeUsage, KnowledgeUsageSurface } from "@/lib/types";
import { cn } from "@/lib/utils";

// RelaxedNotice is the "no exact match" banner. The list endpoint widens the
// query (ORs its terms) when nothing matched exactly and flags that in
// `relaxed`; showing those rows without saying so would present a widened set
// as the filter's answer.
export function RelaxedNotice({ relaxed }: { relaxed: boolean }) {
  const t = useTranslations("memoryPage");
  if (!relaxed) return null;
  return (
    <div data-testid="relaxed-notice" className="border border-warning/40 bg-warning/10 px-3 py-2 text-warning text-xs">
      {t("relaxed")}
    </div>
  );
}

// BulkResults renders one line per id the bulk endpoint answered, so a partial
// failure is visible instead of being flattened into one error toast.
export function BulkResults({ results }: { results: BulkKnowledgeResult[] }) {
  const t = useTranslations("memoryPage");
  const failed = results.filter((r) => !r.ok).length;
  return (
    <div data-testid="bulk-results" className="space-y-2">
      <p className="font-medium text-xs">
        {failed === 0
          ? t("bulk.allOk", { count: results.length })
          : t("bulk.partial", { ok: results.length - failed, failed })}
      </p>
      <ul className="max-h-56 space-y-1 overflow-auto text-xs">
        {results.map((r) => (
          <li key={r.id} className="flex items-start gap-2">
            <span className="w-10 shrink-0 font-mono text-muted-foreground tabular-nums">#{r.id}</span>
            <span className={r.ok ? "text-success" : "text-destructive"}>{r.ok ? t("bulk.ok") : t("bulk.fail")}</span>
            {!r.ok && r.error && <span className="min-w-0 flex-1 break-words text-muted-foreground">{r.error}</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}

// UsageCell shows injection hits and the last time the entry reached a prompt.
// The backend only serves usage per entry, so the count is loaded on demand
// rather than one request per row of the page.
export function UsageCell({
  usage,
  loading,
  onLoad,
}: {
  usage?: KnowledgeUsage;
  loading: boolean;
  onLoad: () => void;
}) {
  const t = useTranslations("memoryPage");
  if (loading) return <Loader2Icon className="size-3.5 animate-spin text-muted-foreground" />;
  if (!usage) {
    return (
      <Button size="sm" variant="ghost" className="h-6 px-1.5 text-xs" onClick={onLoad} title={t("usage.loadHint")}>
        {t("usage.load")}
      </Button>
    );
  }
  if (usage.hits === 0) return <span className="text-muted-foreground text-xs">{t("usage.never")}</span>;
  return (
    <span className="flex flex-col text-xs tabular-nums" title={usage.last_used || undefined}>
      <span>{t("usage.hits", { count: usage.hits })}</span>
      <span className="text-[10px] text-muted-foreground">{fmtTime(usage.last_used, "-")}</span>
    </span>
  );
}

function fmtTime(ts: string, fallback: string): string {
  if (!ts) return fallback;
  return new Date(ts).toLocaleString(getDateLocale(), {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

const SURFACE_KEYS: Record<KnowledgeUsageSurface, string> = {
  task_start: "usage.surface.task_start",
  round: "usage.surface.round",
  recall: "usage.surface.recall",
  chat: "usage.surface.chat",
};

export function surfaceLabel(translate: (key: string) => string, surface: KnowledgeUsageSurface): string {
  const key = SURFACE_KEYS[surface];
  return key ? translate(key) : surface;
}

// StatusBadge keeps the three lifecycle states visually distinct: a candidate
// still waits for an operator, adopted is live, retired is out of injection.
export function StatusBadge({ status }: { status: string }) {
  const tone =
    status === "adopted"
      ? "border-success/40 bg-success/10 text-success"
      : status === "retired"
        ? "border-border text-muted-foreground"
        : "border-warning/40 bg-warning/10 text-warning";
  return (
    <Badge variant="outline" className={cn("px-1.5 py-0 text-[10px]", tone)}>
      {status}
    </Badge>
  );
}

// splitTags accepts the comma/space separated tag input and drops empties.
export function splitTags(raw: string): string[] {
  return raw
    .split(/[,\n]/)
    .map((s) => s.trim())
    .filter(Boolean);
}
