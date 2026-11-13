"use client";

import { useTranslations } from "next-intl";

import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { KnowledgeEntry, KnowledgeReview, KnowledgeReviewOutcome } from "@/lib/types";

const OUTCOME_VARIANT: Record<KnowledgeReviewOutcome, "default" | "secondary" | "outline"> = {
  finding: "default",
  fact: "secondary",
  none: "outline",
  unknown: "outline",
};

// KnowledgeReviewList is the promotion queue for one task: its candidates with
// the evidence needed to promote or drop each one. Selection and promotion stay
// in KnowledgePane, so this view adds no second promotion flow.
export function KnowledgeReviewList({
  review,
  loading,
  selected,
  onToggle,
  onToggleAll,
  onOpen,
}: {
  review: KnowledgeReview | null;
  loading: boolean;
  selected: Set<number>;
  onToggle: (id: number) => void;
  onToggleAll: (ids: number[], on: boolean) => void;
  onOpen: (entry: KnowledgeEntry) => void;
}) {
  const t = useTranslations("memoryPage");
  if (loading && !review) {
    return (
      <div className="flex h-40 items-center justify-center">
        <Spinner />
      </div>
    );
  }
  if (!review || review.items.length === 0) {
    return <p className="p-8 text-center text-muted-foreground text-sm">{t("review.empty")}</p>;
  }
  const ids = review.items.map((item) => item.entry.id);
  const allOn = ids.every((id) => selected.has(id));
  return (
    <Table className="min-w-[56rem] table-fixed" data-testid="knowledge-review">
      <TableHeader>
        <TableRow>
          <TableHead className="w-8">
            <Checkbox
              checked={allOn}
              onCheckedChange={(on) => onToggleAll(ids, on === true)}
              aria-label={t("bulk.selectAll")}
            />
          </TableHead>
          <TableHead className="w-14">{t("column.id")}</TableHead>
          <TableHead>{t("column.title")}</TableHead>
          <TableHead className="w-28">{t("review.outcomeColumn")}</TableHead>
          <TableHead className="w-28">{t("review.redactionsColumn")}</TableHead>
          <TableHead className="w-56">{t("review.duplicateColumn")}</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {review.items.map((item) => (
          <TableRow key={item.entry.id} data-state={selected.has(item.entry.id) ? "selected" : undefined}>
            <TableCell>
              <Checkbox
                checked={selected.has(item.entry.id)}
                onCheckedChange={() => onToggle(item.entry.id)}
                aria-label={t("review.selectEntry", { id: item.entry.id })}
              />
            </TableCell>
            <TableCell className="font-mono text-[11px] text-muted-foreground tabular-nums">#{item.entry.id}</TableCell>
            <TableCell className="overflow-hidden">
              <button
                type="button"
                className="flex w-full min-w-0 flex-col items-start gap-0.5 text-left"
                onClick={() => onOpen(item.entry)}
              >
                <span className="max-w-full truncate font-medium text-xs hover:underline">{item.entry.title}</span>
                <span className="flex max-w-full flex-wrap items-center gap-1">
                  <Badge variant="outline" className="px-1 py-0 text-[10px]">
                    {item.entry.kind}
                  </Badge>
                  {item.origin_intent_id > 0 ? (
                    <span className="text-[10px] text-muted-foreground">
                      {t("review.intent", { id: item.origin_intent_id })}
                    </span>
                  ) : null}
                </span>
              </button>
            </TableCell>
            <TableCell>
              <Badge variant={OUTCOME_VARIANT[item.origin_outcome]} className="px-1.5 py-0 text-[10px]">
                {t(`review.outcome.${item.origin_outcome}`)}
              </Badge>
            </TableCell>
            <TableCell className="text-[11px] text-muted-foreground tabular-nums">
              {item.redactions > 0 ? t("review.redactions", { count: item.redactions }) : t("review.noRedactions")}
            </TableCell>
            <TableCell className="overflow-hidden">
              {item.nearest_adopted ? (
                <span className="block truncate text-[11px]" title={item.nearest_adopted.title}>
                  {t("review.duplicate", { title: item.nearest_adopted.title })}
                </span>
              ) : (
                <span className="text-[11px] text-muted-foreground">-</span>
              )}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
