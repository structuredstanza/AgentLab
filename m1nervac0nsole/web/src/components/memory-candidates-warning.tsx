"use client";

import * as React from "react";

import Link from "next/link";

import { useTranslations } from "next-intl";

import { api } from "@/lib/api";

// MemoryCandidatesWarning names the unreviewed memory candidates attached to
// the tasks an operator is about to archive or delete. Archiving only strands
// them - promotion from an archived task fails until it is restored - while
// deleting the task destroys them. A failed fetch stays silent: the count is
// advisory and must never block either action.
export function MemoryCandidatesWarning({ taskIds, mode }: { taskIds: string[]; mode: "archive" | "delete" }) {
  const t = useTranslations("tasksPage");
  const [total, setTotal] = React.useState(0);
  const key = taskIds.join(",");

  React.useEffect(() => {
    let live = true;
    // A count from the previous selection must never describe this one.
    setTotal(0);
    api
      .knowledgeReviewCounts()
      .then((counts) => {
        if (!live) return;
        setTotal(
          key
            .split(",")
            .filter(Boolean)
            .reduce((sum, id) => sum + (counts[id] ?? 0), 0),
        );
      })
      .catch(() => {
        /* advisory: a failed count must never block the action */
      });
    return () => {
      live = false;
    };
  }, [key]);

  if (total <= 0) return null;
  const ids = taskIds.filter(Boolean);
  return (
    <p data-testid="memory-candidates-warning" className="text-[11px] text-muted-foreground">
      {mode === "delete"
        ? t("deleteDialog.memoryWarning", { count: total })
        : t("archiveDialog.memoryWarning", { count: total })}
      {/* One task has one queue to link to; a multi-task archive does not. */}
      {mode === "archive" && ids.length === 1 && (
        <>
          {" "}
          <Link href={`/system/memory?review_task=${ids[0]}`} className="underline">
            {t("archiveDialog.memoryReview")}
          </Link>
        </>
      )}
    </p>
  );
}
