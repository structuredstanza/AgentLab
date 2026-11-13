"use client";

import * as React from "react";

import Link from "next/link";

import { useTranslations } from "next-intl";

import { api } from "@/lib/api";
import type { Task } from "@/lib/types";

// done/failed/timeout are the statuses the task list treats as finished: no
// worker will write another candidate, so the review count is final.
const TERMINAL_STATUSES: Partial<Record<Task["status"], true>> = { done: true, failed: true, timeout: true };

function reviewHref(taskId: string): string {
  return `/system/memory?review_task=${encodeURIComponent(taskId)}`;
}

// useTaskReviewCounts fetches one task's candidate count once it is terminal.
// A failed fetch yields 0, so the notice simply stays hidden.
export function useTaskReviewCounts(taskId: string, enabled: boolean): number {
  const [count, setCount] = React.useState(0);
  React.useEffect(() => {
    if (!enabled || !taskId) return;
    let live = true;
    api
      .knowledgeReviewCounts()
      .then((counts) => {
        if (live) setCount(counts[taskId] ?? 0);
      })
      .catch(() => {
        /* advisory */
      });
    return () => {
      live = false;
    };
  }, [taskId, enabled]);
  return count;
}

// MemoryReviewBadge is the task-list marker for a finished task whose memory
// candidates still wait for an operator. Counts are fetched once per list, so
// the row only renders the number it is handed.
export function MemoryReviewBadge({ task, count }: { task: Task; count: number }) {
  const t = useTranslations("tasksPage");
  if (count <= 0 || !TERMINAL_STATUSES[task.status]) return null;
  return (
    <Link
      href={reviewHref(task.id)}
      className="shrink-0 text-[11px] text-primary hover:underline"
      title={t("row.memoryReviewHint")}
    >
      {t("row.memoryReview", { count })}
    </Link>
  );
}

// MemoryReviewNotice is the same signal on the task detail header, where there
// is room for a sentence instead of a badge.
export function MemoryReviewNotice({ task, count }: { task: Task; count: number }) {
  const t = useTranslations("tasksPage");
  if (count <= 0 || !TERMINAL_STATUSES[task.status]) return null;
  return (
    <p className="text-[11px] text-muted-foreground">
      {t("row.memoryReviewNotice", { count })}{" "}
      <Link href={reviewHref(task.id)} className="underline">
        {t("row.memoryReviewOpen")}
      </Link>
    </p>
  );
}
