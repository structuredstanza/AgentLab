"use client";

import * as React from "react";

import { useTranslations } from "next-intl";

import { CuratorChat } from "@/components/curator-chat";
import { api } from "@/lib/api";
import type { PlanDraft } from "@/lib/types";

import { PlanProposalGraph } from "./plan-proposal-graph";
import { PlanProposalPreview } from "./plan-proposal-preview";

// The drafting assistant is a normal chat agent; it can only propose, because
// applying a plan is the operator's decision on this page. It runs in the shared
// chat pane with a task binding: the drafter's tools take the task from the
// conversation, so a wrong guess cannot store a draft against another engagement.
const DRAFTER_AGENT = "drafter";

export function PlanTab({ taskId }: { taskId: string }) {
  const t = useTranslations("taskDetail.plan");
  const [drafts, setDrafts] = React.useState<PlanDraft[] | null>(null);

  const load = React.useCallback(() => {
    api
      .planDrafts(taskId)
      .then(setDrafts)
      .catch(() => setDrafts([]));
  }, [taskId]);

  // The draft appears when the drafter's tool runs, which the chat stream does
  // not report, so poll like the intercept badge does.
  React.useEffect(() => {
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, [load]);

  // Prefer the pending draft; otherwise keep showing the last applied one so
  // the node count it created stays visible after a reload.
  const draft = drafts?.find((d) => d.status === "draft") ?? drafts?.find((d) => d.status === "applied") ?? null;

  let panel = <p className="text-muted-foreground text-xs">{t("noDraft")}</p>;
  if (drafts === null) {
    panel = <p className="text-muted-foreground text-xs">{t("loading")}</p>;
  } else if (draft) {
    panel = (
      <div className="flex flex-col gap-3">
        <PlanProposalGraph draft={draft} />
        <PlanProposalPreview
          taskId={taskId}
          draft={draft}
          onApplied={(updated) =>
            setDrafts((list) => (list ?? []).map((item) => (item.id === updated.id ? updated : item)))
          }
          onDiscarded={load}
        />
      </div>
    );
  }

  return (
    <div className="grid min-h-0 gap-4 lg:grid-cols-2">
      <div className="flex h-[30rem] min-h-0 flex-col border">
        <CuratorChat
          agentKey={DRAFTER_AGENT}
          i18n="taskDetail.plan"
          taskId={taskId}
          prefill={{ label: t("scopeEntry"), text: t("scopeStarter") }}
        />
      </div>
      <div className="min-h-0 border p-3">{panel}</div>
    </div>
  );
}
