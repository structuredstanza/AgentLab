"use client";

import * as React from "react";

import { useTranslations } from "next-intl";

import { ExplorationGraph } from "@/components/exploration-graph";
import { Badge } from "@/components/ui/badge";
import type { Edge, PlanDraft, PlanProposal, TaskNode } from "@/lib/types";
import { cn } from "@/lib/utils";

// Synthetic node ids are prefixed by kind: a goal and an intent may reuse the
// same ref in a malformed proposal, and the canvas requires unique ids.
const goalNodeID = (ref: string) => `g:${ref}`;
const intentNodeID = (ref: string) => `i:${ref}`;

// proposalGraph maps a draft onto the exploration graph's shapes, so the
// operator reviews the plan on the same canvas the applied nodes will use.
// Nothing here is persisted; hints are left to the list because they carry no
// edge and would only stack isolated cards in the first column.
export function proposalGraph(proposal: PlanProposal): { nodes: TaskNode[]; edges: Edge[] } {
  const nodes: TaskNode[] = [];
  const edges: Edge[] = [];
  const goalRefs = new Set((proposal.goals ?? []).map((g) => g.ref));
  const intentRefs = new Set((proposal.intents ?? []).map((i) => i.ref));
  const linked = new Set<string>();
  const link = (src: string, dst: string) => {
    const key = `${src}\u0000${dst}`;
    if (linked.has(key)) return;
    linked.add(key);
    edges.push({ src, dst, rel: "spawns" });
  };

  for (const goal of proposal.goals ?? []) {
    nodes.push({
      id: goalNodeID(goal.ref),
      type: "goal",
      payload: JSON.stringify({ text: goal.text }),
      priority: 0,
      state: "open",
      origin: "plan",
      ts: "",
    });
  }

  for (const intent of proposal.intents ?? []) {
    // The card renders payload.summary; the goal ref rides along so the
    // operator can see which goal the intent serves without opening it.
    const summary = intent.goal ? `${intent.summary} (goal ${intent.goal})` : intent.summary;
    nodes.push({
      id: intentNodeID(intent.ref),
      type: "intent",
      payload: JSON.stringify({ summary }),
      priority: 5,
      state: "open",
      origin: "plan",
      ts: "",
    });
    if (goalRefs.has(intent.goal)) link(goalNodeID(intent.goal), intentNodeID(intent.ref));
    for (const dep of intent.depends_on ?? []) {
      if (dep !== intent.ref && intentRefs.has(dep)) link(intentNodeID(dep), intentNodeID(intent.ref));
    }
  }

  return { nodes, edges };
}

// PlanProposalGraph previews a draft on the exploration canvas: goals on the
// left, their seed intents to the right, dependency edges between intents.
export function PlanProposalGraph({ draft, className }: { draft: PlanDraft; className?: string }) {
  const t = useTranslations("taskDetail.plan");
  const { nodes, edges } = React.useMemo(() => proposalGraph(draft.proposal), [draft.proposal]);
  if (nodes.length === 0) return null;
  const pending = draft.status === "draft";

  return (
    <section className={cn("flex flex-col gap-2", className)} data-testid="plan-graph">
      <div className="flex items-center gap-2">
        <h3 className="min-w-0 flex-1 truncate font-medium text-sm">{t("preview.graph")}</h3>
        <Badge variant={pending ? "outline" : "secondary"}>
          {pending ? t("preview.statusDraft") : t("preview.statusApplied")}
        </Badge>
      </div>
      <div
        className={cn("h-80 overflow-hidden rounded-lg border", !pending && "opacity-60")}
        data-testid="plan-graph-canvas"
      >
        <ExplorationGraph nodes={nodes} edges={edges} readOnly className="h-full" />
      </div>
    </section>
  );
}
