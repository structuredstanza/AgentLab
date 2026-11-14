import "@testing-library/jest-dom/vitest";

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { Edge, PlanDraft, PlanProposal, TaskNode } from "@/lib/types";

// Copy under test is the preview's own strings, so the translator returns the
// message instead of the key.
const messages: Record<string, string> = {
  "preview.graph": "Plan graph",
  "preview.statusDraft": "Awaiting your decision",
  "preview.statusApplied": "Applied",
};

function translate(key: string): string {
  return messages[key] ?? key;
}

vi.mock("next-intl", () => ({ useTranslations: () => translate }));

// jsdom has no layout engine, so the canvas is replaced by the nodes it was
// handed; the preview's contract is exactly that hand-off.
vi.mock("@/components/exploration-graph", () => ({
  ExplorationGraph: ({ nodes, edges, readOnly }: { nodes: TaskNode[]; edges: Edge[]; readOnly?: boolean }) => (
    <div data-readonly={String(readOnly)} data-testid="graph">
      {nodes.map((node) => (
        <span key={node.id} data-kind={node.type} data-testid="graph-node">
          {node.id}
        </span>
      ))}
      {edges.map((edge) => (
        <span key={`${edge.src}-${edge.dst}`} data-dst={edge.dst} data-src={edge.src} data-testid="graph-edge" />
      ))}
    </div>
  ),
}));

import { PlanProposalGraph, proposalGraph } from "@/app/(main)/function/tasks/detail/_tabs/plan-proposal-graph";

const proposal: PlanProposal = {
  summary: "Cover the shop and admin surfaces first.",
  goals: [
    { ref: "g1", text: "Reach the order database through search.", vulnclass: "sqli" },
    { ref: "g2", text: "Show an order belonging to another customer.", vulnclass: "idor" },
  ],
  intents: [
    { ref: "i1", summary: "Replay the search request with time-based payloads.", goal: "g1", asset_ids: [1, 2] },
    { ref: "i2", summary: "Walk the order id space.", goal: "g2", depends_on: ["i1"] },
  ],
  hints: [{ text: "Stay under 5 requests per second.", rule: true }],
  scope: [],
};

const draft: PlanDraft = {
  id: 7,
  task_id: 1,
  status: "draft",
  summary: proposal.summary,
  proposal,
  created_at: "2026-11-12T09:00:00Z",
};

function payload(node: TaskNode | undefined): Record<string, unknown> {
  return JSON.parse(node?.payload ?? "{}") as Record<string, unknown>;
}

describe("proposalGraph", () => {
  it("maps every goal and intent to a unique node", () => {
    const { nodes } = proposalGraph(proposal);

    expect(nodes.map((node) => node.id)).toEqual(["g:g1", "g:g2", "i:i1", "i:i2"]);
    expect(new Set(nodes.map((node) => node.id)).size).toBe(nodes.length);
    expect(nodes.find((node) => node.id === "g:g1")?.type).toBe("goal");
    expect(nodes.find((node) => node.id === "i:i1")?.type).toBe("intent");
    expect(payload(nodes.find((node) => node.id === "g:g1")).text).toContain("order database");
  });

  it("labels an intent with its summary and its goal ref", () => {
    const { nodes } = proposalGraph(proposal);

    const label = payload(nodes.find((node) => node.id === "i:i2")).summary as string;
    expect(label).toContain("Walk the order id space.");
    expect(label).toContain("goal g2");
  });

  it("draws goal edges and depends_on edges", () => {
    const { edges } = proposalGraph(proposal);

    expect(edges).toContainEqual({ src: "g:g1", dst: "i:i1", rel: "spawns" });
    expect(edges).toContainEqual({ src: "g:g2", dst: "i:i2", rel: "spawns" });
    expect(edges).toContainEqual({ src: "i:i1", dst: "i:i2", rel: "spawns" });
    expect(edges).toHaveLength(3);
  });

  it("keeps ids unique when a goal and an intent share a ref", () => {
    const { nodes } = proposalGraph({
      ...proposal,
      goals: [{ ref: "same", text: "A goal." }],
      intents: [{ ref: "same", summary: "An intent.", goal: "same" }],
      hints: [],
    });

    expect(nodes.map((node) => node.id)).toEqual(["g:same", "i:same"]);
  });
});

describe("PlanProposalGraph", () => {
  afterEach(cleanup);

  it("renders one node per goal and intent in read-only mode", () => {
    render(<PlanProposalGraph draft={draft} />);

    expect(screen.getByTestId("graph")).toHaveAttribute("data-readonly", "true");
    const nodes = screen.getAllByTestId("graph-node");
    expect(nodes.filter((node) => node.dataset.kind === "goal")).toHaveLength(2);
    expect(nodes.filter((node) => node.dataset.kind === "intent")).toHaveLength(2);
    expect(screen.getAllByTestId("graph-edge")).toHaveLength(3);
  });

  it("marks a pending draft and mutes an applied one", () => {
    const { rerender } = render(<PlanProposalGraph draft={draft} />);
    expect(screen.getByText("Awaiting your decision")).toBeInTheDocument();
    expect(screen.getByTestId("plan-graph-canvas")).not.toHaveClass("opacity-60");

    rerender(<PlanProposalGraph draft={{ ...draft, status: "applied" }} />);
    expect(screen.getByText("Applied")).toBeInTheDocument();
    expect(screen.getByTestId("plan-graph-canvas")).toHaveClass("opacity-60");
  });

  it("renders nothing when the proposal has no goals or intents", () => {
    const { container } = render(
      <PlanProposalGraph draft={{ ...draft, proposal: { ...proposal, goals: [], intents: [], hints: [] } }} />,
    );

    expect(container).toBeEmptyDOMElement();
  });
});
