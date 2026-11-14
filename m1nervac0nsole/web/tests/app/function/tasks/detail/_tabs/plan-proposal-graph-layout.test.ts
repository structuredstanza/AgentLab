import { describe, expect, it } from "vitest";

import { proposalGraph } from "@/app/(main)/function/tasks/detail/_tabs/plan-proposal-graph";
import { computeLayout } from "@/components/exploration-graph";
import type { PlanProposal } from "@/lib/types";

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

// The preview hands nodes/edges to ExplorationGraph, which lays them out with
// this same function; the synthetic graph must never stack at the origin.
describe("proposalGraph layout", () => {
  it("gives every node a distinct layered position", () => {
    const { nodes, edges } = proposalGraph(proposal);

    const positions = computeLayout(nodes, edges);
    expect(positions.size).toBe(nodes.length);

    const points = [...positions.values()];
    expect(new Set(points.map((point) => `${point.x},${point.y}`)).size).toBe(nodes.length);
    expect(points.some((point) => point.x !== 0 || point.y !== 0)).toBe(true);
    expect(points.some((point) => point.x > 0)).toBe(true);
  });
});
