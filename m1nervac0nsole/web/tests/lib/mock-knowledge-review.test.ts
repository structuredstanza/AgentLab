import { describe, expect, it } from "vitest";

import { mockHandle } from "@/lib/mock/handler";
import type { KnowledgeReview } from "@/lib/types";

// The demo build has no database, so the review queue and its counts are
// fixtures: without these routes the feature is invisible in mock mode.
describe("mock knowledge review routes", () => {
  it("serves the finished demo task's candidates", async () => {
    const review = await mockHandle<KnowledgeReview>("GET", "/knowledge/review?task_id=t-vpn-edge");
    expect(review.items).toHaveLength(2);
    expect(review.total).toBe(2);
    expect(review.items[0].entry.status).toBe("candidate");
  });

  it("counts the same candidates for the tasks list", async () => {
    const { counts } = await mockHandle<{ counts: Record<string, number> }>("GET", "/knowledge/review/counts");
    expect(counts["t-vpn-edge"]).toBe(2);
  });

  it("answers an empty queue for a task with no candidates", async () => {
    const review = await mockHandle<KnowledgeReview>("GET", "/knowledge/review?task_id=t-acme-web");
    expect(review.items).toEqual([]);
  });
});
