import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The review queue is one task's candidates: a late answer for the previous
// selection used to render task A's entries under task B's label, where the
// bulk promote button would then hit the wrong task.
const messages: Record<string, string> = {
  "review.label": "Review",
  "review.taskAria": "Review task",
  "review.pickTask": "Review a task",
  "review.off": "All entries",
  "review.hint": "Reviewing task #{task}",
  "review.empty": "This task has no candidates left to review.",
  "review.failed": "Could not load the review queue: {msg}",
  "review.outcomeColumn": "Outcome",
  "review.redactionsColumn": "Redactions",
  "review.duplicateColumn": "Likely duplicate",
  "review.selectEntry": "Select entry #{id}",
  "review.intent": "intent #{id}",
  "review.redactions": "{count} identifiers",
  "review.noRedactions": "none",
  "review.duplicate": "similar to: {title}",
  "review.outcome.finding": "finding",
  "review.outcome.fact": "fact",
  "review.outcome.none": "no result",
  "review.outcome.unknown": "unknown",
  "column.id": "ID",
  "column.title": "Entry",
  "bulk.selectAll": "Select every row on this page",
  empty: "No knowledge entries yet.",
};

function translate(key: string, values?: Record<string, unknown>): string {
  const template = messages[key] ?? key;
  return template.replace(/\{(\w+)\}/g, (_, name: string) => String(values?.[name] ?? `{${name}}`));
}

vi.mock("next-intl", () => ({ useTranslations: () => translate }));
vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));

const h = vi.hoisted(() => ({
  knowledgeList: vi.fn(),
  knowledgeStats: vi.fn(),
  knowledgeReview: vi.fn(),
  knowledgeUsage: vi.fn(),
  bulkKnowledge: vi.fn(),
}));
vi.mock("@/lib/api", () => ({ api: h }));

import { KnowledgePane } from "@/app/(main)/system/memory/_components/knowledge-pane";
import type { KnowledgeReview, Task } from "@/lib/types";

// Radix Select needs these DOM APIs, which jsdom does not implement.
class ResizeObserverStub {
  observe() {
    /* nothing to observe in jsdom */
  }
  unobserve() {
    /* nothing to unobserve in jsdom */
  }
  disconnect() {
    /* nothing to disconnect in jsdom */
  }
}
globalThis.ResizeObserver ??= ResizeObserverStub as unknown as typeof ResizeObserver;
Element.prototype.scrollIntoView ??= () => {
  /* jsdom does not scroll */
};
Element.prototype.hasPointerCapture ??= () => false;
Element.prototype.setPointerCapture ??= () => {
  /* capture is a no-op in jsdom */
};
Element.prototype.releasePointerCapture ??= () => {
  /* capture is a no-op in jsdom */
};

function task(id: string): Task {
  return { id, description: `task ${id}`, goal: "goal", status: "done", created_at: "2026-01-01T00:00:00Z" };
}

function reviewFor(id: number, title: string): KnowledgeReview {
  return {
    total: 1,
    items: [
      {
        entry: {
          id,
          scope: "task",
          task_id: 1,
          kind: "technique",
          title,
          body: "body",
          tags: [],
          status: "candidate",
          source: "agent",
          origin_task_id: 1,
          origin_intent_id: 0,
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        },
        origin_intent_id: 0,
        origin_outcome: "none",
        redactions: 0,
        nearest_adopted: null,
      },
    ],
  };
}

async function pickReviewTask(name: string) {
  // Radix opens on Enter and selects on click without a preceding pointerdown.
  fireEvent.keyDown(screen.getByRole("combobox", { name: "Review task" }), { key: "Enter" });
  fireEvent.click(await screen.findByRole("option", { name }));
}

beforeEach(() => {
  h.knowledgeList.mockResolvedValue({ entries: [], total: 0, count: 0, relaxed: false, limit: 50, offset: 0 });
  h.knowledgeStats.mockResolvedValue({ total: 0, by_scope: {}, by_status: {}, by_kind: {}, by_source: {} });
  h.knowledgeUsage.mockResolvedValue({ total: 0, items: [] });
  h.bulkKnowledge.mockResolvedValue({ results: [] });
  h.knowledgeReview.mockReset();
  window.history.replaceState({}, "", "/system/memory");
});

afterEach(cleanup);

describe("KnowledgePane review queue", () => {
  it("ignores a slow answer for the previous task", async () => {
    const resolvers: Array<(review: KnowledgeReview) => void> = [];
    h.knowledgeReview.mockImplementation(() => {
      const { promise, resolve } = Promise.withResolvers<KnowledgeReview>();
      resolvers.push(resolve);
      return promise;
    });

    render(<KnowledgePane tasks={[task("7"), task("9")]} companies={[]} />);

    await pickReviewTask("task 7");
    await waitFor(() => expect(h.knowledgeReview).toHaveBeenCalledWith("7"));

    await pickReviewTask("task 9");
    await waitFor(() => expect(h.knowledgeReview).toHaveBeenCalledWith("9"));

    // Task 9 answers first, then task 7's older request lands late.
    resolvers[1](reviewFor(91, "task 9 candidate"));
    expect(await screen.findByText("task 9 candidate")).toBeInTheDocument();
    resolvers[0](reviewFor(71, "task 7 candidate"));

    await waitFor(() => expect(screen.queryByText("task 7 candidate")).toBeNull());
    expect(screen.getByText("task 9 candidate")).toBeInTheDocument();
  });

  it("clears the previous task's rows as soon as the selection changes", async () => {
    h.knowledgeReview.mockResolvedValueOnce(reviewFor(71, "task 7 candidate"));
    // The second task's queue never answers, so only the clearing can empty the table.
    const { promise } = Promise.withResolvers<KnowledgeReview>();
    h.knowledgeReview.mockImplementationOnce(() => promise);

    render(<KnowledgePane tasks={[task("7"), task("9")]} companies={[]} />);

    await pickReviewTask("task 7");
    expect(await screen.findByText("task 7 candidate")).toBeInTheDocument();

    await pickReviewTask("task 9");
    await waitFor(() => expect(screen.queryByText("task 7 candidate")).toBeNull());
  });

  it("says the load failed instead of claiming the queue is empty", async () => {
    h.knowledgeReview.mockRejectedValue(new Error("boom"));

    render(<KnowledgePane tasks={[task("7")]} companies={[]} />);

    await pickReviewTask("task 7");
    expect(await screen.findByText("Could not load the review queue: boom")).toBeInTheDocument();
    expect(screen.queryByText("This task has no candidates left to review.")).toBeNull();
  });

  it("hides the list filters while a review task is selected", async () => {
    h.knowledgeReview.mockResolvedValue(reviewFor(71, "task 7 candidate"));

    render(<KnowledgePane tasks={[task("7")]} companies={[]} />);
    expect(screen.getByPlaceholderText("filter.search")).toBeInTheDocument();

    await pickReviewTask("task 7");
    expect(screen.queryByPlaceholderText("filter.search")).toBeNull();
  });
});
