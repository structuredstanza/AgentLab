import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const messages: Record<string, string> = {
  "row.memoryReview": "{count} to review",
  "row.memoryReviewHint": "Memory candidates from this task are waiting for review",
  "row.memoryReviewNotice": "{count} memory candidates from this task are waiting for review.",
  "row.memoryReviewOpen": "Review them",
};

function translate(key: string, values?: Record<string, unknown>): string {
  const template = messages[key] ?? key;
  return template.replace(/\{(\w+)\}/g, (_, name: string) => String(values?.[name] ?? `{${name}}`));
}

vi.mock("next-intl", () => ({ useTranslations: () => translate }));

const mocks = vi.hoisted(() => ({ knowledgeReviewCounts: vi.fn() }));
vi.mock("@/lib/api", () => ({ api: { knowledgeReviewCounts: mocks.knowledgeReviewCounts } }));

import { MemoryReviewBadge, MemoryReviewNotice, useTaskReviewCounts } from "@/components/memory-review-badge";
import type { Task } from "@/lib/types";

const doneTask: Task = {
  id: "7",
  description: "internal range",
  goal: "find something",
  status: "done",
  created_at: "2026-01-01T00:00:00Z",
};

function NoticeHarness({ task }: { task: Task }) {
  const count = useTaskReviewCounts(task.id, task.status === "done");
  return <MemoryReviewNotice task={task} count={count} />;
}

afterEach(() => {
  cleanup();
  mocks.knowledgeReviewCounts.mockReset();
});

describe("MemoryReviewBadge", () => {
  it("links a finished task with candidates to its review queue", () => {
    render(<MemoryReviewBadge task={doneTask} count={3} />);
    const link = screen.getByRole("link", { name: "3 to review" });
    expect(link).toHaveAttribute("href", "/system/memory?review_task=7");
  });

  it("stays hidden for a task that is still running", () => {
    render(<MemoryReviewBadge task={{ ...doneTask, status: "running" }} count={3} />);
    expect(screen.queryByRole("link")).toBeNull();
  });

  it("stays hidden when the count is zero", () => {
    render(<MemoryReviewBadge task={doneTask} count={0} />);
    expect(screen.queryByRole("link")).toBeNull();
  });
});

describe("useTaskReviewCounts", () => {
  it("shows the notice for a terminal task with a positive count", async () => {
    mocks.knowledgeReviewCounts.mockResolvedValue({ "7": 2 });
    render(<NoticeHarness task={doneTask} />);
    const notice = await screen.findByText(/2 memory candidates from this task are waiting for review/);
    expect(notice).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Review them" })).toHaveAttribute("href", "/system/memory?review_task=7");
  });

  it("renders nothing when the counts fetch rejects", async () => {
    mocks.knowledgeReviewCounts.mockRejectedValue(new Error("boom"));
    render(<NoticeHarness task={doneTask} />);
    await waitFor(() => expect(mocks.knowledgeReviewCounts).toHaveBeenCalled());
    expect(screen.queryByRole("link")).toBeNull();
  });
});
