import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const messages: Record<string, string> = {
  "archiveDialog.memoryWarning":
    "{count, plural, =1 {# unreviewed memory candidate stays with the archived task and cannot be promoted until it is restored.} other {# unreviewed memory candidates stay with the archived task and cannot be promoted until it is restored.}}",
  "archiveDialog.memoryReview": "Review them",
  "deleteDialog.memoryWarning":
    "{count, plural, =1 {# unreviewed memory candidate will be permanently deleted with it.} other {# unreviewed memory candidates will be permanently deleted with it.}}",
};

// Renders the ICU plural forms the catalog uses, so a count of 1 is checked
// against the singular an operator actually sees.
function translate(key: string, values?: Record<string, unknown>): string {
  const template = messages[key] ?? key;
  const plural = template.match(/^\{(\w+), plural, =1 \{(.*?)\} other \{(.*?)\}\}$/);
  if (plural) {
    const count = values?.[plural[1]];
    return (count === 1 ? plural[2] : plural[3]).replace(/#/g, String(count));
  }
  return template.replace(/\{(\w+)\}/g, (_, name: string) => String(values?.[name] ?? `{${name}}`));
}

vi.mock("next-intl", () => ({ useTranslations: () => translate }));

const mocks = vi.hoisted(() => ({ knowledgeReviewCounts: vi.fn() }));
vi.mock("@/lib/api", () => ({ api: { knowledgeReviewCounts: mocks.knowledgeReviewCounts } }));

import { MemoryCandidatesWarning } from "@/components/memory-candidates-warning";

afterEach(() => {
  cleanup();
  mocks.knowledgeReviewCounts.mockReset();
});

describe("MemoryCandidatesWarning", () => {
  it("says an archive keeps the candidates and links a single task's queue", async () => {
    mocks.knowledgeReviewCounts.mockResolvedValue({ "7": 3 });
    render(<MemoryCandidatesWarning taskIds={["7"]} mode="archive" />);
    const warning = await screen.findByTestId("memory-candidates-warning");
    expect(warning).toHaveTextContent(
      "3 unreviewed memory candidates stay with the archived task and cannot be promoted until it is restored.",
    );
    expect(warning.querySelector("a")).toHaveAttribute("href", "/system/memory?review_task=7");
  });

  it("says a delete destroys the candidates and offers no review link", async () => {
    mocks.knowledgeReviewCounts.mockResolvedValue({ "7": 1 });
    render(<MemoryCandidatesWarning taskIds={["7"]} mode="delete" />);
    const warning = await screen.findByTestId("memory-candidates-warning");
    expect(warning).toHaveTextContent("1 unreviewed memory candidate will be permanently deleted with it.");
    expect(warning.querySelector("a")).toBeNull();
  });

  it("sums a multi-task selection without linking one task's queue", async () => {
    mocks.knowledgeReviewCounts.mockResolvedValue({ "7": 3, "9": 3 });
    render(<MemoryCandidatesWarning taskIds={["7", "9"]} mode="archive" />);
    const warning = await screen.findByTestId("memory-candidates-warning");
    expect(warning).toHaveTextContent("6 unreviewed memory candidates");
    expect(warning.querySelector("a")).toBeNull();
  });

  it("drops the previous selection's count while the new one loads", async () => {
    const resolvers: Array<(counts: Record<string, number>) => void> = [];
    mocks.knowledgeReviewCounts.mockImplementation(() => {
      const { promise, resolve } = Promise.withResolvers<Record<string, number>>();
      resolvers.push(resolve);
      return promise;
    });
    const { rerender } = render(<MemoryCandidatesWarning taskIds={["7"]} mode="archive" />);
    resolvers[0]({ "7": 3 });
    expect(await screen.findByTestId("memory-candidates-warning")).toHaveTextContent("3 unreviewed memory candidates");

    rerender(<MemoryCandidatesWarning taskIds={["9"]} mode="archive" />);
    await waitFor(() => expect(screen.queryByTestId("memory-candidates-warning")).toBeNull());

    resolvers[1]({ "9": 1 });
    expect(await screen.findByTestId("memory-candidates-warning")).toHaveTextContent(
      "1 unreviewed memory candidate stays",
    );
  });

  it("stays silent when the task has no unreviewed candidates", async () => {
    mocks.knowledgeReviewCounts.mockResolvedValue({});
    render(<MemoryCandidatesWarning taskIds={["7"]} mode="archive" />);
    await waitFor(() => expect(mocks.knowledgeReviewCounts).toHaveBeenCalled());
    expect(screen.queryByTestId("memory-candidates-warning")).toBeNull();
  });

  it("does not block the action when the fetch fails", async () => {
    mocks.knowledgeReviewCounts.mockRejectedValue(new Error("boom"));
    render(<MemoryCandidatesWarning taskIds={["7"]} mode="delete" />);
    await waitFor(() => expect(mocks.knowledgeReviewCounts).toHaveBeenCalled());
    expect(screen.queryByTestId("memory-candidates-warning")).toBeNull();
  });
});
