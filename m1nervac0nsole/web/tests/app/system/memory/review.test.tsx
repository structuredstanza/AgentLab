import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

// Copy under test is the pane's own strings, so the translator here substitutes
// the {name} placeholders instead of returning the key.
const messages: Record<string, string> = {
  "column.id": "ID",
  "column.title": "Entry",
  "bulk.selectAll": "Select every row on this page",
  "review.outcomeColumn": "Outcome",
  "review.redactionsColumn": "Redactions",
  "review.duplicateColumn": "Likely duplicate",
  "review.outcome.finding": "finding",
  "review.outcome.fact": "fact",
  "review.outcome.none": "no result",
  "review.outcome.unknown": "unknown",
  "review.selectEntry": "Select entry #{id}",
  "review.intent": "intent #{id}",
  "review.redactions": "{count, plural, =1 {# identifier} other {# identifiers}}",
  "review.noRedactions": "none",
  "review.duplicate": "similar to: {title}",
  "review.empty": "This task has no candidates left to review.",
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

import { KnowledgeReviewList } from "@/app/(main)/system/memory/_components/knowledge-review";
import type { KnowledgeEntry, KnowledgeReview } from "@/lib/types";

function entry(id: number, title: string, kind: KnowledgeEntry["kind"]): KnowledgeEntry {
  return {
    id,
    scope: "task",
    task_id: 3,
    kind,
    title,
    body: "body",
    tags: [],
    status: "candidate",
    source: "agent",
    origin_task_id: 3,
    origin_intent_id: 28,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  };
}

const review: KnowledgeReview = {
  total: 2,
  items: [
    {
      entry: entry(12, "SSRF through the PDF renderer", "technique"),
      origin_intent_id: 28,
      origin_outcome: "finding",
      redactions: 3,
      nearest_adopted: { id: 4, title: "PDF renderer SSRF" },
    },
    {
      entry: entry(13, "msg field consumed the payload", "note"),
      origin_intent_id: 0,
      origin_outcome: "none",
      redactions: 0,
      nearest_adopted: null,
    },
  ],
};

afterEach(cleanup);

describe("KnowledgeReviewList", () => {
  it("shows the origin outcome, the promotion redaction count and the likely duplicate", () => {
    render(
      <KnowledgeReviewList
        review={review}
        loading={false}
        selected={new Set()}
        onToggle={vi.fn()}
        onToggleAll={vi.fn()}
        onOpen={vi.fn()}
      />,
    );
    const table = screen.getByTestId("knowledge-review");
    expect(table).toHaveTextContent("finding");
    expect(table).toHaveTextContent("no result");
    expect(table).toHaveTextContent("3 identifiers");
    expect(table).toHaveTextContent("similar to: PDF renderer SSRF");
    expect(table).toHaveTextContent("intent #28");
    expect(screen.getByRole("checkbox", { name: "Select entry #12" })).toBeInTheDocument();
  });

  it("counts a single redacted identifier in the singular", () => {
    const single: KnowledgeReview = {
      total: 1,
      items: [{ ...review.items[0], redactions: 1 }],
    };
    render(
      <KnowledgeReviewList
        review={single}
        loading={false}
        selected={new Set()}
        onToggle={vi.fn()}
        onToggleAll={vi.fn()}
        onOpen={vi.fn()}
      />,
    );
    // Exact text: "1 identifiers" would otherwise satisfy a substring match.
    expect(screen.getByText("1 identifier")).toBeInTheDocument();
  });

  it("opens the existing knowledge detail instead of a review-only view", () => {
    const onOpen = vi.fn();
    render(
      <KnowledgeReviewList
        review={review}
        loading={false}
        selected={new Set()}
        onToggle={vi.fn()}
        onToggleAll={vi.fn()}
        onOpen={onOpen}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /SSRF through the PDF renderer/ }));
    expect(onOpen).toHaveBeenCalledWith(review.items[0].entry);
  });

  it("says the queue is empty instead of rendering an empty table", () => {
    render(
      <KnowledgeReviewList
        review={{ items: [], total: 0 }}
        loading={false}
        selected={new Set()}
        onToggle={vi.fn()}
        onToggleAll={vi.fn()}
        onOpen={vi.fn()}
      />,
    );
    expect(screen.getByText("This task has no candidates left to review.")).toBeInTheDocument();
    expect(screen.queryByTestId("knowledge-review")).toBeNull();
  });
});
