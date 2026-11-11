import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

// Copy under test is the page's own strings, so the translator here substitutes
// the {name} placeholders instead of returning the key.
const messages: Record<string, string> = {
  relaxed: "No exact match - showing related entries.",
  "bulk.allOk": "{count} entries updated.",
  "bulk.partial": "{ok} updated, {failed} failed.",
  "bulk.ok": "ok",
  "bulk.fail": "failed",
  "graduate.title": "Graduate reflection",
  "graduate.step1": "Step 1: this writes a task-scoped candidate for task #{task}.",
  "graduate.step2": "Step 2: nothing is shared yet. The candidate stays inside task #{task} until you promote it.",
  "graduate.confirm": "Create candidate",
  "graduate.created": "Candidate #{id} created for this task.",
  "detail.kind": "Kind",
  "detail.title": "Title",
  "detail.tags": "Tags",
  "detail.tagsPlaceholder": "comma separated tags",
  redactions: "Saved. {count} identifiers were generalised.",
  close: "Close",
};

function translate(key: string, values?: Record<string, unknown>): string {
  const template = messages[key] ?? key;
  return template.replace(/\{(\w+)\}/g, (_, name: string) => String(values?.[name] ?? `{${name}}`));
}

vi.mock("next-intl", () => ({ useTranslations: () => translate }));
vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));
vi.mock("@/lib/api", () => ({
  api: {
    graduateReflection: vi.fn(async () => ({
      entry: { id: 41, title: "Timing oracle", body: "b", tags: [], scope: "task", kind: "technique" },
      redactions: 2,
    })),
  },
}));

import { GraduateDialog } from "@/app/(main)/system/memory/_components/graduate-dialog";
import { BulkResults, RelaxedNotice } from "@/app/(main)/system/memory/_components/memory-shared";
import type { Reflection } from "@/lib/types";

const reflection: Reflection = {
  id: 7,
  task_id: 3,
  kind: "learning",
  source: "worker",
  summary: "Timing oracle on the login endpoint",
  detail: "A 40ms delta separates a valid user from an invalid one.",
  created_at: "2026-01-01T00:00:00Z",
};

afterEach(cleanup);

describe("RelaxedNotice", () => {
  it("says the rows are a widened set when the backend relaxed the query", () => {
    render(<RelaxedNotice relaxed />);
    expect(screen.getByTestId("relaxed-notice")).toHaveTextContent("No exact match");
  });

  it("renders nothing when the query matched exactly", () => {
    render(<RelaxedNotice relaxed={false} />);
    expect(screen.queryByTestId("relaxed-notice")).toBeNull();
  });
});

describe("BulkResults", () => {
  it("names the failures and their messages instead of hiding a partial result", () => {
    render(
      <BulkResults
        results={[
          { id: 1, ok: true },
          { id: 2, ok: false, error: "a task-scoped entry must be promoted, not adopted" },
        ]}
      />,
    );
    const panel = screen.getByTestId("bulk-results");
    expect(panel).toHaveTextContent("1 updated, 1 failed.");
    expect(panel).toHaveTextContent("a task-scoped entry must be promoted, not adopted");
    expect(panel.querySelectorAll("li")).toHaveLength(2);
  });

  it("reports a fully successful batch as such", () => {
    render(
      <BulkResults
        results={[
          { id: 1, ok: true },
          { id: 2, ok: true },
        ]}
      />,
    );
    expect(screen.getByTestId("bulk-results")).toHaveTextContent("2 entries updated.");
  });
});

describe("GraduateDialog", () => {
  it("states that graduating only creates a candidate and promotion is still required", async () => {
    const onGraduated = vi.fn();
    render(<GraduateDialog reflection={reflection} open onOpenChange={vi.fn()} onGraduated={onGraduated} />);

    expect(screen.getByText(/writes a task-scoped candidate for task #3/)).toBeInTheDocument();
    expect(screen.getByText(/stays inside task #3 until you promote it/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Create candidate/ }));

    await waitFor(() => expect(onGraduated).toHaveBeenCalled());
    const panel = await screen.findByTestId("graduate-result");
    expect(panel).toHaveTextContent("Candidate #41 created for this task.");
    expect(panel).toHaveTextContent(/until you promote it/);
    expect(panel).toHaveTextContent("Saved. 2 identifiers were generalised.");
  });
});
