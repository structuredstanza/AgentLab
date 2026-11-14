import "@testing-library/jest-dom/vitest";
import * as React from "react";

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Copy under test is the preview's own strings, so the translator substitutes
// the {name} placeholders instead of returning the key.
const messages: Record<string, string> = {
  "preview.title": "Proposal",
  "preview.statusDraft": "Awaiting your decision",
  "preview.statusApplied": "Applied",
  "preview.goals": "Goals",
  "preview.intents": "Seed intents",
  "preview.hints": "Hints",
  "preview.scope": "Scope rules",
  "preview.none": "None",
  "preview.goalRef": "goal {ref}",
  "preview.dependsOn": "after {refs}",
  "preview.assets": "{count} assets",
  "preview.rule": "Rule",
  "preview.include": "Include",
  "preview.exclude": "Exclude",
  "preview.includeWarning": "This widens the task scope",
  "preview.apply": "Apply plan",
  "preview.discard": "Discard",
  "preview.applied": "Plan applied: {count} nodes created",
  "preview.appliedNodes": "Created {count} nodes",
  "preview.applyFailed": "Apply failed: {msg}",
  "preview.discarded": "Draft discarded",
  "preview.discardFailed": "Discard failed: {msg}",
};

function translate(key: string, values?: Record<string, unknown>): string {
  const template = messages[key] ?? key;
  return template.replace(/\{(\w+)\}/g, (_, name: string) => String(values?.[name] ?? `{${name}}`));
}

vi.mock("next-intl", () => ({ useTranslations: () => translate }));
vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));

const mocks = vi.hoisted(() => ({ applyPlanDraft: vi.fn(), discardPlanDraft: vi.fn() }));
vi.mock("@/lib/api", () => ({
  api: { applyPlanDraft: mocks.applyPlanDraft, discardPlanDraft: mocks.discardPlanDraft },
}));

import { PlanProposalPreview } from "@/app/(main)/function/tasks/detail/_tabs/plan-proposal-preview";
import type { PlanDraft } from "@/lib/types";

const pending: PlanDraft = {
  id: 7,
  task_id: 1,
  status: "draft",
  summary: "Cover the shop and admin surfaces first.",
  proposal: {
    summary: "Cover the shop and admin surfaces first.",
    goals: [{ ref: "g1", text: "Reach the order database through search.", vulnclass: "sqli" }],
    intents: [
      { ref: "i1", summary: "Replay the search request with time-based payloads.", goal: "g1", asset_ids: [1, 2] },
      { ref: "i2", summary: "Walk the order id space.", goal: "g1", depends_on: ["i1"] },
    ],
    hints: [
      { text: "Stay under 5 requests per second.", rule: true },
      { text: "The admin back office sits behind a VPN." },
    ],
    scope: [
      { effect: "include", kind: "subdomain", value: "shop.acme.com", note: "Found in JS" },
      { effect: "exclude", kind: "subdomain", value: "status.acme.com" },
    ],
  },
  created_at: "2026-11-12T09:00:00Z",
};

// The tab owns the draft and hands the applied copy back, so the harness does
// the same: the node count must appear without a refetch.
function Harness({ draft }: { draft: PlanDraft }) {
  const [current, setCurrent] = React.useState(draft);
  return <PlanProposalPreview taskId="t-acme-web" draft={current} onApplied={setCurrent} />;
}

beforeEach(() => {
  mocks.applyPlanDraft.mockReset();
  mocks.discardPlanDraft.mockReset();
  mocks.discardPlanDraft.mockResolvedValue({ ok: true });
});

afterEach(cleanup);

describe("PlanProposalPreview", () => {
  it("renders the summary, goals, intents, hints and scope rules", () => {
    render(<PlanProposalPreview taskId="t-acme-web" draft={pending} />);

    expect(screen.getByTestId("plan-summary")).toHaveTextContent("Cover the shop and admin surfaces first.");
    expect(screen.getByTestId("plan-goals")).toHaveTextContent("Reach the order database through search.");
    expect(screen.getByTestId("plan-goals")).toHaveTextContent("sqli");

    const intents = screen.getByTestId("plan-intents");
    expect(intents).toHaveTextContent("Replay the search request with time-based payloads.");
    expect(intents).toHaveTextContent("goal g1");
    expect(intents).toHaveTextContent("after i1");
    expect(intents).toHaveTextContent("2 assets");

    expect(screen.getByTestId("plan-hints")).toHaveTextContent("Rule");
    expect(screen.getByTestId("plan-hints")).toHaveTextContent("Stay under 5 requests per second.");

    const scope = screen.getByTestId("plan-scope");
    expect(scope).toHaveTextContent("Include");
    expect(scope).toHaveTextContent("shop.acme.com");
    expect(scope).toHaveTextContent("Exclude");
    expect(scope).toHaveTextContent("status.acme.com");
  });

  it("keeps Apply disabled until the inclusion is acknowledged, then shows the created node count", async () => {
    mocks.applyPlanDraft.mockResolvedValue({ ...pending, status: "applied", created_node_ids: [11, 12, 13] });
    render(<Harness draft={pending} />);

    const apply = screen.getByRole("button", { name: "Apply plan" });
    expect(apply).toBeDisabled();
    expect(screen.getByText("This widens the task scope")).toBeInTheDocument();

    fireEvent.click(screen.getByTestId("plan-include-checkbox"));
    await waitFor(() => expect(apply).toBeEnabled());

    fireEvent.click(apply);
    await waitFor(() => expect(mocks.applyPlanDraft).toHaveBeenCalledWith("t-acme-web", 7, true));
    expect(await screen.findByTestId("plan-created-nodes")).toHaveTextContent("Created 3 nodes");
  });

  it("applies a narrowing proposal without asking for the scope acknowledgement", async () => {
    const narrowing: PlanDraft = {
      ...pending,
      proposal: { ...pending.proposal, scope: [{ effect: "exclude", kind: "subdomain", value: "status.acme.com" }] },
    };
    mocks.applyPlanDraft.mockResolvedValue({ ...narrowing, status: "applied", created_node_ids: [21] });
    render(<Harness draft={narrowing} />);

    expect(screen.queryByTestId("plan-include-checkbox")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Apply plan" }));
    await waitFor(() => expect(mocks.applyPlanDraft).toHaveBeenCalledWith("t-acme-web", 7, false));
  });

  it("discards the draft through the discard endpoint", async () => {
    render(<PlanProposalPreview taskId="t-acme-web" draft={pending} />);

    fireEvent.click(screen.getByRole("button", { name: "Discard" }));
    await waitFor(() => expect(mocks.discardPlanDraft).toHaveBeenCalledWith("t-acme-web", 7));
    expect(mocks.applyPlanDraft).not.toHaveBeenCalled();
  });

  // A proposal from the model may omit any section; rendering must not throw.
  it("renders a proposal that omits every optional section", () => {
    render(<PlanProposalPreview taskId="t-acme-web" draft={{ ...pending, proposal: { summary: "only a summary" } }} />);
    expect(screen.getByText("only a summary")).toBeTruthy();
    expect(screen.getByRole("button", { name: /apply/i })).toBeTruthy();
  });

  // A draft from the pasted-policy entry point carries only the scope section:
  // the preview must list the rules and still gate Apply on the inclusion.
  it("renders a scope-only draft", () => {
    const scopeOnly: PlanDraft = {
      ...pending,
      summary: "Vendor portal program",
      proposal: {
        summary: "Vendor portal program",
        scope: [
          { effect: "exclude", kind: "root_domain", value: "thirdparty.example", note: "out of scope" },
          { effect: "include", kind: "subdomain", value: "api.vendor.example" },
        ],
      },
    };
    render(<PlanProposalPreview taskId="t-acme-web" draft={scopeOnly} />);

    expect(screen.getByTestId("plan-goals")).toHaveTextContent("None");
    expect(screen.getByTestId("plan-intents")).toHaveTextContent("None");
    expect(screen.getByTestId("plan-hints")).toHaveTextContent("None");
    const scope = screen.getByTestId("plan-scope");
    expect(scope).toHaveTextContent("thirdparty.example");
    expect(scope).toHaveTextContent("api.vendor.example");
    expect(screen.getByRole("button", { name: "Apply plan" })).toBeDisabled();
  });
});
