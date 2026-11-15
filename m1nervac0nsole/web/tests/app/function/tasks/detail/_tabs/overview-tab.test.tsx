import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { Task, TaskScopeRule } from "@/lib/types";

// Regression: the scope-rule card showed a rule's effect but never its
// authorization, and no web code called the policy routes — so an include rule
// written in the console stayed unauthorized and the gateway kept refusing the
// destination with no way to approve it from the UI.
const mocks = vi.hoisted(() => ({
  task: vi.fn(),
  stats: vi.fn(),
  intents: vi.fn(),
  findings: vi.fn(),
  taskCoverage: vi.fn(),
  tokensByModel: vi.fn(),
  taskGoals: vi.fn(),
  taskConstraints: vi.fn(),
  taskScope: vi.fn(),
  taskScopeRules: vi.fn(),
  taskInterceptRules: vi.fn(),
  setTaskRuleAuthorized: vi.fn(),
}));

// StatusBadge asks the translator whether a key exists before using it.
const stableT = Object.assign((key: string) => key, { has: () => false });

vi.mock("next-intl", () => ({ useTranslations: () => stableT }));
vi.mock("@/lib/api", () => ({ api: mocks }));

import { OverviewTab } from "@/app/(main)/function/tasks/detail/_tabs/overview-tab";

const task: Task = { id: "t1", description: "d", goal: "g", status: "running", created_at: "" };

function rule(authorized: boolean): TaskScopeRule {
  return {
    id: 7,
    task_id: 1,
    effect: "include",
    pattern: "api.corp.example",
    note: "",
    created_at: "",
    protocol: "any",
    ports: [],
    authorized,
  };
}

beforeEach(() => {
  mocks.task.mockResolvedValue(task);
  mocks.stats.mockResolvedValue({
    assets: 0,
    engine_mode: "exploring",
    llm_configured: true,
    roe_enabled: false,
    findings_confirmed: 0,
  });
  mocks.intents.mockResolvedValue([]);
  mocks.findings.mockResolvedValue([]);
  mocks.taskCoverage.mockResolvedValue({
    enabled: false,
    scope_rows: 0,
    denominator: 0,
    tested: 0,
    pct: null,
    by_type: [],
  });
  mocks.tokensByModel.mockResolvedValue({ models: [] });
  mocks.taskGoals.mockResolvedValue({ goals: [] });
  mocks.taskConstraints.mockResolvedValue({ constraints: [] });
  mocks.taskScope.mockResolvedValue({ scope: [] });
  mocks.taskInterceptRules.mockResolvedValue([]);
  mocks.setTaskRuleAuthorized.mockResolvedValue({ ok: true, authorized: true });
  // First read is the unapproved rule the operator just wrote; the read after
  // the approval returns the stored state.
  mocks.taskScopeRules.mockResolvedValueOnce([rule(false)]).mockResolvedValue([rule(true)]);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("scope rule authorization", () => {
  it("approves a rule through the policy route and shows it authorized", async () => {
    render(<OverviewTab taskId="t1" />);
    expect(await screen.findByText("scope.state.pending")).toBeInTheDocument();

    fireEvent.click(screen.getByText("scope.approve"));

    await waitFor(() => expect(mocks.setTaskRuleAuthorized).toHaveBeenCalledWith("t1", 7, true));
    await waitFor(() => expect(screen.getByText("scope.state.authorized")).toBeInTheDocument());
    expect(screen.getByText("scope.revoke")).toBeInTheDocument();
  });

  it("keeps the evidence-heavy findings list off the poll while the task is not running", async () => {
    vi.useFakeTimers();
    try {
      mocks.task.mockResolvedValue({ ...task, status: "done" });
      render(<OverviewTab taskId="t1" />);
      await act(async () => {
        for (let i = 0; i < 8; i++) await Promise.resolve();
      });
      expect(mocks.findings).toHaveBeenCalledTimes(1);

      await act(async () => {
        vi.advanceTimersByTime(3000);
      });
      await act(async () => {
        for (let i = 0; i < 8; i++) await Promise.resolve();
      });
      expect(mocks.task).toHaveBeenCalledTimes(2);
      expect(mocks.findings).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});
