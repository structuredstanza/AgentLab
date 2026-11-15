import "@testing-library/jest-dom/vitest";
import { act, cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { Task } from "@/lib/types";

// Regression: the tab refetched the whole findings list — every evidence body
// included — every 3 s for the life of the page, including for a task that had
// already finished and could not produce another finding.
const mocks = vi.hoisted(() => ({ findings: vi.fn(), task: vi.fn() }));

const stableT = Object.assign((key: string) => key, { has: () => false });

vi.mock("next-intl", () => ({ useTranslations: () => stableT }));
vi.mock("@/lib/api", () => ({ api: mocks }));

import { FindingsTab } from "@/app/(main)/function/tasks/detail/_tabs/findings-tab";

const task: Task = { id: "t1", description: "d", goal: "g", status: "done", created_at: "" };

beforeEach(() => {
  mocks.findings.mockResolvedValue([]);
  mocks.task.mockResolvedValue(task);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

async function flush() {
  await act(async () => {
    for (let i = 0; i < 8; i++) await Promise.resolve();
  });
}

describe("findings tab polling", () => {
  it("does not refetch the findings list while the task is not running", async () => {
    vi.useFakeTimers();
    try {
      render(<FindingsTab taskId="t1" />);
      await flush();
      expect(mocks.findings).toHaveBeenCalledTimes(1);

      // One poll tick: it checks the task status and skips the findings list.
      await act(async () => {
        vi.advanceTimersByTime(3000);
      });
      await flush();
      expect(mocks.task).toHaveBeenCalledTimes(1);
      expect(mocks.findings).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});
