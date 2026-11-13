import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { Activity, TaskNode } from "@/lib/types";

const mocks = vi.hoisted(() => ({
  explorationGraph: vi.fn(),
  activityHistory: vi.fn(),
  graphActive: [] as string[],
}));

vi.mock("@/lib/api", () => ({
  api: { explorationGraph: mocks.explorationGraph, activityHistory: mocks.activityHistory },
  sseUrl: (path: string) => path,
}));

vi.mock("@/components/exploration-graph", () => ({
  ExplorationGraph: (props: { activeIds?: ReadonlySet<string> }) => {
    mocks.graphActive = [...(props.activeIds ?? [])];
    return null;
  },
}));

import { GraphTab } from "@/app/(main)/function/tasks/detail/_tabs/graph-tab";

const node: TaskNode = { id: "7", type: "intent", state: "running", priority: 5, origin: "planner", ts: "" };

function activity(seq: number): Activity {
  return { seq, intent_id: "7", worker: "work#1", ts: "", kind: "text", summary: `step ${seq}` };
}

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  url: string;
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((e: { data: string; lastEventId: string }) => void) | null = null;
  close = vi.fn();

  constructor(url: string) {
    this.url = url;
    FakeEventSource.instances.push(this);
  }

  emit(a: Activity) {
    this.onmessage?.({ data: JSON.stringify(a), lastEventId: String(a.seq) });
  }
}

beforeEach(() => {
  FakeEventSource.instances = [];
  mocks.graphActive = [];
  vi.stubGlobal("EventSource", FakeEventSource);
  mocks.explorationGraph.mockResolvedValue({ nodes: [node], edges: [] });
  mocks.activityHistory.mockResolvedValue({ items: [], snapshotCursor: 5, earliestCursor: 0, hasMore: false });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe("GraphTab", () => {
  it("opens the stream at the task cursor and marks the node active", async () => {
    render(<GraphTab taskId="t1" />);
    await waitFor(() => expect(FakeEventSource.instances).toHaveLength(1));
    expect(FakeEventSource.instances[0].url).toContain("since=5");

    act(() => FakeEventSource.instances[0].emit(activity(6)));
    await waitFor(() => expect(mocks.graphActive).toContain("7"));
  });

  it("coalesces a burst of events into one refetch", async () => {
    render(<GraphTab taskId="t1" />);
    await waitFor(() => expect(FakeEventSource.instances).toHaveLength(1));
    expect(mocks.explorationGraph).toHaveBeenCalledTimes(1);

    act(() => {
      for (let i = 0; i < 50; i++) FakeEventSource.instances[0].emit(activity(6 + i));
    });

    await waitFor(() => expect(mocks.explorationGraph).toHaveBeenCalledTimes(2), { timeout: 1500 });
    // One debounce window later no further refetch has been scheduled.
    const { promise, resolve } = Promise.withResolvers<void>();
    setTimeout(resolve, 400);
    await promise;
    expect(mocks.explorationGraph).toHaveBeenCalledTimes(2);
  });

  it("stops the fallback poll once the stream is open", async () => {
    vi.useFakeTimers();
    try {
      render(<GraphTab taskId="t1" />);
      // Flush the cursor fetch and the initial graph load without running timers.
      await act(async () => {
        for (let i = 0; i < 5; i++) await Promise.resolve();
      });
      expect(FakeEventSource.instances).toHaveLength(1);
      act(() => FakeEventSource.instances[0].onopen?.());
      await act(async () => {
        vi.advanceTimersByTime(25000);
      });
      expect(mocks.explorationGraph).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});
