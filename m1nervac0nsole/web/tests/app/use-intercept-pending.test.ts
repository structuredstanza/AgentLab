import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The header indicator and the sidebar badge share one module-level poller, so
// its refcount and failure behaviour are what keep approvals visible without
// double-polling the API.
const { interceptPending } = vi.hoisted(() => ({ interceptPending: vi.fn() }));

vi.mock("@/lib/api", () => ({ api: { interceptPending } }));

type PendingHook = () => number;

// Module state (count, listener set, timer) is per import, so every test needs a
// fresh copy; a static import cannot be reset and would leak the count between
// tests. cleanup() unmounts hooks before that happens.
async function loadHook(): Promise<PendingHook> {
  vi.resetModules();
  const mod = await import("@/app/(main)/_components/use-intercept-pending");
  return mod.useInterceptPendingCount;
}

async function tick(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

beforeEach(() => {
  vi.useFakeTimers();
  interceptPending.mockReset();
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("useInterceptPendingCount", () => {
  it("polls once for two consumers and shares the resolved count", async () => {
    interceptPending.mockResolvedValue([{ id: 1 }, { id: 2 }]);
    const useCount = await loadHook();

    const first = renderHook(() => useCount());
    const second = renderHook(() => useCount());
    await tick(0);

    expect(interceptPending).toHaveBeenCalledTimes(1);
    expect(first.result.current).toBe(2);
    expect(second.result.current).toBe(2);
  });

  it("keeps the last count when a poll fails", async () => {
    interceptPending.mockResolvedValueOnce([{ id: 1 }]).mockRejectedValue(new Error("offline"));
    const useCount = await loadHook();
    const { result } = renderHook(() => useCount());

    await tick(0);
    expect(result.current).toBe(1);

    await tick(5000);
    expect(interceptPending).toHaveBeenCalledTimes(2);
    expect(result.current).toBe(1);
  });

  it("keeps polling while one consumer remains", async () => {
    interceptPending.mockResolvedValue([{ id: 1 }]);
    const useCount = await loadHook();
    const first = renderHook(() => useCount());
    const second = renderHook(() => useCount());

    await tick(0);
    first.unmount();
    await tick(5000);

    expect(interceptPending).toHaveBeenCalledTimes(2);
    expect(second.result.current).toBe(1);
  });

  it("stops the interval when the last consumer unmounts", async () => {
    interceptPending.mockResolvedValue([{ id: 1 }]);
    const useCount = await loadHook();
    const first = renderHook(() => useCount());
    const second = renderHook(() => useCount());

    await tick(0);
    first.unmount();
    second.unmount();
    await tick(20_000);

    expect(interceptPending).toHaveBeenCalledTimes(1);
  });

  it("polls immediately when a consumer remounts after idle", async () => {
    interceptPending.mockResolvedValueOnce([{ id: 1 }]).mockResolvedValue([{ id: 1 }, { id: 2 }]);
    const useCount = await loadHook();
    const first = renderHook(() => useCount());

    await tick(0);
    first.unmount();
    await tick(5000);
    expect(interceptPending).toHaveBeenCalledTimes(1);

    const second = renderHook(() => useCount());
    await tick(0);

    expect(interceptPending).toHaveBeenCalledTimes(2);
    expect(second.result.current).toBe(2);
  });
});
