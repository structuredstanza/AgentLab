import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Regression: the hook loaded one latest page and dropped `hasMore`, so a chat
// pane past the page size silently lost the beginning of its thread with no way
// to page it back. The hook now returns hasMore and a loadEarlier that prepends
// one older page.
const h = vi.hoisted(() => ({ history: vi.fn() }));

vi.mock("@/lib/api", () => ({
  api: { conversationHistory: h.history, conversationMessages: vi.fn() },
}));

import { useConversationTail } from "@/hooks/use-conversation-tail";
import type { Activity } from "@/lib/types";

function activity(seq: number): Activity {
  return { seq, worker: "mainagent", ts: "", kind: "text", summary: `step ${seq}` };
}

describe("useConversationTail", () => {
  beforeEach(() => {
    h.history.mockReset();
  });

  it("reports older steps and prepends them on demand", async () => {
    h.history.mockImplementation(async (_id: number, before = 0) =>
      before === 0
        ? { items: [activity(5), activity(6)], cursor: 6, running: false, hasMore: true }
        : { items: [activity(3), activity(4)], cursor: 6, running: false, hasMore: false },
    );

    const { result } = renderHook(() => useConversationTail(1));
    await waitFor(() => expect(result.current.loaded).toBe(true));
    expect(result.current.hasMore).toBe(true);
    expect(result.current.messages.map((m) => m.seq)).toEqual([5, 6]);

    await act(async () => {
      await result.current.loadEarlier();
    });

    // The older page is requested before the earliest loaded step, and prepended.
    expect(h.history).toHaveBeenLastCalledWith(1, 5, 200);
    expect(result.current.messages.map((m) => m.seq)).toEqual([3, 4, 5, 6]);
    expect(result.current.hasMore).toBe(false);
  });
});
