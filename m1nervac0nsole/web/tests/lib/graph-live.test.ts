import { describe, expect, it } from "vitest";

import {
  ACTIVE_MS,
  activeIds,
  baseline,
  emptyLiveState,
  eventSeq,
  reduceActivity,
  TAIL_LINE_CHARS,
  TAIL_LINES,
} from "@/lib/graph-live";
import type { Activity } from "@/lib/types";

function activity(seq: number, intentId?: string, summary = `step ${seq}`): Activity {
  return { seq, intent_id: intentId, worker: "work#1", ts: "", kind: "text", summary };
}

describe("reduceActivity", () => {
  it("keeps a node active for the activation window only", () => {
    const state = reduceActivity(emptyLiveState(), activity(1, "7"), 1000);
    expect(activeIds(state, 1000)).toEqual(["7"]);
    expect(activeIds(state, 1000 + ACTIVE_MS - 1)).toEqual(["7"]);
    expect(activeIds(state, 1000 + ACTIVE_MS)).toEqual([]);
  });

  it("caps the tail and keeps the newest lines", () => {
    let state = emptyLiveState();
    for (let i = 1; i <= TAIL_LINES + 5; i++) state = reduceActivity(state, activity(i, "7", `line ${i}`), 0);
    expect(state.tail["7"]).toHaveLength(TAIL_LINES);
    expect(state.tail["7"][0]).toBe("line 6");
    expect(state.tail["7"][TAIL_LINES - 1]).toBe(`line ${TAIL_LINES + 5}`);
  });

  it("clips a long line and collapses newlines", () => {
    const state = reduceActivity(emptyLiveState(), activity(1, "7", `a\nb${"x".repeat(500)}`), 0);
    expect(state.tail["7"][0]).toHaveLength(TAIL_LINE_CHARS);
    expect(state.tail["7"][0].startsWith("a b")).toBe(true);
  });

  it("ignores events without a node id but advances the baseline", () => {
    const state = reduceActivity(emptyLiveState(), activity(4), 0);
    expect(state.active).toEqual({});
    expect(state.tail).toEqual({});
    expect(state.seq).toBe(4);
  });

  it("does not mutate the input state", () => {
    const before = reduceActivity(emptyLiveState(), activity(1, "7", "one"), 0);
    const snapshot = JSON.stringify(before);
    const after = reduceActivity(before, activity(2, "7", "two"), 10);
    expect(JSON.stringify(before)).toBe(snapshot);
    expect(after.tail["7"]).toEqual(["one", "two"]);
  });

  it("drops a replayed event at or below the baseline", () => {
    const state = baseline(emptyLiveState(), 10);
    expect(reduceActivity(state, activity(9, "7"), 0)).toBe(state);
    expect(reduceActivity(state, activity(11, "7"), 0).tail["7"]).toEqual(["step 11"]);
  });
});

describe("eventSeq", () => {
  it("prefers the SSE id line over the DTO seq", () => {
    expect(eventSeq("42", 7)).toBe(42);
    expect(eventSeq("", 7)).toBe(7);
    expect(eventSeq("not-a-number", 7)).toBe(7);
  });
});
