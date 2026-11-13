import type { Activity } from "@/lib/types";

// Live state for the exploration graph, fed from the task activity SSE stream.
// Pure and framework-free so the reducer is testable without React or a DOM.

// A node stays visually active for this long after its last activity event.
export const ACTIVE_MS = 2000;
// The per-intent tail is bounded so a long task cannot grow it without limit.
export const TAIL_LINES = 40;
export const TAIL_LINE_CHARS = 200;

export type LiveState = {
  // Node id -> epoch ms until which the node is active.
  active: Record<string, number>;
  // Node id -> recent activity summaries, newest last.
  tail: Record<string, string[]>;
  // Highest activity seq folded in: the reconnect baseline and replay dedupe key.
  seq: number;
};

export function emptyLiveState(): LiveState {
  return { active: {}, tail: {}, seq: 0 };
}

// eventSeq prefers the SSE `id:` line (echoed as lastEventId) over the DTO field:
// the id line is what the server uses for Last-Event-ID replay.
export function eventSeq(lastEventId: string | null | undefined, dtoSeq: number): number {
  const n = Number(lastEventId);
  return Number.isSafeInteger(n) && n > 0 ? n : dtoSeq;
}

// baseline raises the replay floor without touching the live view, so opening a
// stream at the task's current cursor cannot replay old history into the tails.
export function baseline(state: LiveState, seq: number): LiveState {
  return seq > state.seq ? { ...state, seq } : state;
}

// reduceActivity folds one activity event into the live state. Events without a
// node id still advance the baseline but change nothing visible. An event already
// folded (replay after a reconnect) returns the input unchanged.
export function reduceActivity(state: LiveState, event: Activity, nowMs: number): LiveState {
  const seq = event.seq;
  if (seq > 0 && seq <= state.seq) return state;
  const next = seq > state.seq ? { ...state, seq } : state;
  const id = event.intent_id;
  if (!id) return next;
  const line = event.summary.replace(/\s+/g, " ").trim().slice(0, TAIL_LINE_CHARS);
  const tail = state.tail[id] ?? [];
  return {
    seq: next.seq,
    active: { ...state.active, [id]: nowMs + ACTIVE_MS },
    tail: line ? { ...state.tail, [id]: [...tail, line].slice(-TAIL_LINES) } : state.tail,
  };
}

// activeIds lists the nodes whose activation window has not expired yet.
export function activeIds(state: LiveState, nowMs: number): string[] {
  return Object.entries(state.active)
    .filter(([, until]) => until > nowMs)
    .map(([id]) => id);
}
