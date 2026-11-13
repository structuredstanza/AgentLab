"use client";

import * as React from "react";

import { ExplorationGraph } from "@/components/exploration-graph";
import { api, sseUrl } from "@/lib/api";
import { activeIds, baseline, emptyLiveState, eventSeq, type LiveState, reduceActivity } from "@/lib/graph-live";
import type { Activity, Edge, TaskNode } from "@/lib/types";

const REFETCH_DEBOUNCE_MS = 300;
const FALLBACK_POLL_MS = 20000;

export function GraphTab({ taskId }: { taskId: string }) {
  const [nodes, setNodes] = React.useState<TaskNode[]>([]);
  const [edges, setEdges] = React.useState<Edge[]>([]);
  const [live, setLive] = React.useState<LiveState>(emptyLiveState);
  const [sseLive, setSseLive] = React.useState(false);
  const [now, setNow] = React.useState(() => Date.now());
  // Signature of the previous graph data: when a refetch returns identical data, skip setState to avoid needlessly rebuilding the whole graph (while dragging,
  // So it won't be interrupted by a refetch and become choppy). Only pick the fields that affect rendering.
  const sigRef = React.useRef("");
  // Only the newest refetch may land; a slow earlier one must not overwrite it.
  const reqRef = React.useRef(0);
  const debounceRef = React.useRef<number | undefined>(undefined);

  const load = React.useCallback(() => {
    const token = ++reqRef.current;
    api
      .explorationGraph(taskId)
      .then((g) => {
        if (token !== reqRef.current) return;
        const ns = g.nodes ?? [];
        const es = g.edges ?? [];
        const sig = JSON.stringify([
          ns.map((n) => [n.id, n.type, n.state, n.priority, n.payload]),
          es.map((e) => [e.src, e.dst, e.rel]),
        ]);
        if (sig === sigRef.current) return; // No change → do not rebuild
        sigRef.current = sig;
        setNodes(ns);
        setEdges(es);
      })
      .catch(() => {
        /* keep last good data */
      });
  }, [taskId]);

  React.useEffect(() => {
    let cancelled = false;
    let es: EventSource | null = null;
    sigRef.current = ""; // Switching tasks: force the next refresh
    setLive(emptyLiveState());
    setSseLive(false);
    load();

    // A burst of activity events must not trigger one refetch each: coalesce them.
    const scheduleLoad = () => {
      clearTimeout(debounceRef.current);
      debounceRef.current = window.setTimeout(load, REFETCH_DEBOUNCE_MS);
    };

    // The graph tab has no history page, so it takes the task-level activity cursor
    // first: opening the stream at 0 would replay a long task's whole log into the tails.
    void api
      .activityHistory(taskId, "plan", 0, 1)
      .then((r) => r.snapshotCursor)
      .catch(() => 0)
      .then((cursor) => {
        if (cancelled) return;
        setLive((cur) => baseline(cur, cursor));
        es = new EventSource(
          sseUrl(`/api/exploration/activity/stream?task=${encodeURIComponent(taskId)}&since=${cursor}`),
        );
        es.onopen = () => {
          if (!cancelled) setSseLive(true);
        };
        // EventSource auto-reconnects with Last-Event-ID and the server replays the
        // gap, so no manual backoff loop is needed; the poll covers a dead stream.
        es.onerror = () => {
          if (!cancelled) setSseLive(false);
        };
        es.onmessage = (e) => {
          if (cancelled) return; // a frame queued before close must not leak into the next task
          let a: Activity;
          try {
            a = JSON.parse(e.data) as Activity;
          } catch {
            return; // ignore malformed frame
          }
          const seq = eventSeq(e.lastEventId, a.seq);
          const at = Date.now();
          setNow(at);
          setLive((cur) => reduceActivity(cur, { ...a, seq }, at));
          scheduleLoad();
        };
      });

    return () => {
      cancelled = true;
      es?.close();
      clearTimeout(debounceRef.current);
      reqRef.current++; // drop an in-flight refetch from this task
    };
  }, [taskId, load]);

  // Fallback poll: runs only while the stream is down, so a healthy SSE link adds no load.
  React.useEffect(() => {
    if (sseLive) return;
    const timer = setInterval(load, FALLBACK_POLL_MS);
    return () => clearInterval(timer);
  }, [sseLive, load]);

  // Re-render while a node is active so its pulse expires when the window ends.
  React.useEffect(() => {
    if (Object.keys(live.active).length === 0) return;
    const timer = setInterval(() => setNow(Date.now()), 500);
    return () => clearInterval(timer);
  }, [live]);

  const active = React.useMemo(() => new Set(activeIds(live, now)), [live, now]);

  return (
    <div className="min-w-0 border border-border">
      <ExplorationGraph
        nodes={nodes}
        edges={edges}
        className="h-[72vh]"
        taskId={taskId}
        live={live}
        activeIds={active}
      />
    </div>
  );
}
