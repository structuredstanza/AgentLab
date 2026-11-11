"use client";

import { useEffect, useRef, useState } from "react";

import { mergeActivities } from "@/lib/activity-merge";
import { api } from "@/lib/api";
import type { Activity } from "@/lib/types";

// The incremental conversation tail: one latest page on open, then a cursor
// poll while a turn runs. Shared so a second chat surface reuses the same
// endpoints and merge instead of growing its own loop.
const TAIL_PAGE = 200;
const POLL_MS = 1000;

export function useConversationTail(conversationId: number | null) {
  const [messages, setMessages] = useState<Activity[]>([]);
  const [running, setRunning] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const cursor = useRef(0);

  useEffect(() => {
    cursor.current = 0;
    setMessages([]);
    setRunning(false);
    setLoaded(false);
    if (conversationId == null) return;
    let live = true;
    api
      .conversationHistory(conversationId, 0, TAIL_PAGE)
      .then((r) => {
        if (!live) return;
        setMessages((current) => mergeActivities(r.items, current));
        cursor.current = Math.max(cursor.current, r.cursor);
        // A load must not cancel a run the caller already started (a just-sent turn).
        setRunning((current) => current || r.running);
        setLoaded(true);
      })
      .catch(() => {
        if (live) setLoaded(true);
      });
    return () => {
      live = false;
    };
  }, [conversationId]);

  useEffect(() => {
    if (!running || conversationId == null) return;
    let live = true;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      let keepPolling = true;
      try {
        const r = await api.conversationMessages(conversationId, cursor.current);
        if (!live) return;
        if (r.items.length) setMessages((prev) => mergeActivities(prev, r.items));
        cursor.current = Math.max(cursor.current, r.cursor);
        keepPolling = r.running;
        setRunning(r.running);
      } catch {
        /* transient: the next tick retries with the same cursor */
      } finally {
        if (live && keepPolling) timer = setTimeout(() => void tick(), POLL_MS);
      }
    };
    void tick();
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [running, conversationId]);

  return { messages, running, loaded, setRunning };
}
