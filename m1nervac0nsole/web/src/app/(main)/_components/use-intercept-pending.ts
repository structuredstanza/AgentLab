"use client";

import * as React from "react";

import { api } from "@/lib/api";

// One shell-level poller for pending intercept approvals, shared by the sidebar
// badge and the header indicator. A failed poll keeps the last known count
// rather than flashing "nothing pending"; the interval stops when the last
// subscriber unmounts.
let pendingCount = 0;
const listeners = new Set<(count: number) => void>();
let timer: number | null = null;

async function poll() {
  try {
    pendingCount = (await api.interceptPending()).length;
  } catch {
    /* keep the previous count */
  }
  for (const listener of listeners) listener(pendingCount);
}

export function useInterceptPendingCount(): number {
  const [count, setCount] = React.useState(pendingCount);

  React.useEffect(() => {
    listeners.add(setCount);
    if (timer === null) {
      void poll();
      timer = window.setInterval(poll, 5000);
    }
    setCount(pendingCount);
    return () => {
      listeners.delete(setCount);
      if (listeners.size === 0 && timer !== null) {
        window.clearInterval(timer);
        timer = null;
      }
    };
  }, []);

  return count;
}
