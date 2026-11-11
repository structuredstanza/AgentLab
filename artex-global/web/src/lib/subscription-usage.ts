import type { LLMProfileUsage } from "./types";

export function markUsageStale(usage: LLMProfileUsage): LLMProfileUsage {
  return usage.stale ? usage : { ...usage, stale: true };
}

export function formatAllocationReset(resetsAt: string | null | undefined, now = Date.now()): string | null {
  if (!resetsAt) return null;
  const remaining = Date.parse(resetsAt) - now;
  if (!Number.isFinite(remaining)) return null;
  if (remaining <= 0) return "now";
  const minutes = Math.max(1, Math.floor(remaining / 60_000));
  const days = Math.floor(minutes / 1440);
  const hours = Math.floor((minutes % 1440) / 60);
  const duration = days > 0 ? `${days}d${hours}hr` : hours > 0 ? `${hours}hr${minutes % 60}m` : `${minutes}m`;
  return `in ${duration}`;
}
