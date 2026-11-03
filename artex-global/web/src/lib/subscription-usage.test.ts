import { describe, expect, it } from "vitest";

import { formatAllocationReset, markUsageStale } from "./subscription-usage";
import type { LLMProfileUsage } from "./types";

describe("markUsageStale", () => {
  it("marks the cached response stale without changing measured remaining fractions", () => {
    for (const remaining of [0, 0.25]) {
      const usage: LLMProfileUsage = {
        profile_id: "synthetic",
        name: "fixture",
        auth_method: "codex",
        connected: true,
        plan: "Pro",
        fetched_at: "2026-10-30T12:00:00.000Z",
        stale: false,
        windows: [{ id: "five_hour", label: "5-Hour Session", used_fraction: 1 - remaining, remaining_fraction: remaining, resets_at: null }],
      };

      const stale = markUsageStale(usage);
      expect(stale.stale).toBe(true);
      expect(stale.windows).toEqual(usage.windows);
      expect(stale.windows[0].remaining_fraction).toBe(remaining);
    }
  });
});

describe("formatAllocationReset", () => {
  const now = Date.parse("2026-10-31T12:00:00Z");

  it.each([
    [98 * 3600_000, "in 4d2hr"],
    [24 * 3600_000, "in 1d0hr"],
    [24 * 3600_000 - 1, "in 23hr59m"],
    [2 * 3600_000 + 5 * 60_000, "in 2hr5m"],
    [1, "in 1m"],
    [0, "now"],
    [-3600_000, "now"],
  ])("formats the remaining interval of %i ms", (remaining, expected) => {
    expect(formatAllocationReset(new Date(now + remaining).toISOString(), now)).toBe(expected);
  });

  it("uses the timestamp offset rather than the local clock", () => {
    expect(formatAllocationReset("2026-11-04T16:00:00+02:00", now)).toBe("in 4d2hr");
  });

  it.each([null, undefined, "", "invalid"])("omits an unavailable reset timestamp: %s", (reset) => {
    expect(formatAllocationReset(reset, now)).toBeNull();
  });
});
