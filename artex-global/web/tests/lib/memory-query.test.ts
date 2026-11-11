import { describe, expect, it } from "vitest";

import {
  clampLimit,
  dayBound,
  EMPTY_KNOWLEDGE_FILTERS,
  knowledgeQuery,
  knowledgeQueryOf,
  MEMORY_MAX_LIMIT,
  MEMORY_PAGE_SIZE,
  reflectionQuery,
} from "@/lib/memory-query";

function parse(suffix: string): URLSearchParams {
  return new URLSearchParams(suffix.startsWith("?") ? suffix.slice(1) : suffix);
}

describe("knowledgeQuery", () => {
  it("always carries the page window and drops empty filters", () => {
    const sp = parse(knowledgeQuery({ scope: "", kind: "", status: "", q: "  ", tag: "", limit: 0, offset: 0 }));
    expect(sp.get("limit")).toBe(String(MEMORY_PAGE_SIZE));
    expect(sp.has("offset")).toBe(false);
    expect(sp.has("scope")).toBe(false);
    expect(sp.has("q")).toBe(false);
    expect([...sp.keys()]).toEqual(["limit"]);
  });

  it("serializes every filter the endpoint accepts", () => {
    const sp = parse(
      knowledgeQuery({
        scope: "company",
        kind: "opsec",
        status: "candidate",
        source: "agent",
        tag: "env:prod",
        q: "sso bypass",
        origin_task_id: 12,
        company_id: 3,
        task_id: 9,
        created_after: "2026-01-31T00:00:00Z",
        created_before: "2026-02-01T23:59:59Z",
        sort: "updated",
        order: "asc",
        limit: 20,
        offset: 40,
      }),
    );
    expect(sp.get("scope")).toBe("company");
    expect(sp.get("kind")).toBe("opsec");
    expect(sp.get("status")).toBe("candidate");
    expect(sp.get("source")).toBe("agent");
    expect(sp.get("tag")).toBe("env:prod");
    expect(sp.get("q")).toBe("sso bypass");
    expect(sp.get("origin_task_id")).toBe("12");
    expect(sp.get("company_id")).toBe("3");
    expect(sp.get("task_id")).toBe("9");
    expect(sp.get("created_after")).toBe("2026-01-31T00:00:00Z");
    expect(sp.get("created_before")).toBe("2026-02-01T23:59:59Z");
    expect(sp.get("sort")).toBe("updated");
    expect(sp.get("order")).toBe("asc");
    expect(sp.get("limit")).toBe("20");
    expect(sp.get("offset")).toBe("40");
  });

  it("ignores non-positive ids and negative offsets", () => {
    const sp = parse(knowledgeQuery({ origin_task_id: 0, company_id: -1, task_id: null, offset: -5 }));
    expect(sp.has("origin_task_id")).toBe(false);
    expect(sp.has("company_id")).toBe(false);
    expect(sp.has("task_id")).toBe(false);
    expect(sp.has("offset")).toBe(false);
  });
});

describe("clampLimit", () => {
  it("defaults and caps the page size", () => {
    expect(clampLimit(undefined)).toBe(MEMORY_PAGE_SIZE);
    expect(clampLimit(0)).toBe(MEMORY_PAGE_SIZE);
    expect(clampLimit(-10)).toBe(MEMORY_PAGE_SIZE);
    expect(clampLimit(25)).toBe(25);
    expect(clampLimit(5000)).toBe(MEMORY_MAX_LIMIT);
  });
});

describe("dayBound", () => {
  it("widens a date input to the whole local day", () => {
    expect(dayBound("2026-01-31", false)).toBe("2026-01-31T00:00:00Z");
    expect(dayBound("2026-01-31", true)).toBe("2026-01-31T23:59:59Z");
    expect(dayBound("", true)).toBe("");
  });
});

describe("knowledgeQueryOf", () => {
  it("maps page one onto a zero offset and leaves ranking to the backend", () => {
    const q = knowledgeQueryOf(EMPTY_KNOWLEDGE_FILTERS, 1, 50);
    expect(q.offset).toBe(0);
    expect(q.sort).toBeUndefined();
    expect(q.order).toBeUndefined();
    expect(q.origin_task_id).toBeNull();
  });

  it("turns an explicit column sort and page into wire values", () => {
    const q = knowledgeQueryOf({ ...EMPTY_KNOWLEDGE_FILTERS, sort: "title", order: "asc" }, 3, 20);
    expect(q.sort).toBe("title");
    expect(q.order).toBe("asc");
    expect(q.offset).toBe(40);
    expect(q.limit).toBe(20);
  });
});

describe("reflectionQuery", () => {
  it("repeats kinds and omits an absent task", () => {
    const sp = parse(reflectionQuery({ kind: ["opsec", "noise"], q: "timing", limit: 10 }));
    expect(sp.getAll("kind")).toEqual(["opsec", "noise"]);
    expect(sp.has("task_id")).toBe(false);
    expect(sp.get("q")).toBe("timing");
    expect(sp.get("limit")).toBe("10");
  });

  it("accepts a single kind string and a task id", () => {
    const sp = parse(reflectionQuery({ kind: "learning", task_id: 7, since: "2026-01-01T00:00:00Z" }));
    expect(sp.getAll("kind")).toEqual(["learning"]);
    expect(sp.get("task_id")).toBe("7");
    expect(sp.get("since")).toBe("2026-01-01T00:00:00Z");
  });
});
