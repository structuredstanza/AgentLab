// Query-string building for the knowledge and reflection list endpoints.
// Kept out of api.ts so the paging/filter rules are testable without a fetch:
// empty filters are dropped, limit is clamped to the backend's cap, and a date
// input ("2026-01-31") becomes a full RFC3339 instant the Go parser accepts.

import type {
  KnowledgeKind,
  KnowledgeQuery,
  KnowledgeScope,
  KnowledgeSort,
  KnowledgeSource,
  KnowledgeStatus,
  ReflectionQuery,
} from "@/lib/types";

export const MEMORY_PAGE_SIZE = 50;
export const MEMORY_MAX_LIMIT = 200;

function setIf(sp: URLSearchParams, key: string, value: string | number | null | undefined) {
  if (value === null || value === undefined) return;
  const text = String(value).trim();
  if (text !== "") sp.set(key, text);
}

function setID(sp: URLSearchParams, key: string, value: number | null | undefined) {
  if (typeof value === "number" && Number.isFinite(value) && value > 0) sp.set(key, String(Math.trunc(value)));
}

// clampLimit keeps a page request inside what the backend serves.
export function clampLimit(limit?: number): number {
  if (!limit || !Number.isFinite(limit) || limit <= 0) return MEMORY_PAGE_SIZE;
  return Math.min(Math.trunc(limit), MEMORY_MAX_LIMIT);
}

// dayBound turns a date-input value into an RFC3339 instant: the first or the
// last second of that local day, so "created before" includes the whole day.
export function dayBound(day: string, end: boolean): string {
  if (!day.trim()) return "";
  return `${day.trim()}T${end ? "23:59:59" : "00:00:00"}Z`;
}

function suffix(sp: URLSearchParams): string {
  const text = sp.toString();
  return text ? `?${text}` : "";
}

// knowledgeQuery returns the suffix for GET /api/knowledge, always carrying the
// page window so the response's limit/offset match what the UI asked for.
export function knowledgeQuery(q: KnowledgeQuery = {}): string {
  const sp = new URLSearchParams();
  setIf(sp, "scope", q.scope);
  setIf(sp, "kind", q.kind);
  setIf(sp, "status", q.status);
  setIf(sp, "source", q.source);
  setIf(sp, "tag", q.tag);
  setIf(sp, "q", q.q);
  setIf(sp, "created_after", q.created_after);
  setIf(sp, "created_before", q.created_before);
  setID(sp, "origin_task_id", q.origin_task_id);
  setID(sp, "company_id", q.company_id);
  setID(sp, "task_id", q.task_id);
  setIf(sp, "sort", q.sort);
  setIf(sp, "order", q.order);
  sp.set("limit", String(clampLimit(q.limit)));
  if (q.offset && q.offset > 0) sp.set("offset", String(Math.trunc(q.offset)));
  return suffix(sp);
}

// reflectionQuery returns the suffix for GET /api/reflections. Kinds repeat on
// the wire, matching how the endpoint accepts them.
export function reflectionQuery(q: ReflectionQuery = {}): string {
  const sp = new URLSearchParams();
  setID(sp, "task_id", q.task_id);
  // Repeated on the wire: the endpoint accepts kind more than once.
  for (const kind of Array.isArray(q.kind) ? q.kind : [q.kind]) if (kind) sp.append("kind", kind);
  setIf(sp, "source", q.source);
  setIf(sp, "q", q.q);
  setIf(sp, "since", q.since);
  sp.set("limit", String(clampLimit(q.limit)));
  if (q.offset && q.offset > 0) sp.set("offset", String(Math.trunc(q.offset)));
  return suffix(sp);
}

// The knowledge browser's filter form state. "relevance" is a sort choice that
// is not a wire parameter: it leaves sort/order off so the backend ranks by the
// text query instead of a column.
export interface KnowledgeFilters {
  q: string;
  scope: KnowledgeScope | "";
  kind: KnowledgeKind | "";
  status: KnowledgeStatus | "";
  source: KnowledgeSource | "";
  tag: string;
  originTaskId: number;
  companyId: number;
  taskId: number;
  from: string;
  to: string;
  sort: KnowledgeSort | "relevance";
  order: "asc" | "desc";
}

export const EMPTY_KNOWLEDGE_FILTERS: KnowledgeFilters = {
  q: "",
  scope: "",
  kind: "",
  status: "",
  source: "",
  tag: "",
  originTaskId: 0,
  companyId: 0,
  taskId: 0,
  from: "",
  to: "",
  sort: "relevance",
  order: "desc",
};

// knowledgeQueryOf maps the form state plus a 1-based page onto the endpoint's
// query shape; zero means "no filter" for the id fields.
export function knowledgeQueryOf(f: KnowledgeFilters, page: number, pageSize: number): KnowledgeQuery {
  return {
    q: f.q,
    scope: f.scope,
    kind: f.kind,
    status: f.status,
    source: f.source,
    tag: f.tag,
    origin_task_id: f.originTaskId || null,
    company_id: f.companyId || null,
    task_id: f.taskId || null,
    created_after: dayBound(f.from, false),
    created_before: dayBound(f.to, true),
    sort: f.sort === "relevance" ? undefined : f.sort,
    order: f.sort === "relevance" ? undefined : f.order,
    limit: pageSize,
    offset: (page - 1) * pageSize,
  };
}
