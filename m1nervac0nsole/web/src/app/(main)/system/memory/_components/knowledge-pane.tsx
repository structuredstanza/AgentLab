"use client";

import * as React from "react";

import { ChevronRightIcon, PlusIcon, SearchIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { TablePagination } from "@/components/table-pagination";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getDateLocale } from "@/i18n/datetime";
import { api } from "@/lib/api";
import { EMPTY_KNOWLEDGE_FILTERS, type KnowledgeFilters, knowledgeQueryOf, MEMORY_PAGE_SIZE } from "@/lib/memory-query";
import type {
  BulkKnowledgeAction,
  BulkKnowledgeResult,
  Company,
  KnowledgeEntry,
  KnowledgeKind,
  KnowledgeReview,
  KnowledgeScope,
  KnowledgeSort,
  KnowledgeSource,
  KnowledgeStats,
  KnowledgeStatus,
  KnowledgeUsage,
  Task,
} from "@/lib/types";

import { CreateKnowledgeDialog } from "./knowledge-create";
import { KNOWLEDGE_KINDS, KNOWLEDGE_SCOPES, KNOWLEDGE_STATUSES, KnowledgeDetail } from "./knowledge-detail";
import { KnowledgeReviewList } from "./knowledge-review";
import { BulkResults, RelaxedNotice, StatusBadge, UsageCell } from "./memory-shared";

function fmtDate(ts: string): string {
  return new Date(ts).toLocaleString(getDateLocale(), {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function StatRow({ stats }: { stats: KnowledgeStats | null }) {
  const t = useTranslations("memoryPage");
  const tiles = [
    { label: t("stats.total"), value: stats?.total ?? 0 },
    { label: t("stats.adopted"), value: stats?.by_status.adopted ?? 0 },
    { label: t("stats.candidate"), value: stats?.by_status.candidate ?? 0 },
    { label: t("stats.retired"), value: stats?.by_status.retired ?? 0 },
  ];
  const scopes = Object.entries(stats?.by_scope ?? {}).map(([k, v]) => `${k} ${v}`);
  return (
    <div className="space-y-2">
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-4">
        {tiles.map((tile) => (
          <div key={tile.label} className="border-border border-t pt-1.5">
            <dt className="text-[11px] text-muted-foreground">{tile.label}</dt>
            <dd className="font-semibold text-lg tabular-nums">{tile.value}</dd>
          </div>
        ))}
      </dl>
      {scopes.length > 0 && <p className="text-[11px] text-muted-foreground">{scopes.join(" / ")}</p>}
    </div>
  );
}

export function KnowledgePane({ tasks, companies }: { tasks: Task[]; companies: Company[] }) {
  const t = useTranslations("memoryPage");
  const [filters, setFilters] = React.useState<KnowledgeFilters>(EMPTY_KNOWLEDGE_FILTERS);
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(MEMORY_PAGE_SIZE);
  const [entries, setEntries] = React.useState<KnowledgeEntry[]>([]);
  const [total, setTotal] = React.useState(0);
  const [relaxed, setRelaxed] = React.useState(false);
  const [loading, setLoading] = React.useState(true);
  const [stats, setStats] = React.useState<KnowledgeStats | null>(null);
  const [selected, setSelected] = React.useState<Set<number>>(new Set());
  const [detail, setDetail] = React.useState<KnowledgeEntry | null>(null);
  const [createOpen, setCreateOpen] = React.useState(false);
  const [usage, setUsage] = React.useState<Record<number, KnowledgeUsage>>({});
  const [usageLoading, setUsageLoading] = React.useState<Set<number>>(new Set());
  const [bulkPromoteOpen, setBulkPromoteOpen] = React.useState(false);
  const [bulkScope, setBulkScope] = React.useState<"company" | "environment" | "global">("global");
  const [bulkCompany, setBulkCompany] = React.useState(0);
  const [bulkDeleteOpen, setBulkDeleteOpen] = React.useState(false);
  const [bulkBusy, setBulkBusy] = React.useState(false);
  const [bulkResults, setBulkResults] = React.useState<BulkKnowledgeResult[] | null>(null);
  const [reviewTask, setReviewTask] = React.useState("");
  const [review, setReview] = React.useState<KnowledgeReview | null>(null);
  const [reviewLoading, setReviewLoading] = React.useState(false);
  const [reviewError, setReviewError] = React.useState("");

  const query = React.useMemo(() => knowledgeQueryOf(filters, page, pageSize), [filters, page, pageSize]);

  const loadStats = React.useCallback(() => {
    api
      .knowledgeStats()
      .then(setStats)
      .catch(() => {
        /* stats are advisory; the list still works without them */
      });
  }, []);

  // Switching the reviewed task must not keep the previous task's rows on
  // screen: they would sit under the new label and the bulk actions would hit
  // the wrong task's entries.
  const selectReviewTask = React.useCallback((id: string) => {
    setReview(null);
    setReviewError("");
    setReviewTask(id);
    setSelected(new Set());
  }, []);

  // The archive dialog links here with ?review_task=<id>; read it once, as soon
  // as the task list can tell a real id from a malformed one.
  const linked = React.useRef(false);
  React.useEffect(() => {
    if (linked.current || tasks.length === 0) return;
    linked.current = true;
    const id = new URLSearchParams(window.location.search).get("review_task") ?? "";
    if (tasks.some((task) => task.id === id)) selectReviewTask(id);
  }, [tasks, selectReviewTask]);

  // A late answer for the previous selection must not land either.
  const reviewSeq = React.useRef(0);
  const loadReview = React.useCallback(() => {
    const seq = ++reviewSeq.current;
    if (!reviewTask) {
      setReview(null);
      setReviewError("");
      setReviewLoading(false);
      return;
    }
    setReviewLoading(true);
    setReviewError("");
    api
      .knowledgeReview(reviewTask)
      .then((r) => {
        if (seq === reviewSeq.current) setReview(r);
      })
      .catch((e) => {
        if (seq === reviewSeq.current) setReviewError((e as Error).message);
      })
      .finally(() => {
        if (seq === reviewSeq.current) setReviewLoading(false);
      });
  }, [reviewTask]);

  // Typing in the search box fires a request per keystroke; only the newest
  // answer may land, or a slow earlier page would replace the current one.
  const requestId = React.useRef(0);
  const reload = React.useCallback(() => {
    const id = ++requestId.current;
    setLoading(true);
    api
      .knowledgeList(query)
      .then((r) => {
        if (id !== requestId.current) return;
        setEntries(r.entries);
        setTotal(r.total);
        setRelaxed(r.relaxed);
      })
      .catch((e) => {
        if (id === requestId.current) toast.error(t("loadFailed", { msg: (e as Error).message }));
      })
      .finally(() => {
        if (id === requestId.current) setLoading(false);
      });
  }, [query, t]);

  React.useEffect(() => {
    reload();
  }, [reload]);
  React.useEffect(() => {
    loadStats();
  }, [loadStats]);
  React.useEffect(() => {
    loadReview();
  }, [loadReview]);

  const patchFilters = (patch: Partial<KnowledgeFilters>) => {
    setFilters((f) => ({ ...f, ...patch }));
    setPage(1);
  };

  const loadUsage = (id: number) => {
    setUsageLoading((s) => new Set(s).add(id));
    api
      .knowledgeUsage(id, 20)
      .then((u) => setUsage((m) => ({ ...m, [id]: u })))
      .catch(() => {
        /* advisory: the cell stays on "load" */
      })
      .finally(() =>
        setUsageLoading((s) => {
          const next = new Set(s);
          next.delete(id);
          return next;
        }),
      );
  };

  const toggleRow = (id: number) => {
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  const allOnPage = entries.length > 0 && entries.every((e) => selected.has(e.id));
  const toggleAll = () => {
    setSelected((s) => {
      const next = new Set(s);
      if (allOnPage) for (const e of entries) next.delete(e.id);
      else for (const e of entries) next.add(e.id);
      return next;
    });
  };

  const afterWrite = (entry: KnowledgeEntry | null) => {
    if (entry) setDetail(entry);
    else setDetail(null);
    reload();
    loadStats();
    loadReview();
  };

  const toggleAllReview = (ids: number[], on: boolean) => {
    setSelected((s) => {
      const next = new Set(s);
      for (const id of ids) {
        if (on) next.add(id);
        else next.delete(id);
      }
      return next;
    });
  };

  async function runBulk(action: BulkKnowledgeAction, opts?: { scope?: string; companyId?: number }) {
    setBulkBusy(true);
    try {
      const r = await api.bulkKnowledge([...selected], action, opts);
      setBulkResults(r.results);
      setSelected(new Set());
      setBulkPromoteOpen(false);
      setBulkDeleteOpen(false);
      reload();
      loadStats();
      loadReview();
    } catch (e) {
      toast.error(t("bulk.failed", { msg: (e as Error).message }));
    } finally {
      setBulkBusy(false);
    }
  }

  // Secondary filters are collapsed by default; their active count stays visible
  // on the disclosure so a hidden filter can never silently shape the result.
  const advancedCount = [
    filters.kind,
    filters.source,
    filters.tag,
    filters.originTaskId || 0,
    filters.companyId || 0,
    filters.taskId || 0,
    filters.from,
    filters.to,
    filters.sort === "relevance" ? "" : filters.sort,
    filters.sort === "relevance" ? "" : filters.order,
  ].filter(Boolean).length;

  const hasFilters = React.useMemo(
    () => JSON.stringify(filters) !== JSON.stringify(EMPTY_KNOWLEDGE_FILTERS),
    [filters],
  );

  return (
    <div className="flex min-h-0 min-w-0 flex-1 flex-col overflow-y-auto">
      <div className="shrink-0 space-y-3 border-b px-4 py-3 lg:px-6">
        <StatRow stats={stats} />

        <div className="flex flex-wrap items-center gap-2">
          {/* The list filters shape the browser below; a review queue is one
              task's candidates, so they are hidden rather than left inert. */}
          {!reviewTask && (
            <>
              <div className="relative min-w-48 flex-1">
                <SearchIcon className="absolute top-1/2 left-2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  className="h-8 pl-7 text-xs"
                  value={filters.q}
                  onChange={(e) => patchFilters({ q: e.target.value })}
                  placeholder={t("filter.search")}
                />
              </div>
              <Select
                value={filters.scope || "all"}
                onValueChange={(v) => patchFilters({ scope: v === "all" ? "" : (v as KnowledgeScope) })}
              >
                <SelectTrigger size="sm" className="h-8 w-32 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{t("filter.allScope")}</SelectItem>
                  {KNOWLEDGE_SCOPES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Select
                value={filters.status || "all"}
                onValueChange={(v) => patchFilters({ status: v === "all" ? "" : (v as KnowledgeStatus) })}
              >
                <SelectTrigger size="sm" className="h-8 w-32 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{t("filter.allStatus")}</SelectItem>
                  {KNOWLEDGE_STATUSES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </>
          )}
          {/* Review mode: pick a task to see its candidates as a promotion
              queue. The empty value keeps the normal browser. */}
          <span className="text-[11px] text-muted-foreground">{t("review.label")}</span>
          <Select value={reviewTask || "off"} onValueChange={(v) => selectReviewTask(v === "off" ? "" : v)}>
            <SelectTrigger size="sm" className="h-8 w-40 text-xs" aria-label={t("review.taskAria")}>
              <SelectValue placeholder={t("review.pickTask")} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="off">{t("review.off")}</SelectItem>
              {tasks.map((task) => (
                <SelectItem key={task.id} value={task.id}>
                  {task.name || task.description || `#${task.id}`}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button size="sm" className="ml-auto h-8 text-xs" onClick={() => setCreateOpen(true)}>
            <PlusIcon className="size-3.5" />
            {t("create.title")}
          </Button>
        </div>

        {/* Secondary filters stay reachable but collapsed behind a named
            disclosure, so the default toolbar is one readable row. */}
        {!reviewTask && (
          <details className="group" open={advancedCount > 0 || undefined}>
            <summary className="flex w-fit cursor-pointer list-none items-center gap-1.5 text-[11px] text-muted-foreground hover:text-foreground">
              <ChevronRightIcon className="size-3 transition-transform group-open:rotate-90" />
              {t("filter.advanced")}
              {advancedCount > 0 && (
                <span className="border border-border px-1 text-[10px] text-foreground tabular-nums">
                  {advancedCount}
                </span>
              )}
            </summary>
            <div className="flex flex-wrap items-center gap-2 pt-2">
              <Select
                value={filters.kind || "all"}
                onValueChange={(v) => patchFilters({ kind: v === "all" ? "" : (v as KnowledgeKind) })}
              >
                <SelectTrigger size="sm" className="h-8 w-32 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{t("filter.allKind")}</SelectItem>
                  {KNOWLEDGE_KINDS.map((k) => (
                    <SelectItem key={k} value={k}>
                      {k}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Select
                value={filters.source || "all"}
                onValueChange={(v) => patchFilters({ source: v === "all" ? "" : (v as KnowledgeSource) })}
              >
                <SelectTrigger size="sm" className="h-8 w-28 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{t("filter.allSource")}</SelectItem>
                  {["operator", "agent", "reflection"].map((s) => (
                    <SelectItem key={s} value={s}>
                      {s}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Input
                className="h-8 w-28 text-xs"
                value={filters.tag}
                onChange={(e) => patchFilters({ tag: e.target.value })}
                placeholder={t("filter.tag")}
              />
              <Input
                className="h-8 w-28 text-xs"
                type="number"
                min={1}
                value={filters.originTaskId || ""}
                onChange={(e) => patchFilters({ originTaskId: Number(e.target.value) || 0 })}
                placeholder={t("filter.originTask")}
              />
              <Select value={String(filters.companyId)} onValueChange={(v) => patchFilters({ companyId: Number(v) })}>
                <SelectTrigger size="sm" className="h-8 w-32 text-xs">
                  <SelectValue placeholder={t("filter.company")} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="0">{t("filter.allCompany")}</SelectItem>
                  {companies.map((c) => (
                    <SelectItem key={c.id} value={String(c.id)}>
                      {c.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Select value={String(filters.taskId)} onValueChange={(v) => patchFilters({ taskId: Number(v) })}>
                <SelectTrigger size="sm" className="h-8 w-36 text-xs">
                  <SelectValue placeholder={t("filter.taskLens")} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="0">{t("filter.allTasks")}</SelectItem>
                  {tasks.map((task) => (
                    <SelectItem key={task.id} value={task.id}>
                      {task.name || task.description || `#${task.id}`}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Input
                className="h-8 w-32 text-xs"
                type="date"
                value={filters.from}
                onChange={(e) => patchFilters({ from: e.target.value })}
                title={t("filter.createdAfter")}
              />
              <Input
                className="h-8 w-32 text-xs"
                type="date"
                value={filters.to}
                onChange={(e) => patchFilters({ to: e.target.value })}
                title={t("filter.createdBefore")}
              />
              <Select
                value={filters.sort}
                onValueChange={(v) => patchFilters({ sort: v as KnowledgeSort | "relevance" })}
              >
                <SelectTrigger size="sm" className="h-8 w-32 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="relevance">{t("filter.sortRelevance")}</SelectItem>
                  <SelectItem value="created">{t("filter.sortCreated")}</SelectItem>
                  <SelectItem value="updated">{t("filter.sortUpdated")}</SelectItem>
                  <SelectItem value="title">{t("filter.sortTitle")}</SelectItem>
                </SelectContent>
              </Select>
              {filters.sort !== "relevance" && (
                <Button
                  size="sm"
                  variant="outline"
                  className="h-8 px-2 text-xs"
                  onClick={() => patchFilters({ order: filters.order === "asc" ? "desc" : "asc" })}
                >
                  {filters.order === "asc" ? "ASC" : "DESC"}
                </Button>
              )}
              {hasFilters && (
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-8 text-xs"
                  onClick={() => setFilters(EMPTY_KNOWLEDGE_FILTERS)}
                >
                  {t("filter.clear")}
                </Button>
              )}
            </div>
          </details>
        )}

        {!reviewTask && <RelaxedNotice relaxed={relaxed} />}

        {selected.size > 0 && (
          <div className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/50 px-2 py-1.5 text-xs">
            <span className="font-medium">{t("bulk.selected", { count: selected.size })}</span>
            <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => setBulkPromoteOpen(true)}>
              {t("bulk.promote")}
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="h-7 text-xs"
              onClick={() => void runBulk("adopt")}
              disabled={bulkBusy}
            >
              {t("bulk.adopt")}
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="h-7 text-xs"
              onClick={() => void runBulk("retire")}
              disabled={bulkBusy}
            >
              {t("bulk.retire")}
            </Button>
            <Button
              size="sm"
              variant="destructive"
              className="h-7 text-xs"
              onClick={() => setBulkDeleteOpen(true)}
              disabled={bulkBusy}
            >
              {t("bulk.delete")}
            </Button>
            <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={() => setSelected(new Set())}>
              {t("bulk.clear")}
            </Button>
          </div>
        )}
      </div>

      <div className="min-h-[16rem] min-w-0 flex-1 overflow-auto">
        {reviewTask ? (
          <>
            <p className="border-b px-4 py-2 text-[11px] text-muted-foreground lg:px-6">
              {t("review.hint", { task: reviewTask })}
            </p>
            {/* A failed load must not look like an empty queue: the previous
                rows are gone, so say why instead of "nothing left". */}
            {reviewError ? (
              <p className="p-8 text-center text-destructive text-sm">{t("review.failed", { msg: reviewError })}</p>
            ) : (
              <KnowledgeReviewList
                review={review}
                loading={reviewLoading}
                selected={selected}
                onToggle={toggleRow}
                onToggleAll={toggleAllReview}
                onOpen={setDetail}
              />
            )}
          </>
        ) : (
          <>
            {loading && entries.length === 0 && (
              <div className="flex h-40 items-center justify-center">
                <Spinner />
              </div>
            )}
            {!loading && entries.length === 0 && (
              <p className="p-8 text-center text-muted-foreground text-sm">{t("empty")}</p>
            )}
            {!loading && entries.length > 0 && (
              // Fixed layout + min width: long titles truncate inside the title column
              // instead of painting over status/source, and narrow viewports scroll.
              <Table className="min-w-[52rem] table-fixed">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-8">
                      <Checkbox checked={allOnPage} onCheckedChange={toggleAll} aria-label={t("bulk.selectAll")} />
                    </TableHead>
                    <TableHead className="w-14">{t("column.id")}</TableHead>
                    <TableHead>{t("column.title")}</TableHead>
                    <TableHead className="w-24">{t("column.status")}</TableHead>
                    <TableHead className="w-24">{t("column.source")}</TableHead>
                    <TableHead className="w-40">{t("column.tags")}</TableHead>
                    <TableHead className="w-24">{t("column.usage")}</TableHead>
                    <TableHead className="w-28">{t("column.updated")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {entries.map((entry) => (
                    <TableRow key={entry.id} data-state={selected.has(entry.id) ? "selected" : undefined}>
                      <TableCell>
                        <Checkbox
                          checked={selected.has(entry.id)}
                          onCheckedChange={() => toggleRow(entry.id)}
                          aria-label={`select ${entry.id}`}
                        />
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-muted-foreground tabular-nums">
                        #{entry.id}
                      </TableCell>
                      <TableCell className="overflow-hidden">
                        <button
                          type="button"
                          className="flex w-full min-w-0 flex-col items-start gap-0.5 text-left"
                          onClick={() => setDetail(entry)}
                        >
                          <span className="max-w-full truncate font-medium text-xs hover:underline">{entry.title}</span>
                          <span className="flex max-w-full flex-wrap items-center gap-1">
                            <Badge variant="outline" className="px-1 py-0 text-[10px]">
                              {entry.scope}
                            </Badge>
                            <Badge variant="outline" className="px-1 py-0 text-[10px]">
                              {entry.kind}
                            </Badge>
                            {entry.origin_task_id ? (
                              <span className="text-[10px] text-muted-foreground">#{entry.origin_task_id}</span>
                            ) : null}
                          </span>
                        </button>
                      </TableCell>
                      <TableCell className="overflow-hidden">
                        <StatusBadge status={entry.status} />
                      </TableCell>
                      <TableCell className="overflow-hidden">
                        <span className="block truncate text-muted-foreground text-xs" title={entry.source}>
                          {entry.source}
                        </span>
                      </TableCell>
                      <TableCell className="overflow-hidden">
                        <span className="line-clamp-1 text-[11px] text-muted-foreground">{entry.tags.join(", ")}</span>
                      </TableCell>
                      <TableCell>
                        <UsageCell
                          usage={usage[entry.id]}
                          loading={usageLoading.has(entry.id)}
                          onLoad={() => loadUsage(entry.id)}
                        />
                      </TableCell>
                      <TableCell className="overflow-hidden">
                        <span className="block truncate text-[11px] text-muted-foreground tabular-nums">
                          {fmtDate(entry.updated_at)}
                        </span>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </>
        )}
      </div>

      {!reviewTask && (
        <TablePagination
          page={page}
          pageSize={pageSize}
          total={total}
          onPageChange={setPage}
          onPageSizeChange={(s) => {
            setPageSize(s);
            setPage(1);
          }}
        />
      )}

      {detail && (
        <KnowledgeDetail
          entry={detail}
          tasks={tasks}
          companies={companies}
          onClose={() => setDetail(null)}
          onChanged={afterWrite}
        />
      )}

      <CreateKnowledgeDialog
        open={createOpen}
        tasks={tasks}
        companies={companies}
        onOpenChange={setCreateOpen}
        onCreated={() => {
          reload();
          loadStats();
          loadReview();
        }}
      />

      <AlertDialog open={bulkPromoteOpen} onOpenChange={setBulkPromoteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("promote.title")}</AlertDialogTitle>
            <AlertDialogDescription>{t("bulk.promoteDesc", { count: selected.size })}</AlertDialogDescription>
          </AlertDialogHeader>
          <div className="space-y-2">
            <Select value={bulkScope} onValueChange={(v) => setBulkScope(v as typeof bulkScope)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="global">global</SelectItem>
                <SelectItem value="environment">environment</SelectItem>
                <SelectItem value="company">company</SelectItem>
              </SelectContent>
            </Select>
            {bulkScope === "company" && (
              <Select value={String(bulkCompany)} onValueChange={(v) => setBulkCompany(Number(v))}>
                <SelectTrigger>
                  <SelectValue placeholder={t("promote.companyPlaceholder")} />
                </SelectTrigger>
                <SelectContent>
                  {companies.map((c) => (
                    <SelectItem key={c.id} value={String(c.id)}>
                      {c.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault();
                void runBulk("promote", { scope: bulkScope, companyId: bulkCompany });
              }}
              disabled={bulkBusy || (bulkScope === "company" && bulkCompany <= 0)}
            >
              {t("promote.confirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={bulkDeleteOpen} onOpenChange={setBulkDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("delete.title")}</AlertDialogTitle>
            <AlertDialogDescription>{t("bulk.deleteDesc", { count: selected.size })}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault();
                void runBulk("delete");
              }}
              disabled={bulkBusy}
            >
              {t("delete.confirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={bulkResults !== null} onOpenChange={(open) => !open && setBulkResults(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("bulk.results")}</AlertDialogTitle>
          </AlertDialogHeader>
          {bulkResults && <BulkResults results={bulkResults} />}
          <AlertDialogFooter>
            <AlertDialogAction>{t("close")}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
