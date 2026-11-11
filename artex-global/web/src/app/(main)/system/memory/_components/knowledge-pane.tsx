"use client";

import * as React from "react";

import { PlusIcon, SearchIcon } from "lucide-react";
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
import { Card, CardContent } from "@/components/ui/card";
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
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {tiles.map((tile) => (
          <Card key={tile.label} size="sm" className="gap-1">
            <CardContent>
              <p className="text-muted-foreground text-xs">{tile.label}</p>
              <p className="font-semibold text-lg tabular-nums">{tile.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>
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

  const query = React.useMemo(() => knowledgeQueryOf(filters, page, pageSize), [filters, page, pageSize]);

  const loadStats = React.useCallback(() => {
    api
      .knowledgeStats()
      .then(setStats)
      .catch(() => {
        /* stats are advisory; the list still works without them */
      });
  }, []);

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
    } catch (e) {
      toast.error(t("bulk.failed", { msg: (e as Error).message }));
    } finally {
      setBulkBusy(false);
    }
  }

  const hasFilters = React.useMemo(
    () => JSON.stringify(filters) !== JSON.stringify(EMPTY_KNOWLEDGE_FILTERS),
    [filters],
  );

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="space-y-3 border-b px-4 py-3 lg:px-6">
        <StatRow stats={stats} />

        <div className="flex flex-wrap items-center gap-2">
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
          <Select value={filters.sort} onValueChange={(v) => patchFilters({ sort: v as KnowledgeSort | "relevance" })}>
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
          <Button size="sm" className="ml-auto h-8 text-xs" onClick={() => setCreateOpen(true)}>
            <PlusIcon className="size-3.5" />
            {t("create.title")}
          </Button>
        </div>

        <RelaxedNotice relaxed={relaxed} />

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

      <div className="min-h-0 flex-1 overflow-auto">
        {loading && entries.length === 0 && (
          <div className="flex h-40 items-center justify-center">
            <Spinner />
          </div>
        )}
        {!loading && entries.length === 0 && (
          <p className="p-8 text-center text-muted-foreground text-sm">{t("empty")}</p>
        )}
        {!loading && entries.length > 0 && (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8">
                  <Checkbox checked={allOnPage} onCheckedChange={toggleAll} aria-label={t("bulk.selectAll")} />
                </TableHead>
                <TableHead>{t("column.title")}</TableHead>
                <TableHead className="w-20">{t("column.status")}</TableHead>
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
                  <TableCell className="max-w-0">
                    <button
                      type="button"
                      className="flex min-w-0 flex-col items-start gap-0.5 text-left"
                      onClick={() => setDetail(entry)}
                    >
                      <span className="truncate font-medium text-xs hover:underline">{entry.title}</span>
                      <span className="flex flex-wrap items-center gap-1">
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
                  <TableCell>
                    <StatusBadge status={entry.status} />
                  </TableCell>
                  <TableCell className="text-muted-foreground text-xs">{entry.source}</TableCell>
                  <TableCell className="max-w-40">
                    <span className="line-clamp-1 text-[11px] text-muted-foreground">{entry.tags.join(", ")}</span>
                  </TableCell>
                  <TableCell>
                    <UsageCell
                      usage={usage[entry.id]}
                      loading={usageLoading.has(entry.id)}
                      onLoad={() => loadUsage(entry.id)}
                    />
                  </TableCell>
                  <TableCell className="text-[11px] text-muted-foreground tabular-nums">
                    {fmtDate(entry.updated_at)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>

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
