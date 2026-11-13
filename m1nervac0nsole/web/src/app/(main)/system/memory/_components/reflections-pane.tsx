"use client";

import * as React from "react";

import { ChevronRightIcon, SearchIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { TablePagination } from "@/components/table-pagination";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getDateLocale } from "@/i18n/datetime";
import { api } from "@/lib/api";
import { dayBound, MEMORY_PAGE_SIZE } from "@/lib/memory-query";
import type { Reflection, ReflectionKind, ReflectionQuery, ReflectionStats, Task } from "@/lib/types";

import { ReflectionDetail } from "./reflection-detail";

export const REFLECTION_KINDS: ReflectionKind[] = ["opsec", "noise", "lookfor", "learning", "mistake"];

function fmtDate(ts: string): string {
  return new Date(ts).toLocaleString(getDateLocale(), {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ReflectionsPane is the cross-task reflection pool. Reflections are private to
// their task until one is graduated (a task candidate) and then promoted, so
// every row shows the owning task and the copy says the pool does not cross
// engagement boundaries by itself.
export function ReflectionsPane({ tasks }: { tasks: Task[] }) {
  const t = useTranslations("memoryPage");
  const [taskId, setTaskId] = React.useState(0);
  const [kinds, setKinds] = React.useState<ReflectionKind[]>([]);
  const [source, setSource] = React.useState("");
  const [q, setQ] = React.useState("");
  const [since, setSince] = React.useState("");
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(MEMORY_PAGE_SIZE);
  const [rows, setRows] = React.useState<Reflection[]>([]);
  const [total, setTotal] = React.useState(0);
  const [loading, setLoading] = React.useState(true);
  const [stats, setStats] = React.useState<ReflectionStats | null>(null);
  const [detail, setDetail] = React.useState<Reflection | null>(null);

  const query: ReflectionQuery = React.useMemo(
    () => ({
      task_id: taskId || null,
      kind: kinds,
      source: source || undefined,
      q: q.trim() || undefined,
      since: dayBound(since, false),
      limit: pageSize,
      offset: (page - 1) * pageSize,
    }),
    [taskId, kinds, source, q, since, pageSize, page],
  );

  const loadStats = React.useCallback(() => {
    api
      .reflectionStats()
      .then(setStats)
      .catch(() => {
        /* stats are advisory */
      });
  }, []);

  // Only the newest request may land: typing fires one per keystroke.
  const requestId = React.useRef(0);
  const reload = React.useCallback(() => {
    const id = ++requestId.current;
    setLoading(true);
    api
      .reflections(query)
      .then((r) => {
        if (id !== requestId.current) return;
        setRows(r.reflections);
        setTotal(r.total);
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

  const reset = (patch: () => void) => {
    patch();
    setPage(1);
  };

  const toggleKind = (kind: ReflectionKind) =>
    reset(() =>
      setKinds((current) => (current.includes(kind) ? current.filter((k) => k !== kind) : [...current, kind])),
    );

  return (
    <div className="flex min-h-0 min-w-0 flex-1 flex-col overflow-y-auto">
      <div className="shrink-0 space-y-2 border-b px-4 py-3 lg:px-6">
        <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 border-border border-t pt-1.5">
          <span className="text-[11px] text-muted-foreground">
            {t("stats.reflections")}{" "}
            <strong className="font-semibold text-foreground text-sm tabular-nums">{stats?.total ?? 0}</strong>
          </span>
          <div className="flex flex-wrap gap-1">
            {Object.entries(stats?.by_kind ?? {}).map(([kind, count]) => (
              <Badge key={kind} variant="outline" className="border-border px-1.5 py-0 font-normal text-[10px]">
                {kind} <span className="tabular-nums">{count}</span>
              </Badge>
            ))}
          </div>
          <span className="ml-auto max-w-md text-[11px] text-muted-foreground">{t("reflections.privateHint")}</span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-48 flex-1">
            <SearchIcon className="absolute top-1/2 left-2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              className="h-8 pl-7 text-xs"
              value={q}
              onChange={(e) => reset(() => setQ(e.target.value))}
              placeholder={t("filter.searchReflections")}
            />
          </div>
          <Select value={String(taskId)} onValueChange={(v) => reset(() => setTaskId(Number(v)))}>
            <SelectTrigger size="sm" className="h-8 w-40 text-xs">
              <SelectValue placeholder={t("filter.allTasks")} />
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
          {REFLECTION_KINDS.map((kind) => (
            <Button
              key={kind}
              size="sm"
              variant={kinds.includes(kind) ? "secondary" : "outline"}
              className="h-7 px-2 text-[11px]"
              aria-pressed={kinds.includes(kind)}
              onClick={() => toggleKind(kind)}
            >
              {kind}
            </Button>
          ))}
        </div>

        {/* Source and date narrow the pool; they sit behind a named disclosure
            so the default row stays scannable. */}
        <details className="group" open={Boolean(source || since) || undefined}>
          <summary className="flex w-fit cursor-pointer list-none items-center gap-1.5 text-[11px] text-muted-foreground hover:text-foreground">
            <ChevronRightIcon className="size-3 transition-transform group-open:rotate-90" />
            {t("filter.advanced")}
            {(source || since) && (
              <span className="border border-border px-1 text-[10px] text-foreground tabular-nums">
                {(source ? 1 : 0) + (since ? 1 : 0)}
              </span>
            )}
          </summary>
          <div className="flex flex-wrap items-center gap-2 pt-2">
            <Input
              className="h-8 w-28 text-xs"
              value={source}
              onChange={(e) => reset(() => setSource(e.target.value))}
              placeholder={t("column.source")}
            />
            <Input
              className="h-8 w-36 text-xs"
              type="date"
              value={since}
              onChange={(e) => reset(() => setSince(e.target.value))}
              title={t("filter.since")}
            />
          </div>
        </details>
      </div>

      <div className="min-h-[16rem] min-w-0 flex-1 overflow-auto">
        {loading && rows.length === 0 && (
          <div className="flex h-40 items-center justify-center">
            <Spinner />
          </div>
        )}
        {!loading && rows.length === 0 && (
          <p className="p-8 text-center text-muted-foreground text-sm">{t("reflections.empty")}</p>
        )}
        {!loading && rows.length > 0 && (
          // Fixed layout + min width: long summaries truncate instead of painting
          // over the kind/source columns, and narrow viewports scroll the table.
          <Table className="min-w-[40rem] table-fixed">
            <TableHeader>
              <TableRow>
                <TableHead className="w-14">{t("column.id")}</TableHead>
                <TableHead>{t("column.summary")}</TableHead>
                <TableHead className="w-20">{t("column.kind")}</TableHead>
                <TableHead className="w-24">{t("column.source")}</TableHead>
                <TableHead className="w-20">{t("column.task")}</TableHead>
                <TableHead className="w-32">{t("column.created")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((row) => (
                <TableRow key={row.id}>
                  <TableCell className="font-mono text-[11px] text-muted-foreground tabular-nums">#{row.id}</TableCell>
                  <TableCell className="overflow-hidden">
                    <button
                      type="button"
                      className="block w-full truncate text-left text-xs hover:underline"
                      onClick={() => setDetail(row)}
                    >
                      {row.summary}
                    </button>
                  </TableCell>
                  <TableCell className="overflow-hidden">
                    <Badge variant="outline" className="px-1.5 py-0 text-[10px]">
                      {row.kind}
                    </Badge>
                  </TableCell>
                  <TableCell className="overflow-hidden">
                    <span className="block truncate text-muted-foreground text-xs" title={row.source}>
                      {row.source}
                    </span>
                  </TableCell>
                  <TableCell className="text-[11px] text-muted-foreground">#{row.task_id}</TableCell>
                  <TableCell className="overflow-hidden">
                    <span className="block truncate text-[11px] text-muted-foreground tabular-nums">
                      {fmtDate(row.created_at)}
                    </span>
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
        <ReflectionDetail
          reflection={detail}
          onClose={() => setDetail(null)}
          onChanged={(next) => {
            setDetail(next);
            reload();
            loadStats();
          }}
        />
      )}
    </div>
  );
}
