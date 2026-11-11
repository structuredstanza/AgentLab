"use client";

import * as React from "react";

import { SearchIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { TablePagination } from "@/components/table-pagination";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
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
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="space-y-2 border-b px-4 py-3 lg:px-6">
        <div className="flex flex-wrap items-center gap-2">
          <Card size="sm" className="gap-1">
            <CardContent>
              <p className="text-muted-foreground text-xs">{t("stats.reflections")}</p>
              <p className="font-semibold text-lg tabular-nums">{stats?.total ?? 0}</p>
            </CardContent>
          </Card>
          <div className="flex flex-wrap gap-1">
            {Object.entries(stats?.by_kind ?? {}).map(([kind, count]) => (
              <Badge key={kind} variant="secondary" className="px-1.5 py-0 font-normal text-[10px]">
                {kind} {count}
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
          {REFLECTION_KINDS.map((kind) => (
            <Button
              key={kind}
              size="sm"
              variant={kinds.includes(kind) ? "default" : "outline"}
              className="h-7 px-2 text-[11px]"
              aria-pressed={kinds.includes(kind)}
              onClick={() => toggleKind(kind)}
            >
              {kind}
            </Button>
          ))}
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        {loading && rows.length === 0 && (
          <div className="flex h-40 items-center justify-center">
            <Spinner />
          </div>
        )}
        {!loading && rows.length === 0 && (
          <p className="p-8 text-center text-muted-foreground text-sm">{t("reflections.empty")}</p>
        )}
        {!loading && rows.length > 0 && (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("column.summary")}</TableHead>
                <TableHead className="w-24">{t("column.kind")}</TableHead>
                <TableHead className="w-24">{t("column.source")}</TableHead>
                <TableHead className="w-24">{t("column.task")}</TableHead>
                <TableHead className="w-28">{t("column.created")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((row) => (
                <TableRow key={row.id}>
                  <TableCell className="max-w-0">
                    <button
                      type="button"
                      className="min-w-0 truncate text-left text-xs hover:underline"
                      onClick={() => setDetail(row)}
                    >
                      {row.summary}
                    </button>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="px-1.5 py-0 text-[10px]">
                      {row.kind}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-muted-foreground text-xs">{row.source}</TableCell>
                  <TableCell className="text-[11px] text-muted-foreground">#{row.task_id}</TableCell>
                  <TableCell className="text-[11px] text-muted-foreground tabular-nums">
                    {fmtDate(row.created_at)}
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
