"use client";

import * as React from "react";

import { Loader2Icon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { getDateLocale } from "@/i18n/datetime";
import { api } from "@/lib/api";
import type {
  Company,
  KnowledgeEntry,
  KnowledgeKind,
  KnowledgeScope,
  KnowledgeStatus,
  KnowledgeUsage,
  Task,
} from "@/lib/types";

import { StatusBadge, splitTags, surfaceLabel, UsageCell } from "./memory-shared";

export const KNOWLEDGE_KINDS: KnowledgeKind[] = ["technique", "tool", "opsec", "indicator", "playbook", "lead", "note"];
export const KNOWLEDGE_SCOPES: KnowledgeScope[] = ["global", "environment", "company", "task"];
export const KNOWLEDGE_STATUSES: KnowledgeStatus[] = ["candidate", "adopted", "retired"];

function fmtTime(ts: string | undefined, never: string): string {
  if (!ts) return never;
  return new Date(ts).toLocaleString(getDateLocale(), {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// KnowledgeDetail is the entry view: full body, metadata, tags, usage, inline
// edit and the lifecycle actions. Edits overwrite in place - the backend keeps
// no revision history, so nothing here implies one.
export function KnowledgeDetail({
  entry,
  tasks,
  companies,
  onClose,
  onChanged,
}: {
  entry: KnowledgeEntry;
  tasks: Task[];
  companies: Company[];
  onClose: () => void;
  onChanged: (entry: KnowledgeEntry | null) => void;
}) {
  const t = useTranslations("memoryPage");
  const [title, setTitle] = React.useState(entry.title);
  const [body, setBody] = React.useState(entry.body);
  const [kind, setKind] = React.useState<KnowledgeKind>(entry.kind);
  const [status, setStatus] = React.useState<KnowledgeStatus>(entry.status);
  const [tags, setTags] = React.useState(entry.tags.join(", "));
  const [saving, setSaving] = React.useState(false);
  const [usage, setUsage] = React.useState<KnowledgeUsage | null>(null);
  const [usageLoading, setUsageLoading] = React.useState(false);
  const [promoteOpen, setPromoteOpen] = React.useState(false);
  const [promoteScope, setPromoteScope] = React.useState<"company" | "environment" | "global">("global");
  const [promoteCompany, setPromoteCompany] = React.useState(0);
  const [demoteOpen, setDemoteOpen] = React.useState(false);
  const [demoteTask, setDemoteTask] = React.useState(0);
  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    setTitle(entry.title);
    setBody(entry.body);
    setKind(entry.kind);
    setStatus(entry.status);
    setTags(entry.tags.join(", "));
  }, [entry]);

  const loadUsage = React.useCallback(() => {
    setUsageLoading(true);
    api
      .knowledgeUsage(entry.id, 20)
      .then(setUsage)
      .catch(() => {
        /* usage is advisory; a failure leaves the column as "load" */
      })
      .finally(() => setUsageLoading(false));
  }, [entry.id]);

  async function save() {
    setSaving(true);
    try {
      const r = await api.patchKnowledge(entry.id, {
        title: title.trim(),
        body,
        kind,
        status,
        tags: splitTags(tags),
      });
      toast.success(r.redactions > 0 ? t("redactions", { count: r.redactions }) : t("saved"));
      onChanged(r.entry);
    } catch (e) {
      toast.error(t("saveFailed", { msg: (e as Error).message }));
    } finally {
      setSaving(false);
    }
  }

  async function promote() {
    if (promoteScope === "company" && promoteCompany <= 0) return;
    setBusy(true);
    try {
      const r = await api.promoteKnowledge(entry.id, promoteScope, promoteCompany);
      toast.success(r.redactions > 0 ? t("redactions", { count: r.redactions }) : t("saved"));
      setPromoteOpen(false);
      onChanged(r.entry);
    } catch (e) {
      toast.error(t("promoteFailed", { msg: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  }

  async function demote() {
    if (demoteTask <= 0) return;
    setBusy(true);
    try {
      const r = await api.demoteKnowledge(entry.id, demoteTask);
      toast.success(t("demoted"));
      setDemoteOpen(false);
      onChanged(r.entry);
    } catch (e) {
      toast.error(t("demoteFailed", { msg: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  }

  async function retire() {
    setBusy(true);
    try {
      const r = await api.patchKnowledge(entry.id, { status: "retired" });
      toast.success(r.redactions > 0 ? t("redactions", { count: r.redactions }) : t("saved"));
      onChanged(r.entry);
    } catch (e) {
      toast.error(t("saveFailed", { msg: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setBusy(true);
    try {
      await api.deleteKnowledge(entry.id);
      toast.success(t("deleted"));
      setDeleteOpen(false);
      onChanged(null);
    } catch (e) {
      toast.error(t("deleteFailed", { msg: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  }

  const taskLabel = (id?: number) => {
    if (!id) return "-";
    const task = tasks.find((x) => Number(x.id) === id);
    return task ? task.name || task.description || `#${id}` : `#${id}`;
  };

  return (
    <Sheet open onOpenChange={(open) => !open && onClose()}>
      <SheetContent side="right" className="flex w-full flex-col gap-0 sm:max-w-xl">
        <SheetHeader className="border-b">
          <SheetTitle className="pr-6 text-sm leading-snug">{entry.title}</SheetTitle>
          <SheetDescription className="flex flex-wrap items-center gap-1.5">
            <Badge variant="outline" className="px-1.5 py-0 text-[10px]">
              {entry.scope}
            </Badge>
            <Badge variant="outline" className="px-1.5 py-0 text-[10px]">
              {entry.kind}
            </Badge>
            <StatusBadge status={entry.status} />
            <span className="text-[11px]">
              {t("detail.source")}: {entry.source}
            </span>
            <span className="text-[11px]">
              {t("detail.originTask")}: {taskLabel(entry.origin_task_id)}
            </span>
            {entry.company_id ? (
              <span className="text-[11px]">
                {t("detail.company")}:{" "}
                {companies.find((c) => c.id === entry.company_id)?.name ?? `#${entry.company_id}`}
              </span>
            ) : null}
            <span className="text-[11px]">{t("detail.updated", { time: fmtTime(entry.updated_at, "-") })}</span>
          </SheetDescription>
        </SheetHeader>

        <ScrollArea className="min-h-0 flex-1">
          <div className="space-y-5 px-4 pb-6">
            <section className="space-y-1.5">
              <Label className="text-muted-foreground text-xs">{t("detail.body")}</Label>
              <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-md border bg-muted/40 p-3 font-sans text-xs leading-relaxed">
                {entry.body || t("detail.emptyBody")}
              </pre>
              <div className="flex flex-wrap gap-1">
                {entry.tags.map((tag) => (
                  <Badge key={tag} variant="secondary" className="px-1.5 py-0 font-normal text-[10px]">
                    {tag}
                  </Badge>
                ))}
              </div>
            </section>

            <section className="space-y-2">
              <div className="flex items-center justify-between">
                <Label className="text-muted-foreground text-xs">{t("usage.title")}</Label>
                <span className="text-[11px] text-muted-foreground">{t("usage.hint")}</span>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <UsageCell usage={usage ?? undefined} loading={usageLoading} onLoad={loadUsage} />
                {usage?.last_used && (
                  <span className="text-muted-foreground">
                    {t("usage.lastUsed", { time: fmtTime(usage.last_used, "-") })}
                  </span>
                )}
              </div>
              {usage && usage.usage.length > 0 && (
                <ul className="space-y-0.5 text-[11px] text-muted-foreground">
                  {usage.usage.map((row) => (
                    <li key={`${row.task_id}:${row.surface}:${row.shown_at}`} className="flex gap-2">
                      <span className="font-mono">#{row.task_id}</span>
                      <span>{surfaceLabel(t, row.surface)}</span>
                      <span className="ml-auto tabular-nums">{fmtTime(row.shown_at, "-")}</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <Separator />

            <section className="space-y-3">
              <div className="flex items-baseline justify-between">
                <Label className="text-muted-foreground text-xs">{t("detail.edit")}</Label>
                <span className="text-[11px] text-muted-foreground">{t("detail.editHint")}</span>
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="kb-title">{t("detail.title")}</Label>
                <Input id="kb-title" value={title} onChange={(e) => setTitle(e.target.value)} />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="kb-body">{t("detail.body")}</Label>
                <Textarea
                  id="kb-body"
                  className="min-h-40 resize-y font-mono text-xs leading-relaxed"
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div className="grid gap-1.5">
                  <Label>{t("detail.kind")}</Label>
                  <Select value={kind} onValueChange={(v) => setKind(v as KnowledgeKind)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {KNOWLEDGE_KINDS.map((k) => (
                        <SelectItem key={k} value={k}>
                          {k}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid gap-1.5">
                  <Label>{t("detail.status")}</Label>
                  <Select value={status} onValueChange={(v) => setStatus(v as KnowledgeStatus)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {KNOWLEDGE_STATUSES.filter((s) => !(entry.scope === "task" && s === "adopted")).map((s) => (
                        <SelectItem key={s} value={s}>
                          {s}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="kb-tags">{t("detail.tags")}</Label>
                <Input
                  id="kb-tags"
                  value={tags}
                  onChange={(e) => setTags(e.target.value)}
                  placeholder={t("detail.tagsPlaceholder")}
                />
              </div>
              <Button size="sm" onClick={() => void save()} disabled={saving || !title.trim()}>
                {saving && <Loader2Icon className="size-3.5 animate-spin" />}
                {t("detail.save")}
              </Button>
            </section>
          </div>
        </ScrollArea>

        <div className="flex flex-wrap items-center gap-2 border-t p-3">
          <Button size="sm" variant="outline" onClick={() => setPromoteOpen(true)} disabled={entry.scope === "global"}>
            {t("detail.promote")}
          </Button>
          <Button size="sm" variant="outline" onClick={() => setDemoteOpen(true)} disabled={entry.scope === "task"}>
            {t("detail.demote")}
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => void retire()}
            disabled={entry.status === "retired" || busy}
          >
            {t("detail.retire")}
          </Button>
          <Button size="sm" variant="destructive" className="ml-auto" onClick={() => setDeleteOpen(true)}>
            {t("detail.delete")}
          </Button>
        </div>

        <AlertDialog open={promoteOpen} onOpenChange={setPromoteOpen}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>{t("promote.title")}</AlertDialogTitle>
              <AlertDialogDescription>{t("promote.desc")}</AlertDialogDescription>
            </AlertDialogHeader>
            <div className="space-y-2">
              <Select value={promoteScope} onValueChange={(v) => setPromoteScope(v as typeof promoteScope)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="global">global</SelectItem>
                  <SelectItem value="environment">environment</SelectItem>
                  <SelectItem value="company">company</SelectItem>
                </SelectContent>
              </Select>
              {promoteScope === "company" && (
                <Select value={String(promoteCompany)} onValueChange={(v) => setPromoteCompany(Number(v))}>
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
                  void promote();
                }}
                disabled={busy || (promoteScope === "company" && promoteCompany <= 0)}
              >
                {t("promote.confirm")}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>

        <AlertDialog open={demoteOpen} onOpenChange={setDemoteOpen}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>{t("demote.title")}</AlertDialogTitle>
              <AlertDialogDescription>{t("demote.desc")}</AlertDialogDescription>
            </AlertDialogHeader>
            <Select value={String(demoteTask)} onValueChange={(v) => setDemoteTask(Number(v))}>
              <SelectTrigger>
                <SelectValue placeholder={t("demote.taskPlaceholder")} />
              </SelectTrigger>
              <SelectContent>
                {tasks.map((task) => (
                  <SelectItem key={task.id} value={task.id}>
                    {task.name || task.description || `#${task.id}`}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <AlertDialogFooter>
              <AlertDialogCancel>{t("cancel")}</AlertDialogCancel>
              <AlertDialogAction
                onClick={(e) => {
                  e.preventDefault();
                  void demote();
                }}
                disabled={busy || demoteTask <= 0}
              >
                {t("demote.confirm")}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>

        <AlertDialog open={deleteOpen} onOpenChange={setDeleteOpen}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>{t("delete.title")}</AlertDialogTitle>
              <AlertDialogDescription>{t("delete.desc")}</AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>{t("cancel")}</AlertDialogCancel>
              <AlertDialogAction
                onClick={(e) => {
                  e.preventDefault();
                  void remove();
                }}
                disabled={busy}
              >
                {t("delete.confirm")}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </SheetContent>
    </Sheet>
  );
}
