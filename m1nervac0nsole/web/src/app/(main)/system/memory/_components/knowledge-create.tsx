"use client";

import * as React from "react";

import { Loader2Icon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { Company, KnowledgeEntry, KnowledgeKind, KnowledgeScope, Task } from "@/lib/types";

import { KNOWLEDGE_KINDS, KNOWLEDGE_SCOPES } from "./knowledge-detail";
import { splitTags } from "./memory-shared";

// CreateKnowledgeDialog writes an operator entry. The dry run renders the
// scrubber's work without writing, so the operator sees which identifiers get
// generalised before committing.
export function CreateKnowledgeDialog({
  open,
  tasks,
  companies,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  tasks: Task[];
  companies: Company[];
  onOpenChange: (open: boolean) => void;
  onCreated: () => void;
}) {
  const t = useTranslations("memoryPage");
  const [scope, setScope] = React.useState<KnowledgeScope>("global");
  const [companyId, setCompanyId] = React.useState(0);
  const [taskId, setTaskId] = React.useState(0);
  const [kind, setKind] = React.useState<KnowledgeKind>("technique");
  const [title, setTitle] = React.useState("");
  const [body, setBody] = React.useState("");
  const [tags, setTags] = React.useState("");
  const [preview, setPreview] = React.useState<{ entry: KnowledgeEntry; redactions: number } | null>(null);
  const [busy, setBusy] = React.useState(false);

  const input = () => ({
    scope,
    company_id: scope === "company" ? companyId : undefined,
    task_id: scope === "task" ? taskId : undefined,
    kind,
    title: title.trim(),
    body,
    tags: splitTags(tags),
  });
  const invalid = !title.trim() || (scope === "company" && companyId <= 0) || (scope === "task" && taskId <= 0);

  async function dryRun() {
    setBusy(true);
    try {
      setPreview(await api.createKnowledge(input(), true));
    } catch (e) {
      toast.error(t("createFailed", { msg: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  }

  async function create() {
    setBusy(true);
    try {
      const r = await api.createKnowledge(input());
      toast.success(r.redactions > 0 ? t("redactions", { count: r.redactions }) : t("saved"));
      onOpenChange(false);
      onCreated();
    } catch (e) {
      toast.error(t("createFailed", { msg: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("create.title")}</DialogTitle>
          <DialogDescription>{t("create.desc")}</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-2">
            <div className="grid gap-1.5">
              <Label>{t("filter.scope")}</Label>
              <Select value={scope} onValueChange={(v) => setScope(v as KnowledgeScope)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {KNOWLEDGE_SCOPES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
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
          </div>
          {scope === "company" && (
            <Select value={String(companyId)} onValueChange={(v) => setCompanyId(Number(v))}>
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
          {scope === "task" && (
            <Select value={String(taskId)} onValueChange={(v) => setTaskId(Number(v))}>
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
          )}
          <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder={t("detail.title")} />
          <Textarea
            className="min-h-32 resize-y font-mono text-xs leading-relaxed"
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder={t("detail.body")}
          />
          <Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder={t("detail.tagsPlaceholder")} />
          {preview && (
            <div data-testid="dry-run-preview" className="space-y-1 rounded-md border bg-muted/40 p-3 text-xs">
              <p className="font-medium">{t("create.previewRedactions", { count: preview.redactions })}</p>
              <p className="break-words">{preview.entry.title}</p>
              <pre className="max-h-32 overflow-auto whitespace-pre-wrap break-words font-mono text-[11px]">
                {preview.entry.body}
              </pre>
            </div>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" size="sm" onClick={() => void dryRun()} disabled={busy || invalid}>
            {t("create.preview")}
          </Button>
          <Button size="sm" onClick={() => void create()} disabled={busy || invalid}>
            {busy && <Loader2Icon className="size-3.5 animate-spin" />}
            {t("create.confirm")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
