"use client";

import * as React from "react";

import { GraduationCapIcon, Loader2Icon } from "lucide-react";
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
import { api } from "@/lib/api";
import type { KnowledgeEntry, KnowledgeKind, Reflection } from "@/lib/types";

import { splitTags } from "./memory-shared";

// Kinds a reflection may become. The reflection pool's own kinds (noise,
// lookfor, learning, mistake) are not knowledge kinds.
export const GRADUATE_KINDS: KnowledgeKind[] = ["technique", "tool", "opsec", "indicator", "lead", "note"];

export interface GraduatedEntry {
  entry: KnowledgeEntry;
  redactions: number;
}

// GraduateDialog turns a reflection into a task-scoped knowledge candidate.
// It deliberately stops there: graduating never publishes anything, and the
// copy says so, because the promotion that crosses the task boundary is the
// operator's separate action in the Knowledge tab.
export function GraduateDialog({
  reflection,
  open,
  onOpenChange,
  onGraduated,
}: {
  reflection: Reflection;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onGraduated: (result: GraduatedEntry) => void;
}) {
  const t = useTranslations("memoryPage");
  const [kind, setKind] = React.useState<KnowledgeKind>("technique");
  const [title, setTitle] = React.useState(reflection.summary);
  const [tags, setTags] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [done, setDone] = React.useState<GraduatedEntry | null>(null);

  React.useEffect(() => {
    if (!open) {
      setDone(null);
      setTitle(reflection.summary);
    }
  }, [open, reflection.summary]);

  async function graduate() {
    setBusy(true);
    try {
      const r = await api.graduateReflection(reflection.id, {
        kind,
        title: title.trim() || undefined,
        tags: splitTags(tags),
      });
      setDone(r);
      onGraduated(r);
    } catch (e) {
      toast.error(t("graduate.failed", { msg: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("graduate.title")}</DialogTitle>
          <DialogDescription>{t("graduate.step1", { task: reflection.task_id })}</DialogDescription>
        </DialogHeader>

        {done ? (
          <div data-testid="graduate-result" className="space-y-2">
            <p className="text-sm">{t("graduate.created", { id: done.entry.id })}</p>
            <p className="text-muted-foreground text-xs">{t("graduate.step2", { task: reflection.task_id })}</p>
            {done.redactions > 0 && (
              <p className="text-muted-foreground text-xs">{t("redactions", { count: done.redactions })}</p>
            )}
          </div>
        ) : (
          <div className="space-y-3">
            <p className="text-muted-foreground text-xs">{t("graduate.step2", { task: reflection.task_id })}</p>
            <div className="grid gap-1.5">
              <Label htmlFor="grad-title">{t("detail.title")}</Label>
              <Input id="grad-title" value={title} onChange={(e) => setTitle(e.target.value)} />
            </div>
            <div className="grid gap-1.5">
              <Label>{t("detail.kind")}</Label>
              <Select value={kind} onValueChange={(v) => setKind(v as KnowledgeKind)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {GRADUATE_KINDS.map((k) => (
                    <SelectItem key={k} value={k}>
                      {k}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="grad-tags">{t("detail.tags")}</Label>
              <Input
                id="grad-tags"
                value={tags}
                onChange={(e) => setTags(e.target.value)}
                placeholder={t("detail.tagsPlaceholder")}
              />
            </div>
          </div>
        )}

        <DialogFooter>
          {done ? (
            <Button size="sm" onClick={() => onOpenChange(false)}>
              {t("close")}
            </Button>
          ) : (
            <Button size="sm" onClick={() => void graduate()} disabled={busy || !title.trim()}>
              {busy && <Loader2Icon className="size-3.5 animate-spin" />}
              <GraduationCapIcon className="size-3.5" />
              {t("graduate.confirm")}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
