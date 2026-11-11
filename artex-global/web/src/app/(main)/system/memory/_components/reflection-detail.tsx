"use client";

import * as React from "react";

import { GraduationCapIcon, Trash2Icon } from "lucide-react";
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
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { getDateLocale } from "@/i18n/datetime";
import { api } from "@/lib/api";
import type { Reflection } from "@/lib/types";

import { GraduateDialog } from "./graduate-dialog";

function fmtDate(ts: string): string {
  return new Date(ts).toLocaleString(getDateLocale(), {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ReflectionDetail edits a pool row in place, or hands it to the graduate
// dialog. The footer repeats the promotion step so a graduated candidate is
// not mistaken for published knowledge.
export function ReflectionDetail({
  reflection,
  onClose,
  onChanged,
}: {
  reflection: Reflection;
  onClose: () => void;
  onChanged: (reflection: Reflection | null) => void;
}) {
  const t = useTranslations("memoryPage");
  const [summary, setSummary] = React.useState(reflection.summary);
  const [detail, setDetail] = React.useState(reflection.detail);
  const [saving, setSaving] = React.useState(false);
  const [graduateOpen, setGraduateOpen] = React.useState(false);
  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    setSummary(reflection.summary);
    setDetail(reflection.detail);
  }, [reflection]);

  async function save() {
    setSaving(true);
    try {
      const r = await api.patchReflection(reflection.id, { summary: summary.trim(), detail });
      toast.success(t("saved"));
      onChanged(r.reflection);
    } catch (e) {
      toast.error(t("saveFailed", { msg: (e as Error).message }));
    } finally {
      setSaving(false);
    }
  }

  async function remove() {
    setBusy(true);
    try {
      await api.deleteReflection(reflection.id);
      toast.success(t("deleted"));
      setDeleteOpen(false);
      onChanged(null);
    } catch (e) {
      toast.error(t("deleteFailed", { msg: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Sheet open onOpenChange={(open) => !open && onClose()}>
      <SheetContent side="right" className="flex w-full flex-col gap-0 sm:max-w-xl">
        <SheetHeader className="border-b">
          <SheetTitle className="pr-6 text-sm leading-snug">{reflection.summary}</SheetTitle>
          <SheetDescription className="flex flex-wrap items-center gap-1.5">
            <Badge variant="outline" className="px-1.5 py-0 text-[10px]">
              {reflection.kind}
            </Badge>
            <span className="text-[11px]">
              {t("column.source")}: {reflection.source}
            </span>
            <span className="text-[11px]">
              {t("column.task")}: #{reflection.task_id}
            </span>
            <span className="text-[11px]">{fmtDate(reflection.created_at)}</span>
          </SheetDescription>
        </SheetHeader>

        <ScrollArea className="min-h-0 flex-1">
          <div className="space-y-5 px-4 pb-6">
            <section className="space-y-1.5">
              <Label className="text-muted-foreground text-xs">{t("detail.body")}</Label>
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-md border bg-muted/40 p-3 font-sans text-xs leading-relaxed">
                {reflection.detail || t("detail.emptyBody")}
              </pre>
            </section>

            <section className="space-y-3">
              <div className="flex items-baseline justify-between">
                <Label className="text-muted-foreground text-xs">{t("detail.edit")}</Label>
                <span className="text-[11px] text-muted-foreground">{t("detail.editHint")}</span>
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="rf-summary">{t("detail.title")}</Label>
                <Input id="rf-summary" value={summary} onChange={(e) => setSummary(e.target.value)} />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="rf-detail">{t("detail.body")}</Label>
                <Textarea
                  id="rf-detail"
                  className="min-h-40 resize-y font-mono text-xs leading-relaxed"
                  value={detail}
                  onChange={(e) => setDetail(e.target.value)}
                />
              </div>
              <Button size="sm" onClick={() => void save()} disabled={saving || !summary.trim()}>
                {t("detail.save")}
              </Button>
            </section>

            <p className="rounded-md border border-dashed p-2 text-[11px] text-muted-foreground">
              {t("graduate.step2", { task: reflection.task_id })}
            </p>
          </div>
        </ScrollArea>

        <div className="flex flex-wrap items-center gap-2 border-t p-3">
          <Button size="sm" variant="outline" onClick={() => setGraduateOpen(true)}>
            <GraduationCapIcon className="size-3.5" />
            {t("graduate.action")}
          </Button>
          <Button size="sm" variant="destructive" className="ml-auto" onClick={() => setDeleteOpen(true)}>
            <Trash2Icon className="size-3.5" />
            {t("detail.delete")}
          </Button>
        </div>

        <GraduateDialog
          reflection={reflection}
          open={graduateOpen}
          onOpenChange={setGraduateOpen}
          onGraduated={() => {
            /* the candidate lives in the Knowledge tab; the pool row is unchanged */
          }}
        />

        <AlertDialog open={deleteOpen} onOpenChange={setDeleteOpen}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>{t("delete.title")}</AlertDialogTitle>
              <AlertDialogDescription>{t("reflectionDelete.desc")}</AlertDialogDescription>
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
