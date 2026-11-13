"use client";

import * as React from "react";

import { useTranslations } from "next-intl";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";

import { MemoryCandidatesWarning } from "./memory-candidates-warning";

// The evidence gate is the only archive refusal an operator may override, so
// every archive path surfaces it as this error and the dialog offers the retry.
export class ArchiveEvidenceGateError extends Error {}

// ArchiveConfirmDialog is the one archive confirmation: it names the memory
// candidates the archive strands, and when the evidence gate refuses it shows
// the offending findings and retries with force.
export function ArchiveConfirmDialog({
  taskIds,
  trigger,
  onConfirm,
}: {
  taskIds: string[];
  trigger: React.ReactNode;
  onConfirm: (force: boolean) => Promise<void>;
}) {
  const t = useTranslations("tasksPage");
  const [open, setOpen] = React.useState(false);
  const [pending, setPending] = React.useState(false);
  const [blocked, setBlocked] = React.useState("");
  const count = taskIds.length;

  const run = async (force: boolean) => {
    setPending(true);
    setBlocked("");
    try {
      await onConfirm(force);
      setBlocked("");
      setOpen(false);
    } catch (error) {
      // Every other failure already produced its own toast.
      if (error instanceof ArchiveEvidenceGateError) setBlocked(error.message);
    } finally {
      setPending(false);
    }
  };

  return (
    <AlertDialog
      open={open}
      onOpenChange={(next) => {
        if (pending) return;
        setOpen(next);
        if (!next) setBlocked("");
      }}
    >
      <AlertDialogTrigger asChild>{trigger}</AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{t("archiveDialog.title", { count })}</AlertDialogTitle>
          <AlertDialogDescription className="[overflow-wrap:anywhere]">
            {t("archiveDialog.description")}
          </AlertDialogDescription>
          <MemoryCandidatesWarning taskIds={taskIds} mode="archive" />
        </AlertDialogHeader>
        {blocked && (
          <div className="space-y-2">
            <p className="whitespace-pre-line text-[11px] text-destructive [overflow-wrap:anywhere]">{blocked}</p>
            <Button size="sm" variant="outline" disabled={pending} onClick={() => void run(true)}>
              {t("archiveDialog.force")}
            </Button>
          </div>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel disabled={pending}>{t("archiveDialog.cancel")}</AlertDialogCancel>
          <AlertDialogAction
            disabled={pending}
            onClick={(event) => {
              event.preventDefault();
              void run(false);
            }}
          >
            {pending && <Spinner data-icon="inline-start" />}
            {t("archiveDialog.confirm")}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
