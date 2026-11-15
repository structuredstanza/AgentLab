"use client";

import * as React from "react";

import { useTranslations } from "next-intl";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
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
import { Textarea } from "@/components/ui/textarea";

export type IngestFields = { tool: string; repo: string; notes: string; install: boolean };

// composeIngestMessage turns the dialog fields into the one plain-English message
// the operator could have typed into the curator chat. Empty fields are left out.
export function composeIngestMessage({ tool, repo, notes, install }: IngestFields): string {
  const parts = [`Ingest the tool "${tool.trim()}".`];
  if (repo.trim()) parts.push(`Repository: ${repo.trim()}.`);
  if (install) parts.push("Install it if it is missing.");
  if (notes.trim()) parts.push(`Notes: ${notes.trim()}`);
  return parts.join(" ");
}

export function IngestToolDialog({
  open,
  onClose,
  onSubmit,
}: {
  open: boolean;
  onClose: () => void;
  onSubmit: (message: string) => void;
}) {
  const t = useTranslations("toolboxPage");
  const [tool, setTool] = React.useState("");
  const [repo, setRepo] = React.useState("");
  const [notes, setNotes] = React.useState("");
  const [install, setInstall] = React.useState(false);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!tool.trim()) return;
    onSubmit(composeIngestMessage({ tool, repo, notes, install }));
    setTool("");
    setRepo("");
    setNotes("");
    setInstall(false);
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <form onSubmit={submit} className="grid gap-3">
          <DialogHeader>
            <DialogTitle>{t("ingest.title")}</DialogTitle>
            <DialogDescription>{t("ingest.desc")}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-1.5">
            <Label htmlFor="ingest-tool">{t("ingest.tool")}</Label>
            <Input
              id="ingest-tool"
              required
              value={tool}
              onChange={(e) => setTool(e.target.value)}
              placeholder={t("ingest.toolPlaceholder")}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="ingest-repo">{t("ingest.repo")}</Label>
            <Input
              id="ingest-repo"
              value={repo}
              onChange={(e) => setRepo(e.target.value)}
              placeholder="https://github.com/..."
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="ingest-notes">{t("ingest.notes")}</Label>
            <Textarea
              id="ingest-notes"
              rows={5}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder={t("ingest.notesPlaceholder")}
            />
          </div>
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={install} onCheckedChange={(v) => setInstall(v === true)} />
            {t("ingest.install")}
          </label>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t("ingest.cancel")}
            </Button>
            <Button type="submit" disabled={!tool.trim()}>
              {t("ingest.submit")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
