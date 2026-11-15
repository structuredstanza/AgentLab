"use client";

import * as React from "react";

import { DownloadIcon, Loader2Icon, RotateCcwIcon, SaveIcon, Trash2Icon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { getDateLocale } from "@/i18n/datetime";
import { api, type ToolInstallResult } from "@/lib/api";
import type { ToolManifest, ToolPreview } from "@/lib/types";

// formatCommand is what the operator reads: the argv exactly as the executor
// builds it, quoted only where a shell would need it.
export function formatCommand(program: string, args: string[]): string {
  const quote = (a: string) => (/^[A-Za-z0-9_./:=@%+,-]+$/.test(a) ? a : `'${a.replace(/'/g, "'\\''")}'`);
  return [program, ...args].map(quote).join(" ");
}

// PROVENANCE_PREFIX is the comment marker the curator writes into a stored
// template (server: provenancePrefix). The block is part of the TOML, so this
// sheet can show what was verified without another API field.
const PROVENANCE_PREFIX = "# provenance: ";

// provenanceLines reads the curator's verification block out of a template.
export function provenanceLines(toml: string): string[] {
  return toml
    .split("\n")
    .filter((line) => line.startsWith(PROVENANCE_PREFIX))
    .map((line) => line.slice(PROVENANCE_PREFIX.length).trim())
    .filter(Boolean);
}

// STARTER_TOML is the smallest manifest the server accepts, so "New template"
// begins from something that saves and the operator edits from there.
const STARTER_TOML = `id = "my-tool"
name = "My tool"
description = "What it does and when an agent should pick it"
category = "recon"
accepts = ["domain", "ip"]
requires = ["my-tool"]

[params]
mode = { type = "enum", label = "Mode", default = "fast", options = ["fast", "full"] }

[command]
program = "my-tool"
args = ["--mode", "{{ params.mode }}", "{{ target.value }}"]
timeout_seconds = 120

[emit]
parser = "lines"
fields = ["value"]

[[emit.facts]]
kind = "output"
data = { value = "{{ record.value }}" }
`;

// fmtSize is the published binary's size in the unit an operator reads.
function fmtSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function fmtTime(ts: string): string {
  return new Date(ts).toLocaleString(getDateLocale(), {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

const SOURCE_KEY = {
  builtin: "sourceBuiltin",
  modified: "sourceModified",
  custom: "sourceCustom",
} as const;

// TemplateCard is one manifest tile in the catalog grid.
export function TemplateCard({ manifest, onClick }: { manifest: ToolManifest; onClick: () => void }) {
  const t = useTranslations("toolboxPage");
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex flex-col gap-2 border border-border p-3 text-left transition-colors hover:border-primary/50 hover:bg-muted/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium font-mono text-sm">{manifest.id}</span>
        <Badge variant={manifest.source === "builtin" ? "secondary" : "outline"} className="px-1.5 py-0 text-[10px]">
          {t(SOURCE_KEY[manifest.source])}
        </Badge>
        {!manifest.available && (
          <Badge variant="outline" className="px-1.5 py-0 text-[10px] text-destructive">
            {t("notInstalled")}
          </Badge>
        )}
        <Badge variant="secondary" className="ml-auto px-1.5 py-0 text-[10px]">
          {manifest.category}
        </Badge>
      </div>
      <p className="line-clamp-2 text-muted-foreground text-xs">{manifest.description}</p>
      {manifest.artifact && (
        <div className="grid gap-0.5 border-border border-t pt-1.5 font-mono text-[10px] text-muted-foreground">
          <span className="break-all">{manifest.artifact.path}</span>
          <span className="break-all">sha256 {manifest.artifact.sha256}</span>
          <span>
            {fmtSize(manifest.artifact.size)} · {fmtTime(manifest.artifact.installed_at)}
          </span>
        </div>
      )}
    </button>
  );
}

// TemplateBody holds the editor state; it is keyed by template id so switching
// templates never carries a parameter or TOML buffer over to the next one.
function TemplateBody({
  manifest,
  onClose,
  onChanged,
}: {
  manifest: ToolManifest | null;
  onClose: () => void;
  onChanged: () => void;
}) {
  const t = useTranslations("toolboxPage");
  const [toml, setToml] = React.useState(manifest?.toml ?? STARTER_TOML);
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [installResult, setInstallResult] = React.useState<ToolInstallResult | null>(null);
  const [target, setTarget] = React.useState("");
  const [params, setParams] = React.useState<Record<string, string>>({});
  const [preview, setPreview] = React.useState<ToolPreview | null>(null);
  const [previewError, setPreviewError] = React.useState("");
  const [previewing, setPreviewing] = React.useState(false);
  // Read from the editor buffer, so provenance the operator is about to save is
  // visible before it is stored.
  const provenance = React.useMemo(() => provenanceLines(toml), [toml]);

  React.useEffect(() => {
    if (!manifest || !target.trim()) {
      setPreview(null);
      setPreviewError("");
      return;
    }
    // Debounce: a keystroke in the target or a parameter should not race.
    const handle = setTimeout(() => {
      setPreviewing(true);
      api
        .previewTool(manifest.id, target.trim(), params)
        .then((p) => {
          setPreview(p);
          setPreviewError("");
        })
        .catch((e: Error) => {
          setPreview(null);
          setPreviewError(e.message);
        })
        .finally(() => setPreviewing(false));
    }, 250);
    return () => clearTimeout(handle);
  }, [manifest, target, params]);

  // run wraps one mutation: the server's validation message is shown verbatim next
  // to the editor, because it names the offending field and a toast would vanish.
  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const save = () =>
    run(async () => {
      const { id } = await api.saveToolManifest(toml);
      toast.success(t("templateSaved", { id }));
      onChanged();
      onClose();
    });
  const remove = () =>
    run(async () => {
      if (!manifest) return;
      await api.deleteToolManifest(manifest.id);
      toast.success(manifest.source === "modified" ? t("templateReset", { id: manifest.id }) : t("templateDeleted"));
      onChanged();
      onClose();
    });
  const install = () =>
    run(async () => {
      if (!manifest) return;
      const r = await api.installToolManifest(manifest.id);
      setInstallResult(r);
      onChanged();
    });

  // What the last install proved, so a failed or unproven install never reads as
  // a finished one.
  let installVerdict = "";
  if (installResult) {
    if (installResult.is_error) installVerdict = t("installFailed");
    else if (installResult.available) installVerdict = t("installVerified");
    else installVerdict = t("installUnverified");
  }

  // The published file the server reports: from the install just run, or from
  // the catalog row once the page has reloaded.
  const artifact = installResult?.artifact ?? manifest?.artifact ?? null;

  return (
    <>
      <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4 pb-4">
        {manifest && (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant={manifest.source === "builtin" ? "secondary" : "outline"}>
                {t(SOURCE_KEY[manifest.source])}
              </Badge>
              <Badge variant="secondary">{manifest.category}</Badge>
              {!manifest.available && (
                <Badge variant="outline" className="text-destructive">
                  {t("notInstalled")}
                </Badge>
              )}
              <span className="text-muted-foreground text-xs">
                {t("accepts", { kinds: manifest.accepts.join(", ") })}
              </span>
            </div>
            <p className="text-muted-foreground text-sm">{manifest.description}</p>

            <div className="grid gap-1">
              <Label className="text-xs">{t("provenanceLabel")}</Label>
              {provenance.length === 0 ? (
                <p className="text-muted-foreground text-xs">{t("provenanceNone")}</p>
              ) : (
                <ul className="list-disc pl-4 text-xs">
                  {provenance.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              )}
            </div>

            {artifact && (
              <div className="grid gap-1 border border-border bg-muted/30 p-2">
                <div className="flex flex-wrap items-center gap-2">
                  <Label className="text-xs">{t("artifactLabel")}</Label>
                  <Badge variant="secondary" className="px-1.5 py-0 text-[10px]">
                    {fmtSize(artifact.size)}
                  </Badge>
                  <span className="text-muted-foreground text-xs">{fmtTime(artifact.installed_at)}</span>
                </div>
                <code className="wrap-anywhere font-mono text-xs">{artifact.path}</code>
                <code className="wrap-anywhere font-mono text-muted-foreground text-xs">sha256 {artifact.sha256}</code>
              </div>
            )}

            <div className="grid gap-1.5">
              <Label className="text-xs">{t("target")}</Label>
              <Input
                aria-label={t("target")}
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={t("targetPlaceholder")}
              />
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              {Object.entries(manifest.params).map(([name, p]) => (
                <div key={name} className="grid gap-1.5 text-sm">
                  <span className="flex items-center gap-1">
                    <code className="font-mono text-xs">{name}</code>
                    {p.default !== undefined && (
                      <span className="text-muted-foreground text-xs">{t("default", { value: p.default })}</span>
                    )}
                  </span>
                  {p.type === "enum" ? (
                    <Select
                      value={params[name] ?? p.default ?? ""}
                      onValueChange={(v) => setParams((prev) => ({ ...prev, [name]: v }))}
                    >
                      <SelectTrigger aria-label={name} className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {(p.options ?? []).map((o) => (
                          <SelectItem key={o} value={o}>
                            {o}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  ) : p.type === "bool" ? (
                    <label className="flex items-center gap-2 text-sm">
                      <Checkbox
                        aria-label={name}
                        checked={(params[name] ?? p.default ?? "false") === "true"}
                        onCheckedChange={(v) => setParams((prev) => ({ ...prev, [name]: v ? "true" : "false" }))}
                      />
                      <span className="text-muted-foreground text-xs">{p.description}</span>
                    </label>
                  ) : (
                    <Input
                      aria-label={name}
                      value={params[name] ?? ""}
                      placeholder={p.placeholder ?? p.default ?? ""}
                      onChange={(e) => setParams((prev) => ({ ...prev, [name]: e.target.value }))}
                    />
                  )}
                </div>
              ))}
            </div>

            <div className="border border-border bg-muted/30 p-3">
              <div className="mb-1 flex items-center gap-2 text-muted-foreground text-xs">
                {t("preview")}
                {previewing && <Loader2Icon className="size-3 animate-spin" />}
              </div>
              {previewError ? (
                <p className="text-destructive text-sm">{previewError}</p>
              ) : preview ? (
                <pre className="wrap-anywhere font-mono text-xs">{formatCommand(preview.program, preview.args)}</pre>
              ) : (
                <p className="text-muted-foreground text-sm">{t("previewHint")}</p>
              )}
            </div>
          </>
        )}

        <div className="grid gap-1.5">
          <Label className="text-xs">{t("tomlLabel")}</Label>
          <Textarea
            aria-label={t("tomlLabel")}
            className="font-mono text-xs"
            rows={18}
            spellCheck={false}
            value={toml}
            onChange={(e) => setToml(e.target.value)}
          />
          {error && (
            <p role="alert" className="whitespace-pre-wrap break-words font-mono text-destructive text-xs">
              {error}
            </p>
          )}
        </div>

        {installResult && (
          <div className="grid gap-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <Label className="text-xs">{t("installOutput")}</Label>
              <Badge
                variant="outline"
                className={installResult.is_error || !installResult.available ? "text-destructive" : undefined}
              >
                {installVerdict}
              </Badge>
            </div>
            {!installResult.is_error && !installResult.available && (
              <p className="text-destructive text-xs">{t("installNotOnPath")}</p>
            )}
            <pre
              className={`max-h-64 overflow-auto whitespace-pre-wrap break-words bg-muted p-2 font-mono text-xs ${
                installResult.is_error ? "text-destructive" : ""
              }`}
            >
              {installResult.output || t("noOutput")}
            </pre>
          </div>
        )}
      </div>

      <Separator />
      <div className="flex flex-wrap items-center gap-2 p-4">
        <Button size="sm" onClick={save} disabled={busy || !toml.trim()}>
          <SaveIcon /> {t("save")}
        </Button>
        {manifest?.source === "modified" && (
          <Button size="sm" variant="outline" onClick={remove} disabled={busy}>
            <RotateCcwIcon /> {t("resetBuiltin")}
          </Button>
        )}
        {manifest?.source === "custom" && (
          <Button size="sm" variant="outline" className="text-destructive" onClick={remove} disabled={busy}>
            <Trash2Icon /> {t("delete")}
          </Button>
        )}
        {manifest?.installable && (
          <Button size="sm" variant="outline" onClick={install} disabled={busy}>
            <DownloadIcon /> {t("install")}
          </Button>
        )}
      </div>
    </>
  );
}

// TemplateSheet edits one manifest template, or starts a new one when `edit` is "new".
export function TemplateSheet({
  edit,
  onClose,
  onChanged,
}: {
  edit: ToolManifest | "new" | null;
  onClose: () => void;
  onChanged: () => void;
}) {
  const t = useTranslations("toolboxPage");
  const manifest = edit && edit !== "new" ? edit : null;
  return (
    <Sheet open={!!edit} onOpenChange={(o) => !o && onClose()}>
      <SheetContent
        side="right"
        className="flex w-full flex-col gap-0 p-0 data-[side=right]:sm:w-[45vw] data-[side=right]:sm:max-w-[45vw]"
      >
        <SheetHeader className="px-4">
          <SheetTitle className={manifest ? "font-mono" : undefined}>
            {manifest ? manifest.id : t("newTemplate")}
          </SheetTitle>
          <SheetDescription>{t("templateSheetDesc")}</SheetDescription>
        </SheetHeader>
        {edit && (
          <TemplateBody key={manifest?.id ?? "new"} manifest={manifest} onClose={onClose} onChanged={onChanged} />
        )}
      </SheetContent>
    </Sheet>
  );
}
