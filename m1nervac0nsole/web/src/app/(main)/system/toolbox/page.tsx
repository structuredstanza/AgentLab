"use client";

import * as React from "react";

import { Loader2Icon, SearchIcon, TerminalIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { api } from "@/lib/api";
import type { ToolManifest, ToolPreview } from "@/lib/types";

// formatCommand is what the operator reads: the argv exactly as the executor
// builds it, quoted only where a shell would need it.
export function formatCommand(program: string, args: string[]): string {
  const quote = (a: string) => (/^[A-Za-z0-9_./:=@%+,-]+$/.test(a) ? a : `'${a.replace(/'/g, "'\\''")}'`);
  return [program, ...args].map(quote).join(" ");
}

export default function ToolboxPage() {
  const t = useTranslations("toolboxPage");
  const [manifests, setManifests] = React.useState<ToolManifest[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [query, setQuery] = React.useState("");
  const [selected, setSelected] = React.useState<string | null>(null);
  const [target, setTarget] = React.useState("");
  const [params, setParams] = React.useState<Record<string, string>>({});
  const [preview, setPreview] = React.useState<ToolPreview | null>(null);
  const [previewError, setPreviewError] = React.useState("");
  const [previewing, setPreviewing] = React.useState(false);

  React.useEffect(() => {
    api
      .toolManifests()
      .then((list) => {
        setManifests(list);
        if (list.length > 0) setSelected(list[0].id);
      })
      .catch(() => setManifests([]))
      .finally(() => setLoading(false));
  }, []);

  const manifest = manifests.find((m) => m.id === selected) ?? null;

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

  const visible = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return manifests;
    return manifests.filter((m) => `${m.id} ${m.name} ${m.description}`.toLowerCase().includes(q));
  }, [manifests, query]);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4 p-4">
      <div>
        <h1 className="font-semibold text-lg">{t("title")}</h1>
        <p className="text-muted-foreground text-sm">{t("subtitle")}</p>
      </div>

      <div className="grid min-h-0 flex-1 gap-4 lg:grid-cols-[320px_1fr]">
        <div className="flex min-h-0 flex-col gap-2">
          <div className="relative">
            <SearchIcon className="absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
            <Input
              className="pl-8"
              placeholder={t("search")}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <ScrollArea className="min-h-0 flex-1 rounded-md border">
            <div className="divide-y">
              {loading && <p className="p-3 text-muted-foreground text-sm">{t("loading")}</p>}
              {!loading && visible.length === 0 && <p className="p-3 text-muted-foreground text-sm">{t("empty")}</p>}
              {visible.map((m) => (
                <button
                  key={m.id}
                  type="button"
                  onClick={() => {
                    // Reset the form with the tool: a parameter from the previous
                    // tool would be rejected by the next one's resolver.
                    setSelected(m.id);
                    setParams({});
                    setPreview(null);
                    setPreviewError("");
                  }}
                  className={`flex w-full flex-col gap-0.5 px-3 py-2 text-left hover:bg-muted/50 ${
                    m.id === selected ? "bg-muted" : ""
                  }`}
                >
                  <span className="flex items-center gap-2 text-sm">
                    <TerminalIcon className="size-3.5 text-muted-foreground" />
                    <code className="font-mono">{m.id}</code>
                    {!m.available && (
                      <Badge variant="outline" className="ml-auto text-[10px] text-destructive">
                        {t("notInstalled")}
                      </Badge>
                    )}
                  </span>
                  <span className="line-clamp-1 text-muted-foreground text-xs">{m.description}</span>
                </button>
              ))}
            </div>
          </ScrollArea>
        </div>

        <div className="flex min-h-0 flex-col gap-3">
          {!manifest ? (
            <p className="text-muted-foreground text-sm">{t("selectTool")}</p>
          ) : (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <code className="font-mono text-sm">{manifest.id}</code>
                <Badge variant="secondary">{manifest.category}</Badge>
                <span className="text-muted-foreground text-xs">
                  {t("accepts", { kinds: manifest.accepts.join(", ") })}
                </span>
              </div>
              <p className="text-muted-foreground text-sm">{manifest.description}</p>

              <div className="flex flex-col gap-1 text-sm">
                <span>{t("target")}</span>
                <Input
                  aria-label={t("target")}
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder={t("targetPlaceholder")}
                />
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                {Object.entries(manifest.params).map(([name, p]) => (
                  <div key={name} className="flex flex-col gap-1 text-sm">
                    <span className="flex items-center gap-1">
                      <code className="font-mono text-xs">{name}</code>
                      {p.default !== undefined && (
                        <span className="text-muted-foreground text-xs">{t("default", { value: p.default })}</span>
                      )}
                    </span>
                    {p.type === "enum" ? (
                      <select
                        aria-label={name}
                        className="h-9 rounded-md border bg-transparent px-2 text-sm"
                        value={params[name] ?? p.default ?? ""}
                        onChange={(e) => setParams((prev) => ({ ...prev, [name]: e.target.value }))}
                      >
                        {(p.options ?? []).map((o) => (
                          <option key={o} value={o}>
                            {o}
                          </option>
                        ))}
                      </select>
                    ) : p.type === "bool" ? (
                      <label className="flex items-center gap-2 text-sm">
                        <input
                          type="checkbox"
                          checked={(params[name] ?? p.default ?? "false") === "true"}
                          onChange={(e) =>
                            setParams((prev) => ({ ...prev, [name]: e.target.checked ? "true" : "false" }))
                          }
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

              <div className="rounded-md border bg-muted/30 p-3">
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
        </div>
      </div>
    </div>
  );
}
