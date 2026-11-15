"use client";

import * as React from "react";

import { RotateCcwIcon, SaveIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { Agent, Tool } from "@/lib/types";

// Traffic tools are host tools gated by the global traffic capture switch: bindable, but
// only usable when capture is on. Keep in sync with traffic.SeedToolMetas.
const TRAFFIC_TOOL_KEYS = new Set(["traffic_search", "traffic_get"]);

// paramRows flattens schema.properties into an ordered row list for editing.
// name/type/required are read-only (welded to the Go handler); description/default
// are editable. Non-scalar params (array/object) can't carry an editable default.
// parentKey is set for rows that live inside an array param's items.properties.
type ParamRow = {
  name: string;
  type: string;
  required: boolean;
  description: string;
  defaultStr: string; // "" = no default declared
  scalar: boolean;
  parentKey?: string; // set when this is a sub-field of an array param's items
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function toRows(schema: Record<string, any>): ParamRow[] {
  const props = (schema?.properties ?? {}) as Record<string, Record<string, unknown>>;
  const required = new Set<string>((schema?.required as string[]) ?? []);
  const rows: ParamRow[] = [];
  for (const [name, p] of Object.entries(props)) {
    const type = String(p?.type ?? "");
    const hasDefault = p != null && "default" in p && (p as Record<string, unknown>).default != null;
    rows.push({
      name,
      type,
      required: required.has(name),
      description: String(p?.description ?? ""),
      defaultStr: hasDefault ? String((p as Record<string, unknown>).default) : "",
      scalar: ["string", "integer", "number", "boolean"].includes(type),
    });
    // Expand items.properties for array params so sub-fields are editable.
    if (type === "array") {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const itemProps = (p as any)?.items?.properties as Record<string, Record<string, unknown>> | undefined;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const itemRequired = new Set<string>(((p as any)?.items?.required as string[]) ?? []);
      if (itemProps) {
        for (const [subName, subP] of Object.entries(itemProps)) {
          const subType = String((subP as Record<string, unknown>)?.type ?? "");
          const subHasDefault = subP != null && "default" in subP && subP.default != null;
          rows.push({
            name: subName,
            type: subType,
            required: itemRequired.has(subName),
            description: String(subP?.description ?? ""),
            defaultStr: subHasDefault ? String(subP.default) : "",
            scalar: ["string", "integer", "number", "boolean"].includes(subType),
            parentKey: name,
          });
        }
      }
    }
  }
  return rows;
}

// coerceDefault turns the edited default string back into a typed JSON value, or
// undefined to drop the "default" key entirely.
function coerceDefault(type: string, raw: string): unknown {
  const s = raw.trim();
  if (s === "") return undefined;
  if (type === "integer" || type === "number") {
    const n = Number(s);
    return Number.isNaN(n) ? undefined : n;
  }
  if (type === "boolean") return s === "true";
  return raw;
}

// applyRows writes edited rows back into a deep-copied schema (structure untouched).
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function applyRows(schema: Record<string, any>, rows: ParamRow[]): Record<string, any> {
  const next = structuredClone(schema ?? {});
  const props = (next.properties ?? {}) as Record<string, Record<string, unknown>>;
  for (const r of rows) {
    if (r.parentKey) {
      // Sub-field of an array param's items.properties
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const parent = props[r.parentKey] as any;
      const subP = parent?.items?.properties?.[r.name] as Record<string, unknown> | undefined;
      if (!subP) continue;
      subP.description = r.description;
      if (r.scalar) {
        const dv = coerceDefault(r.type, r.defaultStr);
        if (dv === undefined) delete subP.default;
        else subP.default = dv;
      }
    } else {
      const p = props[r.name];
      if (!p) continue;
      p.description = r.description;
      if (r.scalar) {
        const dv = coerceDefault(r.type, r.defaultStr);
        if (dv === undefined) delete p.default;
        else p.default = dv;
      }
    }
  }
  return next;
}

// ToolEditor is the full edit form for one tool, rendered inside the drawer.
function ToolEditor({
  tool,
  agents,
  captureOn,
  onSaved,
  onClose,
}: {
  tool: Tool;
  agents: Agent[];
  captureOn: boolean;
  onSaved: () => void;
  onClose: () => void;
}) {
  const t = useTranslations("toolboxPage");
  // traffic tools can't be bound/enabled until the global traffic capture switch is on.
  const trafficGated = TRAFFIC_TOOL_KEYS.has(tool.key) && !captureOn;
  const [description, setDescription] = React.useState(tool.description);
  const [bound, setBound] = React.useState<string[]>(tool.agents);
  const [enabled, setEnabled] = React.useState(tool.enabled);
  const [rows, setRows] = React.useState<ParamRow[]>(() => toRows(tool.schema));
  const [saving, setSaving] = React.useState(false);

  const setRow = (i: number, patch: Partial<ParamRow>) =>
    setRows((rs) => rs.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const toggleAgent = (k: string) => setBound((b) => (b.includes(k) ? b.filter((x) => x !== k) : [...b, k]));

  async function save() {
    setSaving(true);
    try {
      await api.saveTool(tool.key, {
        description,
        schema: applyRows(tool.schema, rows),
        agents: bound,
        enabled,
      });
      toast.success(t("savedTool", { key: tool.key }));
      onSaved();
      onClose();
    } catch (e) {
      toast.error(t("saveFailed", { msg: (e as Error).message }));
    } finally {
      setSaving(false);
    }
  }
  async function reset() {
    try {
      await api.resetTool(tool.key);
      toast.success(t("resetDone", { key: tool.key }));
      onSaved();
      onClose();
    } catch (e) {
      toast.error(t("resetFailed", { msg: (e as Error).message }));
    }
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4">
        {trafficGated && (
          <div className="border border-warning/40 bg-warning/10 px-3 py-2 text-muted-foreground text-xs">
            {t.rich("trafficGatedNote", { b: (c) => <b>{c}</b> })}
          </div>
        )}
        {/* binding + switch */}
        <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
          <div className="grid gap-1.5">
            <Label className="text-muted-foreground text-xs">{t("bindAgentLabel")}</Label>
            <div className="flex flex-wrap gap-3">
              {agents.map((ag) => (
                <label key={ag.key} className="flex items-center gap-2 text-sm">
                  <Checkbox
                    checked={bound.includes(ag.key)}
                    disabled={trafficGated}
                    onCheckedChange={() => toggleAgent(ag.key)}
                  />
                  {ag.name}
                  <span className="font-mono text-muted-foreground text-xs">{ag.key}</span>
                </label>
              ))}
              {agents.length === 0 && <span className="text-muted-foreground text-xs">{t("noAgents")}</span>}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Switch checked={enabled} onCheckedChange={setEnabled} id={`en-${tool.key}`} />
            <Label htmlFor={`en-${tool.key}`} className="text-sm">
              {t("enabled")}
            </Label>
          </div>
        </div>

        {/* description */}
        <div className="grid gap-1.5">
          <Label className="text-muted-foreground text-xs">{t("descLabel")}</Label>
          <Textarea
            className="font-mono text-xs"
            rows={6}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>

        {/* params */}
        <div className="grid gap-2">
          <Label className="text-muted-foreground text-xs">{t("paramsLabel")}</Label>
          {rows.length === 0 && <span className="text-muted-foreground text-xs">{t("noParams")}</span>}
          {rows.map((r, i) => (
            <div
              key={(r.parentKey ?? "") + "." + r.name}
              className={
                r.parentKey
                  ? "ml-3 grid gap-2 border-border border-l-2 py-2 pl-3"
                  : "grid gap-2 border border-border p-3"
              }
            >
              <div className="flex flex-wrap items-center gap-2">
                {r.parentKey && <span className="font-mono text-[10px] text-muted-foreground">{"\u21b3"}</span>}
                <span className="font-mono text-sm">{r.name}</span>
                <Badge variant="secondary" className="px-1.5 py-0 text-[10px]">
                  {r.type || "?"}
                </Badge>
                {r.required && (
                  <Badge variant="outline" className="px-1.5 py-0 text-[10px]">
                    {t("required")}
                  </Badge>
                )}
                {r.parentKey && <span className="text-[10px] text-muted-foreground">{t("itemsSubfield")}</span>}
              </div>
              <div className="grid gap-2">
                <div className="grid gap-1">
                  <Label className="text-[11px] text-muted-foreground">{t("rowDesc")}</Label>
                  <Input
                    className="text-xs"
                    value={r.description}
                    onChange={(e) => setRow(i, { description: e.target.value })}
                  />
                </div>
                <div className="grid gap-1">
                  <Label className="text-[11px] text-muted-foreground">{t("rowDefault")}</Label>
                  <Input
                    className="text-xs"
                    placeholder={r.scalar ? t("defaultEmptyHint") : t("scalarOnly")}
                    disabled={!r.scalar}
                    value={r.defaultStr}
                    onChange={(e) => setRow(i, { defaultStr: e.target.value })}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <Separator className="mt-4" />
      <div className="flex flex-wrap gap-2 p-4">
        <Button size="sm" onClick={save} disabled={saving}>
          <SaveIcon /> {t("save")}
        </Button>
        <Button size="sm" variant="outline" onClick={reset}>
          <RotateCcwIcon /> {t("resetDefault")}
        </Button>
      </div>
    </div>
  );
}

// ToolGridCard is one clickable tile in the catalog grid.
export function ToolGridCard({ tool, onClick }: { tool: Tool; onClick: () => void }) {
  const t = useTranslations("toolboxPage");
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex flex-col gap-2 border border-border p-3 text-left transition-colors hover:border-primary/50 hover:bg-muted/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium font-mono text-sm">{tool.key}</span>
        {tool.system ? (
          <Badge variant="secondary" className="px-1.5 py-0 text-[10px]">
            {t("badgeSystem")}
          </Badge>
        ) : (
          <Badge variant="outline" className="px-1.5 py-0 text-[10px]">
            {t("badgeCustom")}: {tool.kind}
          </Badge>
        )}
        {tool.deferred && (
          <Badge variant="outline" className="px-1.5 py-0 text-[10px]">
            {t("badgeDeferred")}
          </Badge>
        )}
        {!tool.enabled && (
          <Badge variant="outline" className="px-1.5 py-0 text-[10px] text-destructive">
            {t("badgeDisabled")}
          </Badge>
        )}
        <Badge
          variant="secondary"
          className="ml-auto px-1.5 py-0 text-[10px] tabular-nums"
          title={t("callsTitle", { count: tool.calls ?? 0 })}
        >
          {t("callsBadge", { count: tool.calls ?? 0 })}
        </Badge>
      </div>
      <p className="line-clamp-1 h-4 text-muted-foreground text-xs">{tool.description || t("noDescription")}</p>
      <div className="mt-auto flex flex-wrap gap-1 pt-1">
        {tool.agents.length === 0 && <span className="text-[10px] text-muted-foreground">{t("noBoundAgents")}</span>}
        {tool.agents.map((a) => (
          <Badge key={a} variant="outline" className="px-1.5 py-0 text-[10px]">
            {a}
          </Badge>
        ))}
      </div>
    </button>
  );
}

// matchesTool is the search predicate shared by the agent-tool grid and the catalog.
export function matchesTool(tool: Tool, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return (
    tool.key.toLowerCase().includes(q) ||
    tool.description.toLowerCase().includes(q) ||
    tool.agents.some((a) => a.toLowerCase().includes(q))
  );
}

// AgentTools is the system-tool grid: clicking a card opens the binding/description drawer.
export function AgentTools({
  tools,
  agents,
  captureOn,
  query,
  onChanged,
}: {
  tools: Tool[];
  agents: Agent[];
  captureOn: boolean;
  query: string;
  onChanged: () => void;
}) {
  const t = useTranslations("toolboxPage");
  const [selectedKey, setSelectedKey] = React.useState<string | null>(null);
  const selected = tools.find((x) => x.key === selectedKey) ?? null;
  const systemTools = tools.filter((x) => x.system && matchesTool(x, query));
  const allSystemCount = tools.filter((x) => x.system).length;

  return (
    <section className="border-border border-t pt-3">
      <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="font-semibold text-xs">{t("tabAgentTools")}</h2>
        <span className="text-[11px] text-muted-foreground">
          {query.trim()
            ? t("systemMatched", { shown: systemTools.length, total: allSystemCount })
            : t("systemTotal", { total: allSystemCount })}
        </span>
      </div>
      {systemTools.length === 0 ? (
        <p className="py-6 text-center text-muted-foreground text-sm">
          {query.trim() ? t("systemNoMatch") : t("systemEmpty")}
        </p>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {systemTools.map((tool) => (
            <ToolGridCard key={tool.key} tool={tool} onClick={() => setSelectedKey(tool.key)} />
          ))}
        </div>
      )}

      <Sheet open={!!selected} onOpenChange={(o) => !o && setSelectedKey(null)}>
        <SheetContent
          side="right"
          className="gap-0 p-0 data-[side=right]:w-full data-[side=right]:sm:w-[30vw] data-[side=right]:sm:max-w-[30vw]"
        >
          {selected && (
            <>
              <SheetHeader className="px-4">
                <SheetTitle className="font-mono">{selected.key}</SheetTitle>
                <SheetDescription>{t("editSheetDesc")}</SheetDescription>
              </SheetHeader>
              <ToolEditor
                key={selected.key}
                tool={selected}
                agents={agents}
                captureOn={captureOn}
                onSaved={onChanged}
                onClose={() => setSelectedKey(null)}
              />
            </>
          )}
        </SheetContent>
      </Sheet>
    </section>
  );
}
