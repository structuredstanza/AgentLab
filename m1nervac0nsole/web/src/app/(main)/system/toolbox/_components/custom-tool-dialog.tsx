"use client";

import * as React from "react";

import { PlayIcon, SaveIcon, Trash2Icon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { Agent, Tool } from "@/lib/types";

type ExecState = {
  command: string;
  code: string;
  method: string;
  url: string;
  headers: string;
  body: string;
  timeout_ms: string;
};

export function CustomToolDialog({
  edit,
  agents,
  onClose,
  onSaved,
}: {
  edit: Tool | "new" | null;
  agents: Agent[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const t = useTranslations("toolboxPage");
  const isNew = edit === "new";
  const tool = edit && edit !== "new" ? edit : null;
  const [key, setKey] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [kind, setKind] = React.useState<"shell" | "command" | "script" | "http">("shell");
  const [ex, setEx] = React.useState<ExecState>({
    command: "",
    code: "",
    method: "GET",
    url: "",
    headers: "",
    body: "",
    timeout_ms: "",
  });
  const [schemaText, setSchemaText] = React.useState("");
  const [bound, setBound] = React.useState<string[]>([]);
  const [deferred, setDeferred] = React.useState(false);
  const [enabled, setEnabled] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [paramsText, setParamsText] = React.useState("");
  const [testing, setTesting] = React.useState(false);
  const [testResult, setTestResult] = React.useState<{ output: string; is_error: boolean } | null>(null);

  // (re)load form state when opening.
  React.useEffect(() => {
    if (!edit) return;
    setParamsText("");
    setTestResult(null);
    if (edit === "new") {
      setKey("");
      setDescription("");
      setKind("shell");
      setEx({
        command: "",
        code: "",
        method: "GET",
        url: "",
        headers: "",
        body: "",
        timeout_ms: "",
      });
      setSchemaText("");
      setBound([]);
      setDeferred(false);
      setEnabled(true);
      return;
    }
    const t = edit;
    const e = (t.exec ?? {}) as Record<string, unknown>;
    setKey(t.key);
    setDescription(t.description);
    setKind((t.kind as "shell" | "command" | "script" | "http") ?? "shell");
    setEx({
      command: String(e.command ?? ""),
      code: String(e.code ?? ""),
      method: String(e.method ?? "GET"),
      url: String(e.url ?? ""),
      headers: e.headers ? JSON.stringify(e.headers, null, 2) : "",
      body: String(e.body ?? ""),
      timeout_ms: e.timeout_ms ? String(e.timeout_ms) : "",
    });
    setSchemaText(t.schema && Object.keys(t.schema).length ? JSON.stringify(t.schema, null, 2) : "");
    setBound(t.agents ?? []);
    setDeferred(!!t.deferred);
    setEnabled(t.enabled);
  }, [edit]);

  const toggleAgent = (k: string) => setBound((b) => (b.includes(k) ? b.filter((x) => x !== k) : [...b, k]));

  function buildExec(): Record<string, unknown> {
    if (kind === "shell") return {};
    const t = ex.timeout_ms ? Number(ex.timeout_ms) : undefined;
    if (kind === "command") return { command: ex.command, timeout_ms: t };
    if (kind === "script") return { code: ex.code, timeout_ms: t };
    let headers: Record<string, string> = {};
    if (ex.headers.trim()) {
      try {
        headers = JSON.parse(ex.headers);
      } catch {
        /* validated on save */
      }
    }
    return {
      method: ex.method,
      url: ex.url,
      headers,
      body: ex.body,
      timeout_ms: t,
    };
  }

  async function save() {
    if (isNew && !/^[a-z][a-z0-9_]*$/.test(key.trim())) {
      toast.error(t("keyError"));
      return;
    }
    let schema: Record<string, unknown> = {};
    if (schemaText.trim()) {
      try {
        schema = JSON.parse(schemaText);
      } catch {
        toast.error(t("schemaError"));
        return;
      }
    }
    if (kind === "http" && ex.headers.trim()) {
      try {
        JSON.parse(ex.headers);
      } catch {
        toast.error(t("headersError"));
        return;
      }
    }
    if (kind === "http") {
      const props = (schema as { properties?: Record<string, unknown> }).properties;
      if (!props || Object.keys(props).length === 0) {
        toast.error(t("httpSchemaRequired"));
        return;
      }
    }
    setSaving(true);
    const payload = {
      description,
      schema: kind === "shell" ? {} : schema,
      agents: bound,
      enabled,
      kind,
      exec: buildExec(),
      deferred: kind === "shell" ? false : deferred,
    };
    try {
      if (isNew) await api.createCustomTool({ key: key.trim(), ...payload });
      else await api.updateCustomTool(tool!.key, payload);
      toast.success(isNew ? t("createdCustom") : t("saved"));
      onSaved();
    } catch (e) {
      toast.error(t("saveFailed", { msg: (e as Error).message }));
    } finally {
      setSaving(false);
    }
  }
  async function del() {
    if (!tool) return;
    try {
      await api.deleteCustomTool(tool.key);
      toast.success(t("deleted"));
      onSaved();
    } catch (e) {
      toast.error(t("deleteFailed", { msg: (e as Error).message }));
    }
  }
  // runTest dry-runs the CURRENT form (unsaved) with the sample params, so a
  // template/script/request can be debugged before saving.
  async function runTest() {
    let params: Record<string, unknown> = {};
    if (paramsText.trim()) {
      try {
        params = JSON.parse(paramsText);
      } catch {
        toast.error(t("testParamsError"));
        return;
      }
    }
    if (kind === "http" && ex.headers.trim()) {
      try {
        JSON.parse(ex.headers);
      } catch {
        toast.error(t("headersError"));
        return;
      }
    }
    setTesting(true);
    setTestResult(null);
    try {
      const r = await api.testCustomTool({ kind, exec: buildExec(), params });
      setTestResult(r);
    } catch (e) {
      setTestResult({ output: (e as Error).message, is_error: true });
    } finally {
      setTesting(false);
    }
  }

  let sheetTitle = t("newCustom");
  if (!isNew && tool) sheetTitle = t("editCustom", { key: tool.key });

  return (
    <Sheet open={!!edit} onOpenChange={(o) => !o && onClose()}>
      <SheetContent
        side="right"
        className="flex w-full flex-col gap-0 p-0 data-[side=right]:sm:w-[45vw] data-[side=right]:sm:max-w-[45vw]"
      >
        <SheetHeader className="px-4">
          <SheetTitle>{sheetTitle}</SheetTitle>
          <SheetDescription>{t("customSheetDesc")}</SheetDescription>
        </SheetHeader>

        <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4 pb-4">
          <div className="grid gap-1.5">
            <Label className="text-xs">{t("keyLabel")}</Label>
            <Input
              className="font-mono"
              placeholder={t("keyPlaceholder")}
              value={key}
              disabled={!isNew}
              onChange={(e) => setKey(e.target.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label className="text-xs">{t("descLabelShort")}</Label>
            <Textarea rows={2} value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>

          <div className="grid gap-1.5">
            <Label className="text-xs">{t("kindLabel")}</Label>
            <Select value={kind} onValueChange={(v) => setKind(v as "shell" | "command" | "script" | "http")}>
              <SelectTrigger className="w-56">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="shell">{t("kindShell")}</SelectItem>
                <SelectItem value="command">{t("kindCommand")}</SelectItem>
                <SelectItem value="script">{t("kindScript")}</SelectItem>
                <SelectItem value="http">{t("kindHttp")}</SelectItem>
              </SelectContent>
            </Select>
            {kind === "shell" && <p className="text-muted-foreground text-xs">{t("shellHint")}</p>}
          </div>

          {kind === "command" && (
            <div className="grid gap-1.5">
              <Label className="text-xs">{t("cmdTemplateLabel")}</Label>
              <Textarea
                className="font-mono text-xs"
                rows={2}
                value={ex.command}
                onChange={(e) => setEx({ ...ex, command: e.target.value })}
              />
            </div>
          )}
          {kind === "script" && (
            <div className="grid gap-1.5">
              <Label className="text-xs">{t("scriptLabel")}</Label>
              <Textarea
                className="font-mono text-xs"
                rows={10}
                value={ex.code}
                placeholder={"import json,sys\nargs=json.load(sys.stdin)\nprint(...)"}
                onChange={(e) => setEx({ ...ex, code: e.target.value })}
              />
            </div>
          )}
          {kind === "http" && (
            <div className="grid gap-2">
              <div className="flex gap-2">
                <div className="grid gap-1.5">
                  <Label className="text-xs">{t("methodLabel")}</Label>
                  <Input
                    className="w-24"
                    value={ex.method}
                    onChange={(e) => setEx({ ...ex, method: e.target.value })}
                  />
                </div>
                <div className="grid flex-1 gap-1.5">
                  <Label className="text-xs">{t("httpUrlLabel")}</Label>
                  <Input
                    className="font-mono text-xs"
                    value={ex.url}
                    onChange={(e) => setEx({ ...ex, url: e.target.value })}
                  />
                </div>
              </div>
              <div className="grid gap-1.5">
                <Label className="text-xs">{t("httpHeadersLabel")}</Label>
                <Textarea
                  className="font-mono text-xs"
                  rows={2}
                  value={ex.headers}
                  placeholder={'{"Authorization": "Bearer {token}"}'}
                  onChange={(e) => setEx({ ...ex, headers: e.target.value })}
                />
              </div>
              <div className="grid gap-1.5">
                <Label className="text-xs">{t("httpBodyLabel")}</Label>
                <Textarea
                  className="font-mono text-xs"
                  rows={2}
                  value={ex.body}
                  onChange={(e) => setEx({ ...ex, body: e.target.value })}
                />
              </div>
            </div>
          )}

          {kind !== "shell" && (
            <div className="flex items-center gap-3">
              <div className="grid gap-1.5">
                <Label className="text-xs">{t("timeoutLabel")}</Label>
                <Input
                  type="number"
                  className="w-32"
                  value={ex.timeout_ms}
                  onChange={(e) => setEx({ ...ex, timeout_ms: e.target.value })}
                />
              </div>
            </div>
          )}

          {kind !== "shell" && (
            <div className="grid gap-1.5">
              <Label className="text-xs">
                {t("schemaLabel")}
                {kind === "http" ? t("schemaHttpSuffix") : t("schemaDefaultSuffix")}
              </Label>
              <Textarea
                className="font-mono text-xs"
                rows={4}
                value={schemaText}
                placeholder={'{"type":"object","properties":{"target":{"type":"string"}},"required":["target"]}'}
                onChange={(e) => setSchemaText(e.target.value)}
              />
            </div>
          )}

          <div className="grid gap-1.5">
            <Label className="text-muted-foreground text-xs">{t("bindAgentShort")}</Label>
            <div className="flex flex-wrap gap-3">
              {agents.map((a) => (
                <label key={a.key} className="flex items-center gap-2 text-sm">
                  <Checkbox checked={bound.includes(a.key)} onCheckedChange={() => toggleAgent(a.key)} />
                  {a.name}
                  <span className="font-mono text-muted-foreground text-xs">{a.key}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="flex items-center gap-6">
            <label className="flex items-center gap-2 text-sm">
              <Switch checked={enabled} onCheckedChange={setEnabled} /> {t("enabled")}
            </label>
            {kind !== "shell" && (
              <label className="flex items-center gap-2 text-sm">
                <Switch checked={deferred} onCheckedChange={setDeferred} /> {t("deferredLabel")}
              </label>
            )}
          </div>

          {kind !== "shell" && (
            <div className="grid gap-1.5 border border-border p-3">
              <Label className="font-medium text-xs">{t("testSectionLabel")}</Label>
              <Textarea
                className="font-mono text-xs"
                rows={2}
                value={paramsText}
                placeholder={t("testParamsPlaceholder")}
                onChange={(e) => setParamsText(e.target.value)}
              />
              <div>
                <Button size="sm" variant="outline" onClick={runTest} disabled={testing}>
                  <PlayIcon /> {testing ? t("testRunning") : t("testRun")}
                </Button>
              </div>
              {testResult && (
                <pre
                  className={
                    "max-h-64 overflow-auto whitespace-pre-wrap break-words rounded bg-muted p-2 font-mono text-xs" +
                    (testResult.is_error ? "text-destructive" : "")
                  }
                >
                  {testResult.output || t("noOutput")}
                </pre>
              )}
            </div>
          )}
        </div>

        <Separator />
        <div className="flex items-center gap-2 p-4">
          <Button size="sm" onClick={save} disabled={saving}>
            <SaveIcon /> {isNew ? t("create") : t("save")}
          </Button>
          {!isNew && (
            <Button size="sm" variant="outline" className="text-destructive" onClick={del}>
              <Trash2Icon /> {t("delete")}
            </Button>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
