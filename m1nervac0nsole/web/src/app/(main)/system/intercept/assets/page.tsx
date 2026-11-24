"use client";

import * as React from "react";

import { BanIcon, PencilIcon, PlusIcon, Trash2Icon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { AssetInterceptKind, AssetInterceptRule } from "@/lib/types";

// ---- kind metadata ----
// The label is resolved from assetInterceptRules.kind.*, and the group headers are resolved from assetInterceptPage.group.*.

type KindGroup = "exact" | "fuzzy" | "cidr";

const KIND_OPTIONS: { value: AssetInterceptKind; group: KindGroup; placeholder: string }[] = [
  { value: "exact_domain", group: "exact", placeholder: "example.com" },
  { value: "exact_ip", group: "exact", placeholder: "203.0.113.10" },
  { value: "exact_url", group: "exact", placeholder: "https://example.com/login" },
  { value: "fuzzy_domain", group: "fuzzy", placeholder: ".example.com" },
  { value: "fuzzy_ip", group: "fuzzy", placeholder: "203.0.113." },
  { value: "fuzzy_url", group: "fuzzy", placeholder: "/admin" },
  { value: "cidr", group: "cidr", placeholder: "192.168.0.0/16" },
];

const KIND_GROUPS: KindGroup[] = ["exact", "fuzzy", "cidr"];

function KindBadge({ kind, label }: { kind: AssetInterceptKind; label: string }) {
  const fuzzy = kind.startsWith("fuzzy_");
  const cidr = kind === "cidr";
  return (
    <Badge
      variant="outline"
      className={
        cidr ? "border-info/40 text-info" : fuzzy ? "border-warning/40 text-warning" : "border-success/40 text-success"
      }
    >
      {label}
    </Badge>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <Label className="font-medium text-muted-foreground text-xs uppercase tracking-wide">{label}</Label>
      {children}
      {hint && <p className="text-[11px] text-muted-foreground">{hint}</p>}
    </div>
  );
}

// ---- form state ----

type RuleForm = {
  enabled: boolean;
  kind: AssetInterceptKind;
  pattern: string;
  note: string;
};

const defaultForm = (): RuleForm => ({ enabled: true, kind: "fuzzy_domain", pattern: "", note: "" });

// Lightweight front-end validation (consistent with the backend: only exact_ip / cidr are format-validated; the rest is left to the backend).
// Return the error code, and the screen converts it into a translated message.
function frontValidate(form: RuleForm): "contentRequired" | "cidrInvalid" | null {
  const p = form.pattern.trim();
  if (!p) return "contentRequired";
  if (form.kind === "cidr" && !/^[0-9a-fA-F:.]+\/\d{1,3}$/.test(p)) {
    return "cidrInvalid";
  }
  return null;
}

// ---- page ----

export default function AssetInterceptPage() {
  const t = useTranslations("assetInterceptPage");
  const tr = useTranslations("assetInterceptRules");
  const [rules, setRules] = React.useState<AssetInterceptRule[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [open, setOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<AssetInterceptRule | null>(null);
  const [form, setForm] = React.useState<RuleForm>(defaultForm());
  const [saving, setSaving] = React.useState(false);

  const load = React.useCallback(async () => {
    try {
      setRules(await api.assetInterceptRules());
    } catch {
      toast.error(t("toast.loadFailed"));
    } finally {
      setLoading(false);
    }
  }, [t]);

  React.useEffect(() => {
    void load();
  }, [load]);

  function set(patch: Partial<RuleForm>) {
    setForm((f) => ({ ...f, ...patch }));
  }

  function openNew() {
    setEditing(null);
    setForm(defaultForm());
    setOpen(true);
  }

  function openEdit(rule: AssetInterceptRule) {
    setEditing(rule);
    setForm({ enabled: rule.enabled, kind: rule.kind, pattern: rule.pattern, note: rule.note });
    setOpen(true);
  }

  async function handleSave() {
    const err = frontValidate(form);
    if (err) {
      toast.error(t(`toast.${err}`));
      return;
    }
    const payload = { ...form, pattern: form.pattern.trim() };
    setSaving(true);
    try {
      if (editing) {
        await api.updateAssetInterceptRule(editing.id, payload);
        toast.success(t("toast.ruleUpdated"));
      } else {
        await api.createAssetInterceptRule(payload);
        toast.success(t("toast.ruleCreated"));
      }
      setOpen(false);
      void load();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(rule: AssetInterceptRule) {
    if (!window.confirm(t("deleteConfirm", { pattern: rule.pattern }))) return;
    try {
      await api.deleteAssetInterceptRule(rule.id);
      toast.success(t("toast.ruleDeleted"));
      void load();
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  async function handleToggle(rule: AssetInterceptRule) {
    try {
      await api.toggleAssetInterceptRule(rule.id, !rule.enabled);
      void load();
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  const placeholder = KIND_OPTIONS.find((o) => o.value === form.kind)?.placeholder ?? "";

  return (
    <div className="flex flex-1 flex-col gap-4">
      {/* header */}
      <div className="flex items-center gap-2.5">
        <BanIcon className="size-5 shrink-0" />
        <div>
          <h1 className="font-semibold text-lg leading-tight">{t("title")}</h1>
          <p className="mt-0.5 text-muted-foreground text-xs">{t("subtitle")}</p>
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-muted-foreground text-xs">{t("intro")}</p>
        <Button onClick={openNew} size="sm" className="shrink-0">
          <PlusIcon className="h-4 w-4" />
          {t("add")}
        </Button>
      </div>

      <div className="border border-border">
        {loading ? (
          <p className="p-6 text-muted-foreground text-sm">{t("loading")}</p>
        ) : rules.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 py-16 text-center">
            <BanIcon className="h-8 w-8 text-muted-foreground/40" />
            <p className="text-muted-foreground text-sm">{t("empty")}</p>
            <Button size="sm" variant="outline" onClick={openNew}>
              <PlusIcon className="h-4 w-4" />
              {t("addFirst")}
            </Button>
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-[130px]">{t("colType")}</TableHead>
                <TableHead>{t("colPattern")}</TableHead>
                <TableHead>{t("colNote")}</TableHead>
                <TableHead className="w-[64px] text-center">{t("colEnabled")}</TableHead>
                <TableHead className="w-[80px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rules.map((rule) => (
                <TableRow key={rule.id} className={!rule.enabled ? "opacity-40" : ""}>
                  <TableCell>
                    <KindBadge kind={rule.kind} label={tr(`kind.${rule.kind}`)} />
                  </TableCell>
                  <TableCell className="max-w-[280px]">
                    <code
                      className="block truncate rounded-sm bg-muted px-1.5 py-0.5 font-mono text-xs"
                      title={rule.pattern}
                    >
                      {rule.pattern}
                    </code>
                  </TableCell>
                  <TableCell className="text-muted-foreground text-sm">
                    <div className="flex items-center gap-1.5">
                      {rule.builtin && (
                        <Badge variant="secondary" className="shrink-0 px-1 py-0 text-[10px]">
                          {t("builtin")}
                        </Badge>
                      )}
                      <span className="truncate" title={rule.note}>
                        {rule.note}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell className="text-center">
                    <Switch
                      checked={rule.enabled}
                      onCheckedChange={() => handleToggle(rule)}
                      aria-label={t("colEnabled")}
                    />
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center justify-end gap-0.5">
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-7 w-7"
                        aria-label={t("editAria")}
                        onClick={() => openEdit(rule)}
                      >
                        <PencilIcon className="h-3.5 w-3.5" />
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-7 w-7 text-destructive hover:text-destructive"
                        aria-label={t("deleteAria")}
                        onClick={() => handleDelete(rule)}
                      >
                        <Trash2Icon className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>

      {/* editor sheet */}
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent side="right" className="flex flex-col gap-0 p-0 sm:max-w-md">
          <SheetHeader className="border-b px-6 py-4">
            <SheetTitle>{editing ? t("editor.editTitle") : t("editor.newTitle")}</SheetTitle>
            <SheetDescription className="text-xs">{t("editor.desc")}</SheetDescription>
          </SheetHeader>

          <div className="min-h-0 flex-1 space-y-5 overflow-y-auto px-6 py-5">
            <Field label={t("editor.matchType")}>
              <Select value={form.kind} onValueChange={(v) => set({ kind: v as AssetInterceptKind })}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {KIND_GROUPS.map((g) => (
                    <React.Fragment key={g}>
                      <div className="px-2 py-1 font-semibold text-[10px] text-muted-foreground uppercase tracking-wider">
                        {t(`group.${g}`)}
                      </div>
                      {KIND_OPTIONS.filter((o) => o.group === g).map((o) => (
                        <SelectItem key={o.value} value={o.value}>
                          {tr(`kind.${o.value}`)}
                        </SelectItem>
                      ))}
                    </React.Fragment>
                  ))}
                </SelectContent>
              </Select>
            </Field>

            <Field
              label={t("editor.matchContent")}
              hint={
                form.kind === "cidr"
                  ? t("editor.hintCidr")
                  : form.kind.startsWith("fuzzy_")
                    ? t("editor.hintFuzzy")
                    : t("editor.hintExact")
              }
            >
              <Input
                placeholder={placeholder}
                value={form.pattern}
                onChange={(e) => set({ pattern: e.target.value })}
              />
            </Field>

            <Field label={t("editor.note")}>
              <Textarea
                placeholder={t("editor.notePlaceholder")}
                value={form.note}
                onChange={(e) => set({ note: e.target.value })}
                rows={2}
                className="resize-none"
              />
            </Field>

            <Separator />

            <div className="flex items-center gap-3">
              <Switch id="asset-rule-enabled" checked={form.enabled} onCheckedChange={(v) => set({ enabled: v })} />
              <Label htmlFor="asset-rule-enabled" className="cursor-pointer">
                {t("editor.enableRule")}
              </Label>
            </div>
          </div>

          <SheetFooter className="flex-row justify-end gap-2 border-t px-6 py-4">
            <Button variant="outline" onClick={() => setOpen(false)}>
              {t("editor.cancel")}
            </Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? t("editor.saving") : t("editor.save")}
            </Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    </div>
  );
}
