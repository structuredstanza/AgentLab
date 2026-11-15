"use client";

import * as React from "react";

import { BellIcon, PlusIcon, SendIcon, Trash2Icon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { NotificationChannel, NotificationFilter, NotificationMeta } from "@/lib/types";

import {
  CHANNEL_FIELDS,
  type ChannelForm,
  emptyForm,
  parseIDs,
  parseKeywords,
  parseKV,
  SEVERITY_OPTIONS,
} from "./_components/channel-fields";
import { ConfigField, FilterSummary } from "./_components/channel-form";
import { DeliveryList } from "./_components/delivery-list";
import { formatBacklog, StatTile } from "./_components/stat-tile";

// This page only handles orchestration: loading data, maintaining form state, and calling the API.
// Field definitions and parsing live in _components/channel-fields.ts, controls and the filter summary in
// _components/channel-form.tsx, and delivery records in _components/delivery-list.tsx——
// They are split apart because each can be read and understood on its own; kept in a single file, this page would approach 1100 lines.
export default function NotifyPage() {
  const t = useTranslations("notifyPage");
  // Display names for channel types: the known kinds go through i18n (notifyPage.kind.<kind>),
  // if the backend returns an unknown type, that key is shown as-is (preserving the original `?? ch.kind` semantics).
  const kindLabel = (k: string) => (k in CHANNEL_FIELDS ? t(`kind.${k}`) : k);
  const [meta, setMeta] = React.useState<NotificationMeta | null>(null);
  const [channels, setChannels] = React.useState<NotificationChannel[]>([]);
  const [tab, setTab] = React.useState<"channels" | "deliveries">("channels");

  const [open, setOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<NotificationChannel | null>(null);
  const [form, setForm] = React.useState<ChannelForm>(emptyForm("webhook"));
  // The URL as the sheet opened it: the webhook address is a credential too, so the
  // form only ever holds it masked and the operator cannot see whether it changed.
  const [savedURL, setSavedURL] = React.useState("");
  const [saving, setSaving] = React.useState(false);
  const [testing, setTesting] = React.useState(false);

  const [globalSaving, setGlobalSaving] = React.useState(false);
  const [baseURL, setBaseURL] = React.useState("");
  const [digestMin, setDigestMin] = React.useState("");

  const load = React.useCallback(() => {
    api
      .notifyMeta()
      .then((m) => {
        setMeta(m);
        setBaseURL(m.public_base_url);
        setDigestMin(m.digest_interval_min);
      })
      .catch((e) => toast.error(t("toast.loadConfigFailed", { msg: (e as Error).message })));
    // Failures loading the channel list must be reported: a silent failure would display as "there are no channels at all"
    // Users would think their configuration was lost, which is more alarming than an explicit error.
    api
      .notifyChannels()
      .then(setChannels)
      .catch((e) => toast.error(t("toast.loadChannelsFailed", { msg: (e as Error).message })));
  }, [t]);
  React.useEffect(() => {
    load();
  }, [load]);

  function setF(patch: Partial<ChannelForm>) {
    setForm((f) => ({ ...f, ...patch }));
  }
  function setCfg(key: string, value: unknown) {
    setForm((f) => ({ ...f, config: { ...f.config, [key]: value } }));
  }

  function openAdd() {
    setEditing(null);
    setSavedURL("");
    setForm(emptyForm(meta?.kinds[0]?.kind ?? "webhook"));
    setOpen(true);
  }

  function openEdit(ch: NotificationChannel) {
    setEditing(ch);
    setSavedURL(String(ch.config.url ?? ""));
    // On the backend, filter is a Go struct and is always serialized as an object (never null), so no fallback is needed.
    const f = ch.filter;
    setForm({
      name: ch.name,
      kind: ch.kind,
      mode: ch.mode,
      enabled: ch.enabled,
      ratePerMin: String(ch.rate_per_min),
      // The backend echoes back credentials in config as masked values; they are placed into the form as-is and sent back unchanged on submit,
      // which tells the backend to keep the original values stored in the database.
      config: { ...ch.config },
      minSeverity: f.min_severity ?? "",
      includeText: (f.vulnclass_include ?? []).join("\n"),
      excludeText: (f.vulnclass_exclude ?? []).join("\n"),
      taskIDsText: (f.task_ids ?? []).join(","),
      assetIDsText: (f.asset_ids ?? []).join(","),
      onStatusChange: f.on_status_change ?? false,
    });
    setOpen(true);
  }

  // buildConfig converts the form state into a channel config.
  //
  // The only rule, covering two kinds of values:
  //   - A masked value ("__masked__...") sent back unchanged → the backend interprets this as "this field was not modified; keep the original value in the database"
  //   - Everything else is submitted exactly as the user entered it; an empty string means "clear this field"
  //
  // The reason credential fields get no special treatment (such as "skip when the credential is left blank") is that doing so would make it **impossible to clear** them.
  // a mistakenly set key: no action in the UI can express "I want to delete it." Under the current rule,
  // clearing the input box is the same as clearing the field, which gives a single unambiguous meaning that the user controls.
  // The masked value never appears in the input box (see ConfigField), so "there is text in the box" always means
  // "the user typed it on purpose."
  function buildConfig(): Record<string, unknown> {
    const defs = CHANNEL_FIELDS[form.kind] ?? [];
    const out: Record<string, unknown> = {};
    for (const d of defs) {
      const raw = form.config[d.key];
      if (d.kind === "switch") {
        out[d.key] = raw === true;
        continue;
      }
      if (typeof raw === "string" && raw.startsWith("__masked__")) {
        out[d.key] = raw;
        continue;
      }
      if (d.kind === "number") {
        const n = Number(raw);
        out[d.key] = Number.isFinite(n) && n > 0 ? n : 0;
        continue;
      }
      if (d.kind === "kv") {
        out[d.key] = parseKV(String(raw ?? ""));
        continue;
      }
      if (d.kind === "list") {
        out[d.key] = String(raw ?? "")
          .split(/[\s,\uff0c]+/)
          .map((s) => s.trim())
          .filter(Boolean);
        continue;
      }
      out[d.key] = String(raw ?? "").trim();
    }
    return out;
  }

  function buildFilter(): NotificationFilter {
    return {
      min_severity: form.minSeverity || undefined,
      vulnclass_include: parseKeywords(form.includeText),
      vulnclass_exclude: parseKeywords(form.excludeText),
      task_ids: parseIDs(form.taskIDsText),
      asset_ids: parseIDs(form.assetIDsText),
      on_status_change: form.onStatusChange,
    };
  }

  async function saveForm() {
    if (!form.name.trim()) {
      toast.error(t("toast.nameRequired"));
      return;
    }
    setSaving(true);
    try {
      const payload = {
        name: form.name.trim(),
        kind: form.kind,
        mode: form.mode,
        enabled: form.enabled,
        config: buildConfig(),
        filter: buildFilter(),
        rate_per_min: form.ratePerMin.trim() === "" ? undefined : Number(form.ratePerMin),
      };
      if (editing) {
        await api.notifyUpdateChannel(editing.id, payload);
        toast.success(t("toast.saved"));
        setOpen(false);
      } else {
        await api.notifyCreateChannel(payload);
        toast.success(t("toast.channelAdded"));
        setOpen(false);
      }
      load();
    } catch (e) {
      toast.error(t("toast.saveFailed", { msg: (e as Error).message }));
    } finally {
      setSaving(false);
    }
  }

  async function testChannel() {
    if (!editing) return;
    setTesting(true);
    try {
      const r = await api.notifyTestChannel(editing.id);
      toast.success(t("toast.testSent", { ms: r.latency_ms }));
    } catch (e) {
      // The backend passes through the channel's raw error verbatim; it is the only clue for troubleshooting the configuration, so display it as-is.
      toast.error(t("toast.testFailed", { msg: (e as Error).message }), { duration: 12000 });
    } finally {
      setTesting(false);
    }
  }

  async function removeChannel(ch: NotificationChannel) {
    try {
      await api.notifyDeleteChannel(ch.id);
      toast.success(t("toast.deleted", { name: ch.name }));
      setOpen(false);
      load();
    } catch (e) {
      toast.error(t("toast.deleteFailed", { msg: (e as Error).message }));
    }
  }

  async function toggleEnabled(ch: NotificationChannel) {
    try {
      await api.notifyUpdateChannel(ch.id, { enabled: !ch.enabled });
      load();
    } catch (e) {
      toast.error(t("toast.actionFailed", { msg: (e as Error).message }));
    }
  }

  async function toggleGlobal(on: boolean) {
    setGlobalSaving(true);
    try {
      await api.setSettings({ notify_enabled: on });
      setMeta((m) => (m ? { ...m, enabled: on } : m));
      toast.success(on ? t("toast.globalOn") : t("toast.globalOff"));
    } catch (e) {
      toast.error(t("toast.actionFailed", { msg: (e as Error).message }));
    } finally {
      setGlobalSaving(false);
    }
  }

  async function saveGlobal() {
    setGlobalSaving(true);
    try {
      const patch: Record<string, unknown> = { notify_public_base_url: baseURL.trim() };
      const n = Number(digestMin);
      if (Number.isFinite(n) && n > 0) patch.notify_digest_interval_min = n;
      await api.setSettings(patch);
      toast.success(t("toast.saved"));
      load();
    } catch (e) {
      toast.error(t("toast.saveFailed", { msg: (e as Error).message }));
    } finally {
      setGlobalSaving(false);
    }
  }

  const fields = CHANNEL_FIELDS[form.kind] ?? [];
  const secretKeys = new Set(meta?.kinds.find((k) => k.kind === form.kind)?.secret_keys ?? []);
  const defaultRate = meta?.kinds.find((k) => k.kind === form.kind)?.default_rate_per_min ?? 0;
  // The webhook URL is both the destination and a credential, so it is echoed masked
  // and so are the headers. Editing the address drops the stored headers: they were
  // the old address's credential and must not travel to the new one.
  const urlChanged = editing?.kind === "webhook" && form.config.url !== savedURL;
  const maskedHeaders = typeof form.config.headers === "string" && form.config.headers.startsWith("__masked__");

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="font-semibold text-lg tracking-tight">{t("title")}</h1>
          <p className="text-muted-foreground text-xs">{t("subtitle")}</p>
        </div>
        {meta && (
          // Use a div instead of a label: Switch already has an aria-label, and wrapping it in another label would
          // It isn't associated with any native control, yet clicking the text would make it look like it should toggle something.
          <div className="flex shrink-0 items-center gap-2 text-sm">
            <span className="text-muted-foreground">{t("globalSwitch")}</span>
            <Switch
              checked={meta.enabled}
              disabled={globalSaving}
              onCheckedChange={toggleGlobal}
              aria-label={t("aria.globalSwitch")}
            />
          </div>
        )}
      </div>

      {meta && (
        <dl className="grid grid-cols-2 gap-x-4 gap-y-3 sm:grid-cols-3 lg:grid-cols-5">
          <StatTile
            label={t("stats.channels")}
            value={`${meta.stats.channels_on} / ${meta.stats.channels}`}
            hint={t("stats.channelsHint")}
          />
          <StatTile label={t("stats.sentToday")} value={String(meta.stats.sent_today)} />
          <StatTile label={t("stats.pending")} value={String(meta.stats.pending)} />
          <StatTile
            label={t("stats.failed")}
            value={String(meta.stats.failed)}
            tone={meta.stats.failed > 0 ? "red" : undefined}
          />
          <StatTile
            label={t("stats.backlog")}
            value={formatBacklog(meta.stats.backlog_age_ms, t)}
            // The backlog's age is far more useful than its item count: a backlog of 3 items could span anywhere from 3 seconds to 3 hours.
            hint={meta.stats.backlog_age_ms > 5 * 60_000 ? t("stats.backlogStuck") : undefined}
            tone={meta.stats.backlog_age_ms > 5 * 60_000 ? "red" : undefined}
          />
        </dl>
      )}

      <section className="border-border border-t pt-3">
        <h2 className="mb-3 font-semibold text-xs">{t("global.title")}</h2>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="n-base">{t("global.baseUrl")}</Label>
            <Input
              id="n-base"
              placeholder="https://console.example.com"
              value={baseURL}
              onChange={(e) => setBaseURL(e.target.value)}
            />
            <p className="text-muted-foreground text-xs">{t("global.baseUrlHint")}</p>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="n-digest">{t("global.digest")}</Label>
            <Input
              id="n-digest"
              type="number"
              min={1}
              max={1440}
              placeholder="30"
              value={digestMin}
              onChange={(e) => setDigestMin(e.target.value)}
            />
            <p className="text-muted-foreground text-xs">{t("global.digestHint")}</p>
          </div>
          <div className="sm:col-span-2">
            <Button onClick={saveGlobal} disabled={globalSaving}>
              {t("global.save")}
            </Button>
          </div>
        </div>
      </section>

      <Tabs value={tab} onValueChange={(v) => setTab(v as "channels" | "deliveries")} className="flex flex-col gap-4">
        <TabsList>
          <TabsTrigger value="channels">{t("tab.channels")}</TabsTrigger>
          <TabsTrigger value="deliveries">{t("tab.deliveries")}</TabsTrigger>
        </TabsList>

        <TabsContent value="channels">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            <button
              type="button"
              onClick={openAdd}
              className="flex min-h-[104px] flex-col items-center justify-center gap-2 border border-border border-dashed text-muted-foreground transition-colors hover:bg-muted/40 hover:text-foreground"
            >
              <PlusIcon className="size-5" />
              <span className="text-sm">{t("addChannel")}</span>
            </button>

            {channels.map((ch) => (
              <div key={ch.id} className="relative flex min-w-0 flex-col border border-border p-3">
                <button
                  type="button"
                  onClick={() => openEdit(ch)}
                  className="flex min-w-0 flex-col gap-3 text-left outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <div className="flex min-w-0 items-center gap-2 pr-24">
                    <BellIcon className="size-4 shrink-0 text-muted-foreground" />
                    <span className="truncate font-medium text-sm">{ch.name}</span>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="outline">{kindLabel(ch.kind)}</Badge>
                    <Badge variant="outline">{ch.mode === "digest" ? t("mode.digest") : t("mode.realtime")}</Badge>
                    {!ch.enabled && <Badge variant="outline">{t("disabled")}</Badge>}
                  </div>
                  <FilterSummary filter={ch.filter} />
                </button>
                {/* Controls sit above the card button so a toggle or delete never also opens the editor. */}
                <div className="absolute top-3 right-3 flex items-center gap-2">
                  <Switch
                    checked={ch.enabled}
                    onCheckedChange={() => toggleEnabled(ch)}
                    aria-label={t("aria.enable")}
                  />
                  <Button
                    size="icon"
                    variant="outline"
                    aria-label={t("aria.delete")}
                    onClick={() => {
                      // void explicitly discards the Promise: removeChannel handles its own catch and shows a toast,
                      // No await is needed here (onClick is not async).
                      void removeChannel(ch);
                    }}
                  >
                    <Trash2Icon className="text-destructive" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="deliveries">
          <DeliveryList channels={channels} />
        </TabsContent>
      </Tabs>

      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent side="right" className="w-full data-[side=right]:sm:max-w-lg">
          <SheetHeader>
            <SheetTitle>{editing ? editing.name : t("sheet.addTitle")}</SheetTitle>
            <SheetDescription>
              {kindLabel(form.kind)}
              {defaultRate > 0 ? t("sheet.rateLimited", { rate: defaultRate }) : t("sheet.rateUnlimited")}
            </SheetDescription>
          </SheetHeader>

          <div className="flex min-h-0 flex-1 flex-col overflow-y-auto px-4">
            <div className="grid gap-4 py-4">
              <div className="grid gap-2">
                <Label>{t("sheet.kindLabel")}</Label>
                <Select
                  value={form.kind}
                  onValueChange={(v) => {
                    // Changing the type means switching to an entirely different set of credential fields, so the old configuration must not be merged in.
                    setF({ kind: v, config: {} });
                  }}
                  disabled={!!editing}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {(meta?.kinds ?? []).map((k) => (
                      <SelectItem key={k.kind} value={k.kind}>
                        {kindLabel(k.kind)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {editing && <p className="text-muted-foreground text-xs">{t("sheet.kindLocked")}</p>}
              </div>

              <div className="grid gap-2">
                <Label htmlFor="n-name">{t("sheet.nameLabel")}</Label>
                <Input
                  id="n-name"
                  placeholder={t("sheet.namePlaceholder")}
                  value={form.name}
                  onChange={(e) => setF({ name: e.target.value })}
                />
              </div>

              {fields.length === 0 ? (
                <p className="text-muted-foreground text-sm">{t("sheet.noFields")}</p>
              ) : (
                fields.map((d) => (
                  <ConfigField
                    key={d.key}
                    def={d}
                    value={form.config[d.key]}
                    isSecret={secretKeys.has(d.key)}
                    onChange={(v) => setCfg(d.key, v)}
                  />
                ))
              )}

              {urlChanged && maskedHeaders && (
                <p className="text-warning text-xs">{t("sheet.headersClearedOnUrlChange")}</p>
              )}

              <div className="grid gap-2">
                <Label>{t("sheet.modeLabel")}</Label>
                <Select value={form.mode} onValueChange={(v) => setF({ mode: v as "realtime" | "digest" })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="realtime">{t("sheet.modeRealtime")}</SelectItem>
                    <SelectItem value="digest">{t("sheet.modeDigest")}</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-muted-foreground text-xs">{t("sheet.modeHint")}</p>
              </div>

              <div className="grid gap-2">
                <Label htmlFor="n-rate">{t("sheet.rateLabel")}</Label>
                <Input
                  id="n-rate"
                  type="number"
                  min={0}
                  placeholder={defaultRate > 0 ? String(defaultRate) : t("sheet.ratePlaceholder")}
                  value={form.ratePerMin}
                  onChange={(e) => setF({ ratePerMin: e.target.value })}
                />
                <p className="text-muted-foreground text-xs">{t("sheet.rateHint")}</p>
              </div>

              <div className="border-t pt-4">
                <p className="mb-3 font-medium text-sm">{t("filter.title")}</p>
                <div className="grid gap-4">
                  <div className="grid gap-2">
                    <Label>{t("filter.minSeverity")}</Label>
                    <Select
                      value={form.minSeverity || "all"}
                      onValueChange={(v) => setF({ minSeverity: v === "all" ? "" : v })}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {SEVERITY_OPTIONS.map((o) => (
                          <SelectItem key={o.value || "all"} value={o.value || "all"}>
                            {t(o.label)}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="n-inc">{t("filter.includeLabel")}</Label>
                    <Textarea
                      id="n-inc"
                      placeholder={t("filter.includePlaceholder")}
                      value={form.includeText}
                      onChange={(e) => setF({ includeText: e.target.value })}
                    />
                    <p className="text-muted-foreground text-xs">{t("filter.includeHint")}</p>
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="n-exc">{t("filter.excludeLabel")}</Label>
                    <Textarea
                      id="n-exc"
                      placeholder={t("filter.excludePlaceholder")}
                      value={form.excludeText}
                      onChange={(e) => setF({ excludeText: e.target.value })}
                    />
                    <p className="text-muted-foreground text-xs">{t("filter.excludeHint")}</p>
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="n-tasks">{t("filter.taskIds")}</Label>
                    <Input
                      id="n-tasks"
                      placeholder="1, 2, 3"
                      value={form.taskIDsText}
                      onChange={(e) => setF({ taskIDsText: e.target.value })}
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="n-assets">{t("filter.assetIds")}</Label>
                    <Input
                      id="n-assets"
                      placeholder="10, 11"
                      value={form.assetIDsText}
                      onChange={(e) => setF({ assetIDsText: e.target.value })}
                    />
                    <p className="text-muted-foreground text-xs">{t("filter.idsHint")}</p>
                  </div>
                  <div className="flex items-center gap-2 text-sm">
                    <Switch
                      checked={form.onStatusChange}
                      onCheckedChange={(v) => setF({ onStatusChange: v })}
                      aria-label={t("aria.statusChange")}
                    />
                    {t("filter.onStatusChange")}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2 text-sm">
                <Switch
                  checked={form.enabled}
                  onCheckedChange={(v) => setF({ enabled: v })}
                  aria-label={t("aria.enable")}
                />
                {t("sheet.enable")}
              </div>
            </div>

            <div className="flex gap-2 pt-2 pb-6">
              <Button onClick={saveForm} disabled={saving}>
                {editing ? t("sheet.save") : t("sheet.add")}
              </Button>
              {editing && (
                <Button variant="outline" onClick={testChannel} disabled={testing}>
                  <SendIcon /> {t("sheet.sendTest")}
                </Button>
              )}
            </div>
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
