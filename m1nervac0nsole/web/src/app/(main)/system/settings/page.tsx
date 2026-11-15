"use client";

import * as React from "react";

import { CpuIcon, FlaskConicalIcon, KeyboardIcon, RadioTowerIcon, SearchIcon, ShieldAlertIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import { type ChatSendMode, setChatSendMode, useChatSendMode, useChatSendModeOptions } from "@/lib/chat-send-mode";
import type { Settings } from "@/lib/types";
import { cn } from "@/lib/utils";

// One settings group: a hairline rule and a heading, not a nested card. The
// multi-column parent below balances these by content height.
function Section({
  icon: Icon,
  title,
  desc,
  descId,
  children,
  className,
}: {
  icon: React.ElementType;
  title: React.ReactNode;
  desc: React.ReactNode;
  descId?: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className="mb-4 break-inside-avoid border-border border-t pt-3 md:mb-6">
      <div className="flex items-center gap-1.5 font-semibold text-xs">
        <Icon className="size-3.5 shrink-0 text-muted-foreground" />
        {title}
      </div>
      <p id={descId} className="mt-1 text-muted-foreground text-xs leading-relaxed">
        {desc}
      </p>
      <div className={cn("mt-3 flex flex-col gap-3", className)}>{children}</div>
    </section>
  );
}

export default function SystemSettingsPage() {
  const t = useTranslations("settingsPage");
  const richTags = {
    b: (chunks: React.ReactNode) => <b>{chunks}</b>,
    br: () => <br />,
    code: (chunks: React.ReactNode) => <span className="font-mono">{chunks}</span>,
  };
  const [trafficCapture, setTrafficCapture] = React.useState(false);
  const [agentTrafficBinding, setAgentTrafficBinding] = React.useState(false);
  const [webSearch, setWebSearch] = React.useState(false);
  const [backend, setBackend] = React.useState("ddgs");
  const [braveKeySet, setBraveKeySet] = React.useState(false);
  const [braveKeyInput, setBraveKeyInput] = React.useState("");
  const [tavilyKeySet, setTavilyKeySet] = React.useState(false);
  const [tavilyKeyInput, setTavilyKeyInput] = React.useState("");
  const [savingTavilyKey, setSavingTavilyKey] = React.useState(false);
  const [proxyInput, setProxyInput] = React.useState("");
  const [savingProxy, setSavingProxy] = React.useState(false);
  const [globalProxyInput, setGlobalProxyInput] = React.useState("");
  const [savingGlobalProxy, setSavingGlobalProxy] = React.useState(false);
  const [testing, setTesting] = React.useState(false);
  const [loaded, setLoaded] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [savingKey, setSavingKey] = React.useState(false);
  const [pyInterp, setPyInterp] = React.useState("");
  const [workers, setWorkers] = React.useState("3");
  const [savingWorkers, setSavingWorkers] = React.useState(false);
  // Scope for operation-constraint injection (all enabled by default).
  const [injectPlanner, setInjectPlanner] = React.useState(true);
  const [injectWorker, setInjectWorker] = React.useState(true);
  // Experimental feature: noa context compression (disabled by default).
  const [noaCompaction, setNoaCompaction] = React.useState(false);
  // Pure frontend preference: does not go through /api/settings; reads and writes localStorage directly.
  const sendMode = useChatSendMode();
  const sendModeOptions = useChatSendModeOptions();

  const apply = React.useCallback((s: Settings) => {
    setTrafficCapture(!!s.traffic_capture);
    setAgentTrafficBinding(!!s.agent_traffic_binding);
    setWebSearch(!!s.web_search_enabled);
    setBackend(s.web_search_backend || "ddgs");
    setBraveKeySet(!!s.brave_key_set);
    setTavilyKeySet(!!s.tavily_key_set);
    setProxyInput(s.web_search_proxy ?? "");
    setGlobalProxyInput(s.global_proxy ?? "");
    setPyInterp(s.python_interpreter ?? "");
    setWorkers(String(s.workers ?? 3));
    setInjectPlanner(s.constraints_inject_planner !== false);
    setInjectWorker(s.constraints_inject_worker !== false);
    setNoaCompaction(!!s.noa_compaction);
  }, []);

  const saveWorkers = () => {
    const n = Number(workers);
    if (!Number.isInteger(n) || n <= 0) {
      toast.error(t("toast.workersInvalid"));
      return;
    }
    setSavingWorkers(true);
    api
      .setSettings({ workers: n })
      .then((s) => {
        apply(s);
        toast.success(t("toast.workersSaved"));
      })
      .catch((e) => toast.error(t("toast.saveFailed", { error: (e as Error).message })))
      .finally(() => setSavingWorkers(false));
  };

  const savePython = () => {
    setSaving(true);
    api
      .setSettings({ python_interpreter: pyInterp.trim() })
      .then((s) => {
        apply(s);
        toast.success(t("toast.pythonSaved"));
      })
      .catch((e) => toast.error(t("toast.saveFailed", { error: (e as Error).message })))
      .finally(() => setSaving(false));
  };
  const detectPython = () => {
    setSaving(true);
    api
      .detectPython()
      .then((r) => setPyInterp(r.python_interpreter))
      .catch(() => undefined)
      .finally(() => setSaving(false));
  };

  React.useEffect(() => {
    api
      .settings()
      .then(apply)
      .catch(() => undefined)
      .finally(() => setLoaded(true));
  }, [apply]);

  const toggleTraffic = (v: boolean) => {
    setTrafficCapture(v); // optimistic
    setSaving(true);
    api
      .setSettings({ traffic_capture: v })
      .then(apply)
      .catch(() => setTrafficCapture(!v)) // revert on failure
      .finally(() => setSaving(false));
  };

  const toggleInjectPlanner = (v: boolean) => {
    setInjectPlanner(v); // optimistic
    api
      .setSettings({ constraints_inject_planner: v })
      .then(apply)
      .catch(() => setInjectPlanner(!v)); // revert on failure
  };

  const toggleAgentTrafficBinding = (v: boolean) => {
    setAgentTrafficBinding(v);
    setSaving(true);
    api
      .setSettings({ agent_traffic_binding: v })
      .then((s) => {
        apply(s);
        toast.success(v ? t("toast.bindingOn") : t("toast.bindingOff"));
      })
      .catch((e) => {
        setAgentTrafficBinding(!v);
        toast.error(t("toast.saveFailed", { error: (e as Error).message }));
      })
      .finally(() => setSaving(false));
  };

  const toggleInjectWorker = (v: boolean) => {
    setInjectWorker(v); // optimistic
    api
      .setSettings({ constraints_inject_worker: v })
      .then(apply)
      .catch(() => setInjectWorker(!v)); // revert on failure
  };

  const toggleNoaCompaction = (v: boolean) => {
    setNoaCompaction(v); // optimistic
    api
      .setSettings({ noa_compaction: v })
      .then((s) => {
        apply(s);
        toast.success(v ? t("toast.noaOn") : t("toast.noaOff"));
      })
      .catch((e) => {
        setNoaCompaction(!v); // revert on failure
        toast.error(t("toast.saveFailed", { error: (e as Error).message }));
      });
  };

  // Persist a web-search patch (enable and/or backend). Optimistic with refetch.
  const saveWebSearch = (patch: Partial<Settings>) => {
    setSaving(true);
    api
      .setSettings(patch)
      .then((s) => {
        apply(s);
        toast.success(t("toast.webSearchSaved"));
      })
      .catch((e) => {
        toast.error(t("toast.saveFailed", { error: (e as Error).message }));
        api
          .settings()
          .then(apply)
          .catch(() => undefined);
      })
      .finally(() => setSaving(false));
  };

  const saveBraveKey = () => {
    setSavingKey(true);
    api
      .setSettings({ brave_search_api_key: braveKeyInput })
      .then((s) => {
        apply(s);
        setBraveKeyInput("");
        toast.success(t("toast.braveKeySaved"));
      })
      .catch((e) => toast.error(t("toast.saveFailed", { error: (e as Error).message })))
      .finally(() => setSavingKey(false));
  };

  const saveTavilyKey = () => {
    setSavingTavilyKey(true);
    api
      .setSettings({ tavily_search_api_key: tavilyKeyInput })
      .then((s) => {
        apply(s);
        setTavilyKeyInput("");
        toast.success(t("toast.tavilyKeySaved"));
      })
      .catch((e) => toast.error(t("toast.saveFailed", { error: (e as Error).message })))
      .finally(() => setSavingTavilyKey(false));
  };

  const saveProxy = () => {
    setSavingProxy(true);
    api
      .setSettings({ web_search_proxy: proxyInput.trim() })
      .then((s) => {
        apply(s);
        toast.success(proxyInput.trim() ? t("toast.proxySaved") : t("toast.proxyCleared"));
      })
      .catch((e) => toast.error(t("toast.saveFailed", { error: (e as Error).message })))
      .finally(() => setSavingProxy(false));
  };

  const saveGlobalProxy = () => {
    setSavingGlobalProxy(true);
    api
      .setSettings({ global_proxy: globalProxyInput.trim() })
      .then((s) => {
        apply(s);
        toast.success(globalProxyInput.trim() ? t("toast.globalProxySaved") : t("toast.globalProxyCleared"));
      })
      .catch((e) => toast.error(t("toast.saveFailed", { error: (e as Error).message })))
      .finally(() => setSavingGlobalProxy(false));
  };

  // Run a real "test" search ("test") against the CURRENT form values (backend +
  // proxy + entered key), falling back to saved values server-side. Toasts result.
  const runTest = () => {
    setTesting(true);
    api
      .testWebSearch({
        web_search_backend: backend,
        web_search_proxy: proxyInput.trim(),
        brave_search_api_key: braveKeyInput,
        tavily_search_api_key: tavilyKeyInput,
      })
      .then((r) => {
        if (r.ok) toast.success(t("toast.testSuccess", { backend: r.backend ?? "", count: r.count ?? 0 }));
        else toast.error(t("toast.testFailed", { error: r.error || t("toast.testUnknownError") }));
      })
      .catch((e) => toast.error(t("toast.testFailed", { error: (e as Error).message })))
      .finally(() => setTesting(false));
  };

  // brave-free selected but no key stored and none being entered → tool stays off.
  const braveNeedsKey = webSearch && backend === "brave-free" && !braveKeySet;

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div>
        <h1 className="font-semibold text-lg tracking-tight">{t("title")}</h1>
        <p className="text-muted-foreground text-xs">{t("subtitle")}</p>
      </div>

      {/* Multi-column instead of grid: the web search section is several times taller than the rest, and its height changes with the selected backend (the brave/tavily
          key input is conditionally rendered). A grid would stretch every row to the tallest section and leave large empty areas beside the others, while
          multi-column automatically balances filling by content height. Section spacing uses mb rather than gap, because under multi-column layout
          column-gap only controls column spacing, so row spacing must be provided by the child elements themselves. */}
      <div className="columns-1 gap-4 md:gap-6 lg:columns-2">
        <Section icon={RadioTowerIcon} title={t("trafficCapture.title")} desc={t.rich("trafficCapture.desc", richTags)}>
          <div className="flex items-center justify-between gap-4">
            <Label htmlFor="traffic-capture" className="font-normal text-muted-foreground text-sm">
              {trafficCapture ? t("trafficCapture.on") : t("trafficCapture.off")}
            </Label>
            <Switch
              id="traffic-capture"
              checked={trafficCapture}
              disabled={!loaded || saving}
              onCheckedChange={toggleTraffic}
            />
          </div>
        </Section>

        <Section
          icon={RadioTowerIcon}
          title={t("agentBinding.title")}
          desc={t.rich("agentBinding.desc", richTags)}
          descId="agent-traffic-binding-description"
        >
          <div className="flex items-center justify-between gap-4">
            <Label htmlFor="agent-traffic-binding" className="font-normal text-muted-foreground text-sm">
              {agentTrafficBinding ? t("agentBinding.on") : t("agentBinding.off")}
            </Label>
            <Switch
              id="agent-traffic-binding"
              aria-describedby="agent-traffic-binding-description"
              checked={agentTrafficBinding}
              disabled={!loaded || saving}
              onCheckedChange={toggleAgentTrafficBinding}
            />
          </div>
        </Section>

        <Section icon={RadioTowerIcon} title={t("globalProxy.title")} desc={t.rich("globalProxy.desc", richTags)}>
          <div className="grid gap-2">
            <Label htmlFor="global-proxy" className="font-normal text-muted-foreground text-sm">
              {t("globalProxy.addrLabel")}
            </Label>
            <div className="flex flex-wrap items-center gap-2">
              <Input
                id="global-proxy"
                autoComplete="off"
                placeholder={t("globalProxy.placeholder")}
                value={globalProxyInput}
                disabled={!loaded || savingGlobalProxy}
                onChange={(e) => setGlobalProxyInput(e.target.value)}
                className="min-w-0 flex-1"
              />
              <Button type="button" onClick={saveGlobalProxy} disabled={!loaded || savingGlobalProxy}>
                {t("save")}
              </Button>
            </div>
            <p className="text-muted-foreground text-xs">
              {globalProxyInput.trim() ? t("globalProxy.configured") : t("globalProxy.notConfigured")}
            </p>
          </div>
        </Section>

        <Section icon={ShieldAlertIcon} title={t("constraints.title")} desc={t.rich("constraints.desc", richTags)}>
          <div className="flex items-center justify-between gap-4">
            <Label htmlFor="inject-planner" className="font-normal text-muted-foreground text-sm">
              {t("constraints.injectPlanner")}
              {injectPlanner ? t("onSuffix") : t("offSuffix")}
            </Label>
            <Switch
              id="inject-planner"
              checked={injectPlanner}
              disabled={!loaded}
              onCheckedChange={toggleInjectPlanner}
            />
          </div>
          <div className="flex items-center justify-between gap-4">
            <Label htmlFor="inject-worker" className="font-normal text-muted-foreground text-sm">
              {t("constraints.injectWorker")}
              {injectWorker ? t("onSuffix") : t("offSuffix")}
            </Label>
            <Switch id="inject-worker" checked={injectWorker} disabled={!loaded} onCheckedChange={toggleInjectWorker} />
          </div>
        </Section>

        <Section icon={FlaskConicalIcon} title={t("experimental.title")} desc={t.rich("experimental.desc", richTags)}>
          <div className="flex items-center justify-between gap-4">
            <Label htmlFor="noa-compaction" className="font-normal text-muted-foreground text-sm">
              {t("experimental.noaLabel")}
              {noaCompaction ? t("onSuffix") : t("offSuffix")}
            </Label>
            <Switch
              id="noa-compaction"
              checked={noaCompaction}
              disabled={!loaded}
              onCheckedChange={toggleNoaCompaction}
            />
          </div>
        </Section>

        <Section icon={SearchIcon} title={t("webSearch.title")} desc={t.rich("webSearch.desc", richTags)}>
          <div className="flex items-center justify-between gap-4">
            <Label htmlFor="web-search" className="font-normal text-muted-foreground text-sm">
              {webSearch ? t("webSearch.on") : t("webSearch.off")}
            </Label>
            <Switch
              id="web-search"
              checked={webSearch}
              disabled={!loaded || saving}
              onCheckedChange={(v) => {
                setWebSearch(v); // optimistic
                saveWebSearch({ web_search_enabled: v });
              }}
            />
          </div>

          {webSearch && (
            <div className="flex flex-wrap items-center justify-between gap-4">
              <Label className="font-normal text-muted-foreground text-sm">{t("webSearch.sourceLabel")}</Label>
              <Select
                value={backend}
                disabled={!loaded || saving}
                onValueChange={(v) => {
                  setBackend(v); // optimistic
                  saveWebSearch({ web_search_backend: v });
                }}
              >
                <SelectTrigger className="w-48 shrink-0">
                  <SelectValue placeholder={t("webSearch.sourcePlaceholder")} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ddgs">{t("webSearch.sourceDdgs")}</SelectItem>
                  <SelectItem value="brave-free">{t("webSearch.sourceBrave")}</SelectItem>
                  <SelectItem value="tavily">{t("webSearch.sourceTavily")}</SelectItem>
                  <SelectItem value="deepseek">{t("webSearch.sourceDeepseek")}</SelectItem>
                </SelectContent>
              </Select>
            </div>
          )}

          {webSearch && backend === "deepseek" && (
            <div className="flex flex-col gap-2 border-border border-l-2 pl-3">
              <p className="font-medium text-xs">{t("webSearch.deepseekTitle")}</p>
              <p className="text-muted-foreground text-xs leading-relaxed">
                {t.rich("webSearch.deepseekDesc1", richTags)}
              </p>
              <p className="text-muted-foreground text-xs leading-relaxed">
                {t.rich("webSearch.deepseekDesc2", richTags)}
              </p>
              <p className="text-muted-foreground text-xs leading-relaxed">{t("webSearch.deepseekDesc3")}</p>
            </div>
          )}

          {webSearch && backend === "brave-free" && (
            <div className="flex flex-col gap-2">
              <Label htmlFor="brave-key" className="font-normal text-muted-foreground text-sm">
                {t("webSearch.braveKeyLabel")}
                {braveKeySet && <span className="ml-2 text-success text-xs">{t("configured")}</span>}
              </Label>
              <div className="flex flex-wrap items-center gap-2">
                <Input
                  id="brave-key"
                  type="password"
                  autoComplete="off"
                  className="min-w-0 flex-1"
                  placeholder={
                    braveKeySet ? t("webSearch.braveKeyPlaceholderSet") : t("webSearch.braveKeyPlaceholderUnset")
                  }
                  value={braveKeyInput}
                  disabled={!loaded || savingKey}
                  onChange={(e) => setBraveKeyInput(e.target.value)}
                />
                <Button
                  type="button"
                  onClick={saveBraveKey}
                  disabled={!loaded || savingKey || braveKeyInput.trim() === ""}
                >
                  {t("save")}
                </Button>
              </div>
              {braveNeedsKey && <p className="text-warning text-xs">{t("webSearch.braveNeedsKey")}</p>}
              <p className="text-muted-foreground text-xs">{t("webSearch.braveQuota")}</p>
            </div>
          )}

          {webSearch && backend === "tavily" && (
            <div className="flex flex-col gap-2">
              <Label htmlFor="tavily-key" className="font-normal text-muted-foreground text-sm">
                {t("webSearch.tavilyKeyLabel")}
                {tavilyKeySet && <span className="ml-2 text-success text-xs">{t("configured")}</span>}
              </Label>
              <div className="flex flex-wrap items-center gap-2">
                <Input
                  id="tavily-key"
                  type="password"
                  autoComplete="off"
                  className="min-w-0 flex-1"
                  placeholder={
                    tavilyKeySet ? t("webSearch.tavilyKeyPlaceholderSet") : t("webSearch.tavilyKeyPlaceholderUnset")
                  }
                  value={tavilyKeyInput}
                  disabled={!loaded || savingTavilyKey}
                  onChange={(e) => setTavilyKeyInput(e.target.value)}
                />
                <Button
                  type="button"
                  onClick={saveTavilyKey}
                  disabled={!loaded || savingTavilyKey || tavilyKeyInput.trim() === ""}
                >
                  {t("save")}
                </Button>
              </div>
              {!tavilyKeySet && <p className="text-warning text-xs">{t("webSearch.tavilyNeedsKey")}</p>}
              <p className="text-muted-foreground text-xs">{t("webSearch.tavilyGetKey")}</p>
            </div>
          )}

          {webSearch && (
            <div className="flex flex-col gap-2">
              <Label htmlFor="ws-proxy" className="font-normal text-muted-foreground text-sm">
                {t("webSearch.proxyLabel")}
              </Label>
              <div className="flex flex-wrap items-center gap-2">
                <Input
                  id="ws-proxy"
                  autoComplete="off"
                  className="min-w-0 flex-1"
                  placeholder={t("webSearch.proxyPlaceholder")}
                  value={proxyInput}
                  disabled={!loaded || savingProxy}
                  onChange={(e) => setProxyInput(e.target.value)}
                />
                <Button type="button" onClick={saveProxy} disabled={!loaded || savingProxy}>
                  {t("save")}
                </Button>
              </div>
              <p className="text-muted-foreground text-xs">{t("webSearch.proxyHint")}</p>
            </div>
          )}

          {webSearch && (
            <div className="flex flex-wrap items-center justify-between gap-4 border-border border-t pt-3">
              <p className="text-muted-foreground text-xs">{t("webSearch.testHint")}</p>
              <Button
                type="button"
                variant="outline"
                onClick={runTest}
                disabled={!loaded || testing}
                className="shrink-0"
              >
                {testing ? t("webSearch.testRunning") : t("webSearch.testButton")}
              </Button>
            </div>
          )}
        </Section>

        <Section icon={RadioTowerIcon} title={t("python.title")} desc={t.rich("python.desc", richTags)}>
          <div className="flex flex-wrap items-center gap-2">
            <Input
              className="min-w-0 flex-1 font-mono text-sm"
              placeholder={t("python.placeholder")}
              value={pyInterp}
              disabled={!loaded || saving}
              onChange={(e) => setPyInterp(e.target.value)}
            />
            <Button variant="outline" onClick={detectPython} disabled={!loaded || saving}>
              {t("python.detect")}
            </Button>
            <Button onClick={savePython} disabled={!loaded || saving}>
              {t("save")}
            </Button>
          </div>
        </Section>

        <Section icon={CpuIcon} title={t("workers.title")} desc={t.rich("workers.desc", richTags)}>
          <div className="flex flex-wrap items-center gap-2">
            <Input
              type="number"
              min={1}
              className="w-32 font-mono text-sm"
              placeholder="3"
              value={workers}
              disabled={!loaded || savingWorkers}
              onChange={(e) => setWorkers(e.target.value)}
            />
            <Button onClick={saveWorkers} disabled={!loaded || savingWorkers}>
              {t("save")}
            </Button>
          </div>
        </Section>

        <Section icon={KeyboardIcon} title={t("sendKey.title")} desc={t.rich("sendKey.desc", richTags)}>
          <div className="flex flex-wrap items-center justify-between gap-4">
            <Label htmlFor="chat-send-mode" className="font-normal text-muted-foreground text-sm">
              {t("sendKey.label")}
            </Label>
            <Select value={sendMode} onValueChange={(v) => setChatSendMode(v as ChatSendMode)}>
              <SelectTrigger id="chat-send-mode" className="w-full max-w-72">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {sendModeOptions.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </Section>
      </div>
    </div>
  );
}
