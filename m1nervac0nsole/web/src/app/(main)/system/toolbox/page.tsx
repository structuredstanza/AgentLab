"use client";

import * as React from "react";

import { PlusIcon, SearchIcon, SparklesIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { CuratorChat } from "@/components/curator-chat";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { Agent, Tool, ToolManifest } from "@/lib/types";

import { AgentTools, matchesTool, ToolGridCard } from "./_components/agent-tools";
import { CustomToolDialog } from "./_components/custom-tool-dialog";
import { IngestToolDialog } from "./_components/ingest-tool-dialog";
import { TemplateCard, TemplateSheet } from "./_components/template-sheet";

// The tool curator reads the toolbox freely and proposes templates or custom
// tools behind an approval card; it never writes on its own.
const TOOL_CURATOR_AGENT = "toolcurator";

type TabKey = "catalog" | "agent-tools" | "curator";

// ToolboxPage is the one tooling surface: the catalog of command templates and
// custom tools, the system tools agents are bound to, and the curator that
// registers new tooling on request.
export default function ToolboxPage() {
  const t = useTranslations("toolboxPage");
  const [tab, setTab] = React.useState<TabKey>("catalog");
  const [tools, setTools] = React.useState<Tool[]>([]);
  const [manifests, setManifests] = React.useState<ToolManifest[]>([]);
  const [agents, setAgents] = React.useState<Agent[]>([]);
  const [captureOn, setCaptureOn] = React.useState(false);
  const [loading, setLoading] = React.useState(true);
  const [loadError, setLoadError] = React.useState("");
  const [query, setQuery] = React.useState("");
  const [templateEdit, setTemplateEdit] = React.useState<ToolManifest | "new" | null>(null);
  const [customEdit, setCustomEdit] = React.useState<Tool | "new" | null>(null);
  const [ingestOpen, setIngestOpen] = React.useState(false);
  const [outbox, setOutbox] = React.useState<{ id: number; text: string } | null>(null);

  // A failed load must read as a failure: an empty catalog would look like
  // "nothing is installed" and invite the operator to re-create what exists.
  const reload = React.useCallback(() => {
    setLoadError("");
    Promise.all([api.tools(), api.toolManifests()])
      .then(([toolRows, manifestRows]) => {
        setTools(toolRows);
        setManifests(manifestRows);
      })
      .catch((e: Error) => setLoadError(e.message))
      .finally(() => setLoading(false));
  }, []);
  React.useEffect(() => {
    reload();
    api
      .agents()
      .then(setAgents)
      .catch(() => {
        /* Ignore lookup failures and keep the default state */
      });
    api
      .settings()
      .then((s) => setCaptureOn(!!s.traffic_capture))
      .catch(() => {
        /* Ignore lookup failures and keep the default state */
      });
  }, [reload]);

  const q = query.trim().toLowerCase();
  const visibleTemplates = manifests.filter(
    (m) => !q || `${m.id} ${m.name} ${m.description} ${m.category}`.toLowerCase().includes(q),
  );
  const customTools = tools.filter((x) => !x.system);
  const visibleCustom = customTools.filter((x) => matchesTool(x, query));
  const total = manifests.length + customTools.length;
  const shown = visibleTemplates.length + visibleCustom.length;

  const failure = (
    <p role="alert" className="border border-destructive/40 bg-destructive/10 px-3 py-2 text-destructive text-sm">
      {t("loadFailed", { msg: loadError })}{" "}
      <Button size="sm" variant="outline" onClick={reload}>
        {t("retry")}
      </Button>
    </p>
  );

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="font-semibold text-lg tracking-tight">{t("title")}</h1>
          <p className="text-muted-foreground text-xs">{t("subtitle")}</p>
        </div>
        {tab !== "curator" && (
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative w-full max-w-64">
              <SearchIcon className="absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                className="h-8 pl-8 text-sm"
                aria-label={t("search")}
                placeholder={t("search")}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </div>
            {tab === "catalog" && (
              <>
                <Button size="sm" variant="outline" onClick={() => setTemplateEdit("new")}>
                  <PlusIcon /> {t("newTemplate")}
                </Button>
                <Button size="sm" onClick={() => setCustomEdit("new")}>
                  <PlusIcon /> {t("newCustom")}
                </Button>
              </>
            )}
          </div>
        )}
        {tab === "curator" && (
          <Button size="sm" onClick={() => setIngestOpen(true)}>
            <SparklesIcon /> {t("ingest.action")}
          </Button>
        )}
      </div>

      <Tabs value={tab} onValueChange={(v) => setTab(v as TabKey)}>
        <TabsList>
          <TabsTrigger value="catalog">{t("tabCatalog")}</TabsTrigger>
          <TabsTrigger value="agent-tools">{t("tabAgentTools")}</TabsTrigger>
          <TabsTrigger value="curator">{t("tabCurator")}</TabsTrigger>
        </TabsList>

        <TabsContent value="catalog">
          <section className="border-border border-t pt-3">
            {loadError ? (
              failure
            ) : (
              <>
                <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
                  <h2 className="font-semibold text-xs">{t("tabCatalog")}</h2>
                  <span className="text-[11px] text-muted-foreground">
                    {q ? t("catalogMatched", { shown, total }) : t("catalogTotal", { total })}
                  </span>
                </div>
                {loading ? (
                  <p className="py-6 text-center text-muted-foreground text-sm">{t("loading")}</p>
                ) : shown === 0 ? (
                  <p className="py-6 text-center text-muted-foreground text-sm">{q ? t("empty") : t("catalogEmpty")}</p>
                ) : (
                  <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                    {visibleTemplates.map((m) => (
                      <TemplateCard key={`template-${m.id}`} manifest={m} onClick={() => setTemplateEdit(m)} />
                    ))}
                    {visibleCustom.map((tool) => (
                      <ToolGridCard key={`tool-${tool.key}`} tool={tool} onClick={() => setCustomEdit(tool)} />
                    ))}
                  </div>
                )}
              </>
            )}
          </section>
        </TabsContent>

        <TabsContent value="agent-tools">
          {loadError ? (
            <section className="border-border border-t pt-3">{failure}</section>
          ) : (
            <AgentTools tools={tools} agents={agents} captureOn={captureOn} query={query} onChanged={reload} />
          )}
        </TabsContent>

        <TabsContent value="curator">
          <section className="border-border border-t pt-3">
            <div className="flex h-[70dvh] min-h-96 flex-col border border-border">
              <CuratorChat agentKey={TOOL_CURATOR_AGENT} i18n="toolboxPage" outbox={outbox} />
            </div>
          </section>
        </TabsContent>
      </Tabs>

      <IngestToolDialog
        open={ingestOpen}
        onClose={() => setIngestOpen(false)}
        onSubmit={(text) => {
          setOutbox({ id: Date.now(), text });
          setIngestOpen(false);
        }}
      />

      <TemplateSheet edit={templateEdit} onClose={() => setTemplateEdit(null)} onChanged={reload} />

      <CustomToolDialog
        edit={customEdit}
        agents={agents}
        onClose={() => setCustomEdit(null)}
        onSaved={() => {
          setCustomEdit(null);
          reload();
        }}
      />
    </div>
  );
}
