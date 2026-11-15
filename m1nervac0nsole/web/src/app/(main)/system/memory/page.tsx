"use client";

import * as React from "react";

import { useTranslations } from "next-intl";

import { CuratorChat } from "@/components/curator-chat";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { Company, Task } from "@/lib/types";

import { KnowledgePane } from "./_components/knowledge-pane";
import { PreviewPane } from "./_components/preview-pane";
import { ReflectionsPane } from "./_components/reflections-pane";

// MemoryPage is the operator surface over the knowledge base and the reflection
// pool: browse and curate entries, browse and graduate reflections, and check
// what a task's injection block would actually say. The curator is a tab beside
// the browser but can only propose - promotion stays an operator action.
export default function MemoryPage() {
  const t = useTranslations("memoryPage");
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [companies, setCompanies] = React.useState<Company[]>([]);

  React.useEffect(() => {
    api
      .tasks()
      .then((r) => setTasks(r.tasks))
      .catch(() => {
        /* pickers degrade to "no task selected" */
      });
    api
      .companies()
      .then(setCompanies)
      .catch(() => {
        /* a company scope just shows no options */
      });
  }, []);

  return (
    // Viewport-bounded workspace so the curator tab fills the height instead of
    // growing with its transcript.
    <div data-content-padding="false" className="flex h-[calc(100dvh-3rem)] min-w-0 flex-col overflow-hidden">
      <div className="flex shrink-0 flex-col gap-0.5 border-b px-4 py-2.5 lg:px-6">
        <h1 className="font-semibold text-sm leading-tight">{t("title")}</h1>
        <p className="text-[11px] text-muted-foreground">{t("subtitle")}</p>
      </div>

      <Tabs defaultValue="knowledge" className="flex min-h-0 min-w-0 flex-1 flex-col gap-0">
        <div className="border-b px-4 pt-2 lg:px-6">
          <TabsList variant="line">
            <TabsTrigger value="knowledge">{t("tab.knowledge")}</TabsTrigger>
            <TabsTrigger value="reflections">{t("tab.reflections")}</TabsTrigger>
            <TabsTrigger value="preview">{t("tab.preview")}</TabsTrigger>
            <TabsTrigger value="curator">{t("tab.curator")}</TabsTrigger>
          </TabsList>
        </div>
        <TabsContent value="knowledge" className="flex min-h-0 flex-1 flex-col overflow-hidden">
          <KnowledgePane tasks={tasks} companies={companies} />
        </TabsContent>
        <TabsContent value="reflections" className="flex min-h-0 flex-1 flex-col overflow-hidden">
          <ReflectionsPane tasks={tasks} />
        </TabsContent>
        <TabsContent value="preview" className="flex min-h-0 flex-1 flex-col overflow-hidden">
          <PreviewPane tasks={tasks} />
        </TabsContent>
        <TabsContent value="curator" className="flex min-h-0 flex-1 flex-col overflow-hidden">
          <CuratorChat agentKey="curator" i18n="memoryPage" />
        </TabsContent>
      </Tabs>
    </div>
  );
}
