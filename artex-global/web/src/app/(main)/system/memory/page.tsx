"use client";

import * as React from "react";

import { MessageSquareIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { Company, Task } from "@/lib/types";

import { CuratorChat } from "./_components/curator-chat";
import { KnowledgePane } from "./_components/knowledge-pane";
import { PreviewPane } from "./_components/preview-pane";
import { ReflectionsPane } from "./_components/reflections-pane";

// MemoryPage is the operator surface over the knowledge base and the reflection
// pool: browse and curate entries, browse and graduate reflections, and check
// what a task's injection block would actually say. The curator chat sits beside
// the browser but can only propose - promotion stays an operator action.
export default function MemoryPage() {
  const t = useTranslations("memoryPage");
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [companies, setCompanies] = React.useState<Company[]>([]);
  const [chatOpen, setChatOpen] = React.useState(true);

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
    <div data-content-padding="false" className="flex flex-1 flex-col overflow-hidden">
      <div className="flex items-center gap-3 border-b px-4 py-2.5 lg:px-6">
        <div className="flex flex-col gap-0.5">
          <h1 className="font-semibold text-sm leading-tight">{t("title")}</h1>
          <p className="text-[11px] text-muted-foreground">{t("subtitle")}</p>
        </div>
        <Button
          size="sm"
          variant={chatOpen ? "secondary" : "outline"}
          className="ml-auto hidden h-7 text-xs lg:inline-flex"
          aria-pressed={chatOpen}
          onClick={() => setChatOpen((v) => !v)}
        >
          <MessageSquareIcon className="size-3.5" />
          {t("chat.toggle")}
        </Button>
      </div>

      <div className="flex min-h-0 flex-1 overflow-hidden">
        <Tabs defaultValue="knowledge" className="flex min-h-0 min-w-0 flex-1 flex-col gap-0">
          <div className="border-b px-4 pt-2 lg:px-6">
            <TabsList variant="line">
              <TabsTrigger value="knowledge">{t("tab.knowledge")}</TabsTrigger>
              <TabsTrigger value="reflections">{t("tab.reflections")}</TabsTrigger>
              <TabsTrigger value="preview">{t("tab.preview")}</TabsTrigger>
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
        </Tabs>

        {chatOpen && (
          <div className="hidden w-90 shrink-0 flex-col border-l lg:flex">
            <CuratorChat />
          </div>
        )}
      </div>
    </div>
  );
}
