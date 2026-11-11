"use client";

import * as React from "react";

import { EyeIcon, Loader2Icon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api } from "@/lib/api";
import type { MemoryPreview, Task } from "@/lib/types";

// PreviewPane renders the exact memory block a task would receive at start and
// before each round, plus which entries fed it. Read-only by design: it is the
// injection path's own output, not a simulation of it.
export function PreviewPane({ tasks }: { tasks: Task[] }) {
  const t = useTranslations("memoryPage");
  const [taskId, setTaskId] = React.useState(0);
  const [preview, setPreview] = React.useState<MemoryPreview | null>(null);
  const [loading, setLoading] = React.useState(false);

  async function load() {
    if (taskId <= 0) return;
    setLoading(true);
    try {
      setPreview(await api.memoryPreview(taskId));
    } catch (e) {
      toast.error(t("preview.failed", { msg: (e as Error).message }));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b px-4 py-3 lg:px-6">
        <Select value={String(taskId)} onValueChange={(v) => setTaskId(Number(v))}>
          <SelectTrigger size="sm" className="h-8 w-64 text-xs">
            <SelectValue placeholder={t("preview.pickTask")} />
          </SelectTrigger>
          <SelectContent>
            {tasks.map((task) => (
              <SelectItem key={task.id} value={task.id}>
                {task.name || task.description || `#${task.id}`}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button size="sm" className="h-8 text-xs" onClick={() => void load()} disabled={loading || taskId <= 0}>
          {loading ? <Loader2Icon className="size-3.5 animate-spin" /> : <EyeIcon className="size-3.5" />}
          {t("preview.load")}
        </Button>
        {preview && (
          <Badge variant={preview.mode === "inject" ? "default" : "outline"} className="px-1.5 py-0 text-[10px]">
            {preview.mode === "inject" ? t("preview.modeInject") : t("preview.modeOff")}
          </Badge>
        )}
        {preview && (
          <span className="text-[11px] text-muted-foreground">
            {t("preview.counts", {
              knowledge: preview.knowledge_ids.length,
              reflections: preview.reflection_ids.length,
            })}
          </span>
        )}
      </div>

      <div className="min-h-0 flex-1 space-y-4 overflow-auto px-4 py-3 lg:px-6">
        {!preview ? (
          <p className="py-10 text-center text-muted-foreground text-sm">{t("preview.empty")}</p>
        ) : (
          <>
            <section className="space-y-1.5">
              <p className="font-medium text-xs">{t("preview.startBlock")}</p>
              <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-md border bg-muted/40 p-3 font-mono text-[11px] leading-relaxed">
                {preview.start_block || t("preview.none")}
              </pre>
            </section>
            <section className="space-y-1.5">
              <p className="font-medium text-xs">{t("preview.roundBlock")}</p>
              <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-md border bg-muted/40 p-3 font-mono text-[11px] leading-relaxed">
                {preview.round_block || t("preview.none")}
              </pre>
            </section>
            <section className="space-y-1 text-[11px] text-muted-foreground">
              <p>
                {t("preview.knowledgeIds")}: {preview.knowledge_ids.join(", ") || "-"}
              </p>
              <p>
                {t("preview.reflectionIds")}: {preview.reflection_ids.join(", ") || "-"}
              </p>
            </section>
          </>
        )}
      </div>
    </div>
  );
}
