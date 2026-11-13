"use client";

import * as React from "react";

import { EyeIcon, Loader2Icon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { getDateLocale } from "@/i18n/datetime";
import { api } from "@/lib/api";
import type { MemoryPreview, Task } from "@/lib/types";

function fmtDate(ts: string): string {
  return new Date(ts).toLocaleString(getDateLocale(), {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// PreviewPane renders the exact memory block a task would receive at start and
// before each round, plus which entries fed it. Read-only by design: it is the
// injection path's own output, not a simulation of it.
export function PreviewPane({ tasks }: { tasks: Task[] }) {
  const t = useTranslations("memoryPage");
  const [taskId, setTaskId] = React.useState(0);
  const [intentId, setIntentId] = React.useState(0);
  const [preview, setPreview] = React.useState<MemoryPreview | null>(null);
  const [loading, setLoading] = React.useState(false);

  async function load() {
    if (taskId <= 0) return;
    setLoading(true);
    try {
      setPreview(await api.memoryPreview(taskId, intentId));
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
        {/* Optional: with an intent id the second block is that worker's launch
            block, rendered as of its own first activity row. */}
        <Input
          className="h-8 w-32 text-xs"
          type="number"
          min={0}
          value={intentId || ""}
          onChange={(e) => setIntentId(Number(e.target.value) || 0)}
          placeholder={t("preview.intentPlaceholder")}
          aria-label={t("preview.intentPlaceholder")}
        />
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
        {preview?.as_of && (
          <span className="text-[11px] text-muted-foreground">
            {t("preview.asOf", { time: fmtDate(preview.as_of) })}
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
              <p className="font-medium text-xs">
                {preview.intent_id > 0
                  ? t("preview.launchBlock", { intent: preview.intent_id })
                  : t("preview.roundBlock")}
              </p>
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
