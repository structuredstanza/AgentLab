"use client";

import * as React from "react";

import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { TaskNode } from "@/lib/types";

const DONE_KEY = { pause: "live.paused", resume: "live.resumed", cancel: "live.cancelled" } as const;

// crypto.randomUUID is only available in a secure context (https/localhost); when
// accessed via IP+http it degrades, so fall back to a random-ish id.
function newRequestID(): string {
  return (
    globalThis.crypto?.randomUUID?.() ??
    `graph-message-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 12)}`
  );
}

// IntentLivePanel is the graph drawer's live section: the intent's recent activity
// tail plus the controls that already exist as API endpoints. Only the action that
// applies to the current state is offered, matching what the server accepts.
export function IntentLivePanel({ taskId, node, lines }: { taskId: string; node: TaskNode; lines: string[] }) {
  const t = useTranslations("explorationGraph");
  const [busy, setBusy] = React.useState(false);
  const [message, setMessage] = React.useState("");
  const tailRef = React.useRef<HTMLPreElement>(null);
  const canPause = node.state === "running";
  const canResume = node.state === "paused";
  const canCancel = node.state === "running" || node.state === "paused";

  React.useEffect(() => {
    const el = tailRef.current;
    if (el && lines.length > 0) el.scrollTop = el.scrollHeight; // keep the newest line in view
  }, [lines]);

  const control = async (action: "pause" | "resume" | "cancel") => {
    setBusy(true);
    try {
      // The API requires a reason for cancel; the drawer has no reason field, so
      // record where the action came from.
      await api.controlIntent(taskId, node.id, action, action === "cancel" ? t("live.cancelReason") : "");
      toast.success(t(DONE_KEY[action], { id: node.id }));
    } catch (e) {
      toast.error(t("live.actionFailed", { msg: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  };

  const send = async () => {
    const text = message.trim();
    if (!text) return;
    setBusy(true);
    try {
      await api.sendWorkerMessage(taskId, node.id, text, newRequestID());
      setMessage("");
      toast.success(t("live.messageSent", { id: node.id }));
    } catch (e) {
      toast.error(t("live.actionFailed", { msg: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="flex flex-col gap-3 border-t pt-3">
      <h4 className="font-medium text-muted-foreground text-xs">{t("live.title")}</h4>
      {lines.length === 0 ? (
        <p className="text-muted-foreground text-xs">{t("live.empty")}</p>
      ) : (
        <pre
          ref={tailRef}
          className="max-h-64 max-w-full overflow-auto whitespace-pre rounded-md border bg-muted/50 p-3 font-mono text-foreground text-xs leading-relaxed"
        >
          {lines.join("\n")}
        </pre>
      )}
      {(canPause || canResume || canCancel) && (
        <div className="flex flex-wrap gap-2">
          {canPause && (
            <Button size="sm" variant="destructive" disabled={busy} onClick={() => void control("pause")}>
              {t("live.pause")}
            </Button>
          )}
          {canResume && (
            <Button size="sm" variant="outline" disabled={busy} onClick={() => void control("resume")}>
              {t("live.resume")}
            </Button>
          )}
          {canCancel && (
            <Button size="sm" variant="destructive" disabled={busy} onClick={() => void control("cancel")}>
              {t("live.cancel")}
            </Button>
          )}
        </div>
      )}
      {canResume && (
        <div className="flex flex-col gap-2">
          <Textarea
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            rows={2}
            placeholder={t("live.messagePlaceholder")}
            aria-label={t("live.messagePlaceholder")}
          />
          <Button size="sm" disabled={busy || !message.trim()} onClick={() => void send()}>
            {t("live.send")}
          </Button>
        </div>
      )}
    </section>
  );
}
