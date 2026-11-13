"use client";

import * as React from "react";

import { ArrowUpIcon, BotIcon, Loader2Icon, Square } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Transcript } from "@/components/transcript";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Textarea } from "@/components/ui/textarea";
import { useConversationTail } from "@/hooks/use-conversation-tail";
import { api } from "@/lib/api";
import { shouldSubmitOnKey, useChatSendMode } from "@/lib/chat-send-mode";
import type { Conversation, PlanDraft } from "@/lib/types";

import { PlanProposalPreview } from "./plan-proposal-preview";

// The drafting assistant is a normal chat agent; it can only propose, because
// applying a plan is the operator's decision on this page.
const DRAFTER_AGENT = "drafter";

// The curator pane (system/memory/_components/curator-chat.tsx) is hardcoded to
// the curator agent and its own i18n namespace, so it cannot be reused as-is.
// This is the same conversation-tail loop with the drafter key and no memory
// chrome; the shared parts (useConversationTail, Transcript) are reused.
function DrafterChat({ taskId }: { taskId: string }) {
  const t = useTranslations("taskDetail.plan");
  const sendMode = useChatSendMode();
  const [conversation, setConversation] = React.useState<Conversation | null>(null);
  const [resolving, setResolving] = React.useState(true);
  const [input, setInput] = React.useState("");
  const [sending, setSending] = React.useState(false);
  const [stopping, setStopping] = React.useState(false);
  const { messages, running, loaded, setRunning } = useConversationTail(conversation?.id ?? null);
  const scrollRef = React.useRef<HTMLDivElement | null>(null);

  // Reuse the newest drafter conversation bound to THIS task, so the pane
  // survives a reload without two engagements sharing one thread; a fresh one
  // is created on the first send when there is none.
  React.useEffect(() => {
    let live = true;
    api
      .conversations()
      .then((list) => {
        const bound = list.find((c) => c.agent_key === DRAFTER_AGENT && c.task_id === Number(taskId));
        if (live) setConversation(bound ?? null);
      })
      .catch(() => {
        /* a failure just leaves the draft state */
      })
      .finally(() => {
        if (live) setResolving(false);
      });
    return () => {
      live = false;
    };
  }, [taskId]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: new activity should re-pin the view to the bottom.
  React.useLayoutEffect(() => {
    const viewport = scrollRef.current?.closest('[data-slot="scroll-area-viewport"]') as HTMLElement | null;
    if (viewport) viewport.scrollTop = viewport.scrollHeight;
  }, [messages, running]);

  const fetchDetail = React.useCallback(
    (seq: number) => (conversation ? api.conversationMsgDetail(conversation.id, seq) : Promise.resolve("")),
    [conversation],
  );

  async function send() {
    const message = input.trim();
    if (!message || sending || running) return;
    setSending(true);
    setInput("");
    try {
      let target = conversation;
      if (!target) {
        // Bind the thread to this task: the drafter's tools then take the task
        // from the conversation, so a wrong guess cannot store a draft against
        // another engagement.
        target = await api.createConversation(DRAFTER_AGENT, "", null, Number(taskId));
        setConversation(target);
      }
      // The drafter has no other way to know which engagement it is drafting
      // for: the conversation is not bound to a task, and a wrong guess stores
      // a draft against a real task. Every message names the task.
      await api.sendConversationMessage(target.id, `${t("taskPrefix", { id: taskId })} ${message}`);
      setRunning(true);
    } catch (e) {
      toast.error(t("sendFailed", { msg: (e as Error).message }));
      setInput(message);
    } finally {
      setSending(false);
    }
  }

  async function stop() {
    if (!conversation || stopping) return;
    setStopping(true);
    try {
      await api.stopConversation(conversation.id);
    } catch (e) {
      toast.error(t("stopFailed", { msg: (e as Error).message }));
    } finally {
      setStopping(false);
    }
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (!shouldSubmitOnKey(e, sendMode)) return;
    e.preventDefault();
    void send();
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex shrink-0 items-start gap-2 border-b px-3 py-2">
        <BotIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
        <div className="min-w-0">
          <p className="font-medium text-sm">{t("title")}</p>
          <p className="text-[11px] text-muted-foreground leading-snug">{t("proposesOnly")}</p>
        </div>
      </div>

      <ScrollArea type="auto" className="[&_[data-slot=scroll-area-viewport]>div]:block! min-h-0 flex-1">
        <div className="px-3 py-3" ref={scrollRef}>
          {resolving && (
            <div className="flex h-24 items-center justify-center">
              <Loader2Icon className="size-4 animate-spin text-muted-foreground" />
            </div>
          )}
          {!resolving && (!conversation || (messages.length === 0 && !running)) && (
            <p className="py-8 text-center text-muted-foreground text-xs">{t("empty")}</p>
          )}
          {!resolving && conversation && loaded && (
            <Transcript activity={messages} live={running} chat fetchDetail={fetchDetail} />
          )}
          {!resolving && conversation && !loaded && (
            <div className="flex h-24 items-center justify-center">
              <Loader2Icon className="size-4 animate-spin text-muted-foreground" />
            </div>
          )}
        </div>
      </ScrollArea>

      <div className="shrink-0 border-t p-2">
        <div className="flex items-end gap-2">
          <Textarea
            className="max-h-32 min-h-9 flex-1 resize-none text-xs"
            rows={1}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKeyDown}
            disabled={sending}
            placeholder={t("placeholder")}
          />
          {running ? (
            <Button size="icon" variant="destructive" onClick={() => void stop()} disabled={stopping} title={t("stop")}>
              <Square className="size-3.5 fill-current" />
            </Button>
          ) : (
            <Button
              size="icon"
              onClick={() => void send()}
              disabled={sending || !input.trim()}
              title={t("send")}
              aria-label={t("send")}
            >
              <ArrowUpIcon />
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

export function PlanTab({ taskId }: { taskId: string }) {
  const t = useTranslations("taskDetail.plan");
  const [drafts, setDrafts] = React.useState<PlanDraft[] | null>(null);

  const load = React.useCallback(() => {
    api
      .planDrafts(taskId)
      .then(setDrafts)
      .catch(() => setDrafts([]));
  }, [taskId]);

  // The draft appears when the drafter's tool runs, which the chat stream does
  // not report, so poll like the intercept badge does.
  React.useEffect(() => {
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, [load]);

  // Prefer the pending draft; otherwise keep showing the last applied one so
  // the node count it created stays visible after a reload.
  const draft = drafts?.find((d) => d.status === "draft") ?? drafts?.find((d) => d.status === "applied") ?? null;

  let panel = <p className="text-muted-foreground text-xs">{t("noDraft")}</p>;
  if (drafts === null) {
    panel = <p className="text-muted-foreground text-xs">{t("loading")}</p>;
  } else if (draft) {
    panel = (
      <PlanProposalPreview
        taskId={taskId}
        draft={draft}
        onApplied={(updated) =>
          setDrafts((list) => (list ?? []).map((item) => (item.id === updated.id ? updated : item)))
        }
        onDiscarded={load}
      />
    );
  }

  return (
    <div className="grid min-h-0 gap-4 lg:grid-cols-2">
      <div className="flex h-[30rem] min-h-0 flex-col border">
        <DrafterChat taskId={taskId} />
      </div>
      <div className="min-h-0 border p-3">{panel}</div>
    </div>
  );
}
