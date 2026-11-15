"use client";

import * as React from "react";

import { ArrowUpIcon, BotIcon, FileTextIcon, Loader2Icon, Square } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Transcript } from "@/components/transcript";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Textarea } from "@/components/ui/textarea";
import { useConversationTail } from "@/hooks/use-conversation-tail";
import { api } from "@/lib/api";
import { shouldSubmitOnKey, useChatSendMode } from "@/lib/chat-send-mode";
import type { Conversation } from "@/lib/types";

// pickConversation returns the thread to reopen for this pane: the newest one of
// this agent, bound to `taskId` when the pane is task-scoped. A thread bound to
// another task is never reused: two engagements would share one history, and the
// tools take their task from the binding.
export function pickConversation(list: Conversation[], agentKey: string, taskId?: string): Conversation | null {
  const task = taskId === undefined ? null : Number(taskId);
  return list.find((c) => c.agent_key === agentKey && (task === null || c.task_id === task)) ?? null;
}

// CuratorChat is the chat pane for a propose-only agent (memory curator, tool
// curator, the task drafter). The agent may read freely and only propose; the
// operator decides. The pane says so, because a chat that looked like it could
// publish would invite the operator to trust the wrong step. `i18n` is the message
// namespace that holds a `chat.*` block (title, proposesOnly, empty, placeholder,
// send, stop, ...).
// `taskId` binds the thread to one task and prefixes each message with it, because
// the drafter's tools take the task from the conversation binding.
// `prefill` adds a button that seeds the composer with a starter line.
// `outbox` lets the host page send one message as if it had been typed: each new
// `id` is delivered once, creating the conversation when there is none.
export function CuratorChat({
  agentKey,
  i18n,
  taskId,
  prefill,
  outbox,
}: {
  agentKey: string;
  i18n: string;
  taskId?: string;
  prefill?: { label: string; text: string };
  outbox?: { id: number; text: string } | null;
}) {
  const t = useTranslations(i18n);
  const sendMode = useChatSendMode();
  const [conversation, setConversation] = React.useState<Conversation | null>(null);
  const [resolving, setResolving] = React.useState(true);
  const [input, setInput] = React.useState("");
  const [sending, setSending] = React.useState(false);
  const [stopping, setStopping] = React.useState(false);
  const { messages, running, loaded, setRunning, hasMore, loadEarlier } = useConversationTail(conversation?.id ?? null);
  const scrollRef = React.useRef<HTMLDivElement | null>(null);
  const inputRef = React.useRef<HTMLTextAreaElement | null>(null);

  // Reuse the newest conversation of this agent so the pane survives a reload; a
  // fresh one is created on the first send when there is none.
  const resolve = React.useCallback(() => {
    setResolving(true);
    api
      .conversations()
      .then((list) => {
        setConversation(pickConversation(list, agentKey, taskId));
      })
      .catch(() => {
        /* a failure just leaves the draft state */
      })
      .finally(() => setResolving(false));
  }, [agentKey, taskId]);

  React.useEffect(() => {
    resolve();
  }, [resolve]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: new activity should re-pin the view to the bottom.
  React.useLayoutEffect(() => {
    const viewport = scrollRef.current?.closest('[data-slot="scroll-area-viewport"]') as HTMLElement | null;
    if (viewport) viewport.scrollTop = viewport.scrollHeight;
  }, [messages, running]);

  const fetchDetail = React.useCallback(
    (seq: number) => (conversation ? api.conversationMsgDetail(conversation.id, seq) : Promise.resolve("")),
    [conversation],
  );

  async function deliver(message: string): Promise<boolean> {
    if (sending || running) return false;
    setSending(true);
    try {
      let target = conversation;
      if (!target) {
        target = await api.createConversation(agentKey, "", null, taskId === undefined ? undefined : Number(taskId));
        setConversation(target);
      }
      // The drafter's tools take the task from the conversation binding, but every
      // message names it too, so a wrong guess cannot store a draft elsewhere.
      const body = taskId === undefined ? message : `${t("chat.taskPrefix", { id: taskId })} ${message}`;
      await api.sendConversationMessage(target.id, body);
      setRunning(true);
      return true;
    } catch (e) {
      toast.error(t("chat.sendFailed", { msg: (e as Error).message }));
      return false;
    } finally {
      setSending(false);
    }
  }

  async function send() {
    const message = input.trim();
    if (!message || sending || running) return;
    setInput("");
    if (!(await deliver(message))) setInput(message);
  }

  const deliveredOutbox = React.useRef(0);
  // biome-ignore lint/correctness/useExhaustiveDependencies: deliver reads current state; the ref makes each outbox id fire once.
  React.useEffect(() => {
    if (!outbox || resolving || deliveredOutbox.current === outbox.id) return;
    deliveredOutbox.current = outbox.id;
    if (sending || running) {
      toast.error(t("chat.busy"));
      return;
    }
    void deliver(outbox.text);
  }, [outbox, resolving]);

  async function stop() {
    if (!conversation || stopping) return;
    setStopping(true);
    try {
      await api.stopConversation(conversation.id);
    } catch (e) {
      toast.error(t("chat.stopFailed", { msg: (e as Error).message }));
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
          <p className="font-medium text-sm">{t("chat.title")}</p>
          <p className="text-[11px] text-muted-foreground leading-snug">{t("chat.proposesOnly")}</p>
        </div>
      </div>

      <ScrollArea type="auto" className="[&_[data-slot=scroll-area-viewport]>div]:block! min-h-0 flex-1">
        <div className="px-3 py-3" ref={scrollRef}>
          {resolving && (
            <div className="flex h-24 items-center justify-center">
              <Loader2Icon className="size-4 animate-spin text-muted-foreground" />
            </div>
          )}
          {!resolving && hasMore && (
            <div className="flex justify-center pb-2">
              <Button size="xs" variant="ghost" onClick={() => void loadEarlier()}>
                {t("chat.loadEarlier")}
              </Button>
            </div>
          )}
          {!resolving && (!conversation || (messages.length === 0 && !running)) && (
            <p className="py-8 text-center text-muted-foreground text-xs">{t("chat.empty")}</p>
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
        {prefill && (
          <div className="mb-2 flex">
            <Button
              size="xs"
              variant="outline"
              onClick={() => {
                setInput((prev) => (prev.trim() ? prev : prefill.text));
                inputRef.current?.focus();
              }}
              disabled={sending}
            >
              <FileTextIcon />
              {prefill.label}
            </Button>
          </div>
        )}
        <div className="flex items-end gap-2">
          <Textarea
            ref={inputRef}
            className="max-h-32 min-h-9 flex-1 resize-none text-xs"
            rows={1}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKeyDown}
            disabled={sending}
            placeholder={t("chat.placeholder")}
          />
          {running ? (
            <Button
              size="icon"
              variant="destructive"
              onClick={() => void stop()}
              disabled={stopping}
              title={t("chat.stop")}
            >
              <Square className="size-3.5 fill-current" />
            </Button>
          ) : (
            <Button
              size="icon"
              onClick={() => void send()}
              disabled={sending || !input.trim()}
              title={t("chat.send")}
              aria-label={t("chat.send")}
            >
              <ArrowUpIcon />
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
