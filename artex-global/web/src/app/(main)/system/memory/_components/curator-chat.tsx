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
import type { Conversation } from "@/lib/types";

// The curator agent may read memory freely and write task-scoped candidates;
// it never adopts or promotes. The pane says so, because a chat that looked
// like it could publish would invite the operator to trust the wrong step.
const CURATOR_AGENT = "curator";

export function CuratorChat() {
  const t = useTranslations("memoryPage");
  const sendMode = useChatSendMode();
  const [conversation, setConversation] = React.useState<Conversation | null>(null);
  const [resolving, setResolving] = React.useState(true);
  const [input, setInput] = React.useState("");
  const [sending, setSending] = React.useState(false);
  const [stopping, setStopping] = React.useState(false);
  const { messages, running, loaded, setRunning } = useConversationTail(conversation?.id ?? null);
  const scrollRef = React.useRef<HTMLDivElement | null>(null);

  // Reuse the newest curator conversation so the pane survives a reload; a
  // fresh one is created on the first send when there is none.
  const resolve = React.useCallback(() => {
    setResolving(true);
    api
      .conversations()
      .then((list) => {
        const existing = list.find((c) => c.agent_key === CURATOR_AGENT) ?? null;
        setConversation(existing);
      })
      .catch(() => {
        /* a failure just leaves the draft state */
      })
      .finally(() => setResolving(false));
  }, []);

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

  async function send() {
    const message = input.trim();
    if (!message || sending || running) return;
    setSending(true);
    setInput("");
    try {
      let target = conversation;
      if (!target) {
        target = await api.createConversation(CURATOR_AGENT);
        setConversation(target);
      }
      await api.sendConversationMessage(target.id, message);
      setRunning(true);
    } catch (e) {
      toast.error(t("chat.sendFailed", { msg: (e as Error).message }));
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
      <div className="flex items-start gap-2 border-b px-3 py-2">
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

      <div className="border-t p-2">
        <div className="flex items-end gap-2">
          <Textarea
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
