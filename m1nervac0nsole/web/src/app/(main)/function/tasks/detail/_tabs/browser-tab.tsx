"use client";

import * as React from "react";

import { useTranslations } from "next-intl";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { api, sseUrl } from "@/lib/api";
import { type LiveEvent, type LiveState, mapPointerToViewport, nextLiveState } from "@/lib/browser-live";
import type {
  BrowserInput,
  BrowserLiveDialog,
  BrowserLiveFrame,
  BrowserLivePage,
  BrowserLiveViewport,
} from "@/lib/types";

// CDP modifier bits: Alt=1, Ctrl=2, Meta=4, Shift=8.
function modifiers(event: React.KeyboardEvent): number {
  return (event.altKey ? 1 : 0) | (event.ctrlKey ? 2 : 0) | (event.metaKey ? 4 : 0) | (event.shiftKey ? 8 : 0);
}

// Keys a page needs as key events rather than inserted text. Printable keys go
// through Input.insertText, which is what a real keystroke produces anyway.
const KEY_CODES: Record<string, number> = {
  Enter: 13,
  Tab: 9,
  Escape: 27,
  Backspace: 8,
  Delete: 46,
  ArrowLeft: 37,
  ArrowUp: 38,
  ArrowRight: 39,
  ArrowDown: 40,
  Home: 36,
  End: 35,
  PageUp: 33,
  PageDown: 34,
};

function operatorToken(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `op-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function mouseButton(button: number): string {
  if (button === 1) return "middle";
  if (button === 2) return "right";
  return "left";
}

export function BrowserTab({ taskId }: { taskId: string }) {
  const t = useTranslations("taskDetail.browser");
  const [state, setState] = React.useState<LiveState>("idle");
  const [viewport, setViewport] = React.useState<BrowserLiveViewport | null>(null);
  const [frame, setFrame] = React.useState("");
  const [page, setPage] = React.useState<BrowserLivePage | null>(null);
  const [dialog, setDialog] = React.useState<BrowserLiveDialog | null>(null);
  const [promptText, setPromptText] = React.useState("");
  const [error, setError] = React.useState("");
  const sourceRef = React.useRef<EventSource | null>(null);
  const tokenRef = React.useRef("");
  const surfaceRef = React.useRef<HTMLDivElement | null>(null);
  const lastMoveRef = React.useRef(0);

  const transition = React.useCallback((event: LiveEvent) => {
    setState((current) => nextLiveState(current, event));
  }, []);

  const stop = React.useCallback(() => {
    sourceRef.current?.close();
    sourceRef.current = null;
    const token = tokenRef.current;
    tokenRef.current = "";
    setViewport(null);
    setFrame("");
    setPage(null);
    setDialog(null);
    setError("");
    transition("release");
    // The caller may wait for the slot to be free before opening a new stream.
    return token ? api.browserRelease(taskId, token).catch(() => undefined) : Promise.resolve();
  }, [taskId, transition]);

  // Leaving the tab releases the operator slot: the next viewer must not wait
  // for a stream nobody is reading.
  React.useEffect(
    () => () => {
      void stop();
    },
    [stop],
  );

  const start = React.useCallback(() => {
    if (sourceRef.current) return;
    const token = operatorToken();
    tokenRef.current = token;
    setError("");
    setFrame("");
    setPage(null);
    setDialog(null);
    transition("connect");
    // The panel's own size is the viewport: a small panel must not stream
    // 1280x800. The server clamps whatever arrives, so an unlaid-out panel
    // (zero size) simply gets the default.
    const rect = surfaceRef.current?.getBoundingClientRect();
    const size =
      rect && rect.width >= 1 && rect.height >= 1
        ? `&width=${Math.round(rect.width)}&height=${Math.round(rect.height)}`
        : "";
    const source = new EventSource(
      sseUrl(`/api/tasks/${encodeURIComponent(taskId)}/browser/stream?op=${encodeURIComponent(token)}${size}`),
    );
    sourceRef.current = source;
    source.addEventListener("viewport", (event) => {
      setViewport(JSON.parse((event as MessageEvent).data) as BrowserLiveViewport);
      transition("open");
    });
    source.addEventListener("page", (event) => {
      setPage(JSON.parse((event as MessageEvent).data) as BrowserLivePage);
    });
    source.addEventListener("frame", (event) => {
      const next = JSON.parse((event as MessageEvent).data) as BrowserLiveFrame;
      setFrame(`data:image/jpeg;base64,${next.data}`);
    });
    source.addEventListener("dialog", (event) => {
      const next = JSON.parse((event as MessageEvent).data) as BrowserLiveDialog;
      setDialog(next.open ? next : null);
      if (next.open) setPromptText(next.default_prompt ?? "");
    });
    source.onerror = () => transition("fail");
  }, [taskId, transition]);

  // Taking control (or retrying after a drop) always releases the old session
  // first: the server allows one operator stream per task, so a new token must
  // not race the old stream's teardown.
  const takeControl = React.useCallback(() => {
    void stop().then(() => start());
  }, [start, stop]);

  const send = React.useCallback(
    (input: BrowserInput) => {
      const token = tokenRef.current;
      if (!token || state !== "controlling") return;
      void api.browserInput(taskId, token, input).catch((e) => setError((e as Error).message));
    },
    [state, taskId],
  );

  const point = React.useCallback(
    (clientX: number, clientY: number) => {
      const surface = surfaceRef.current;
      if (!surface || !viewport) return null;
      return mapPointerToViewport(clientX, clientY, surface.getBoundingClientRect(), viewport);
    },
    [viewport],
  );

  // Wheel needs a non-passive listener: React's onWheel cannot preventDefault,
  // so the page behind the frame would scroll too.
  React.useEffect(() => {
    const surface = surfaceRef.current;
    if (!surface || state !== "controlling" || !viewport) return;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      const p = mapPointerToViewport(event.clientX, event.clientY, surface.getBoundingClientRect(), viewport);
      send({ kind: "scroll", x: p.x, y: p.y, delta_x: event.deltaX, delta_y: event.deltaY });
    };
    surface.addEventListener("wheel", onWheel, { passive: false });
    return () => surface.removeEventListener("wheel", onWheel);
  }, [send, state, viewport]);

  function onMouseDown(event: React.MouseEvent<HTMLDivElement>) {
    if (state !== "controlling") return;
    const p = point(event.clientX, event.clientY);
    if (!p) return;
    // The surface is the keyboard target; a click must focus it so the next
    // keystroke reaches the page instead of the surrounding form.
    event.currentTarget.focus();
    event.preventDefault();
    send({ kind: "mouse", type: "mousePressed", x: p.x, y: p.y, button: mouseButton(event.button), click_count: 1 });
  }

  function onMouseUp(event: React.MouseEvent<HTMLDivElement>) {
    if (state !== "controlling") return;
    const p = point(event.clientX, event.clientY);
    if (!p) return;
    event.preventDefault();
    send({ kind: "mouse", type: "mouseReleased", x: p.x, y: p.y, button: mouseButton(event.button), click_count: 1 });
  }

  function onMouseMove(event: React.MouseEvent<HTMLDivElement>) {
    if (state !== "controlling") return;
    const now = Date.now();
    if (now - lastMoveRef.current < 50) return;
    lastMoveRef.current = now;
    const p = point(event.clientX, event.clientY);
    if (p) send({ kind: "mouse", type: "mouseMoved", x: p.x, y: p.y });
  }

  function onKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    if (state !== "controlling") return;
    // Tab belongs to the page, not to the surrounding form.
    if (event.key === "Tab") event.preventDefault();
    if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
      event.preventDefault();
      send({ kind: "text", text: event.key });
      return;
    }
    event.preventDefault();
    send({
      kind: "key",
      type: "keyDown",
      key: event.key,
      code: event.code,
      modifiers: modifiers(event),
      windows_virtual_key_code: KEY_CODES[event.key],
    });
  }

  function onKeyUp(event: React.KeyboardEvent<HTMLDivElement>) {
    if (state !== "controlling" || event.key.length === 1) return;
    send({
      kind: "key",
      type: "keyUp",
      key: event.key,
      code: event.code,
      modifiers: modifiers(event),
      windows_virtual_key_code: KEY_CODES[event.key],
    });
  }

  async function answer(accept: boolean) {
    const token = tokenRef.current;
    if (!token) return;
    try {
      await api.browserDialog(taskId, token, {
        accept,
        prompt_text: accept && dialog?.type === "prompt" ? promptText : undefined,
      });
      setDialog(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  let badge: "default" | "outline" | "destructive" = "outline";
  if (state === "controlling") badge = "default";
  else if (state === "error") badge = "destructive";

  return (
    <section className="flex min-w-0 flex-col gap-3 border-border border-t pt-3">
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2">
          <Switch
            checked={state === "controlling"}
            onCheckedChange={(on) => (on ? takeControl() : void stop())}
            disabled={state === "connecting"}
            aria-label={t("takeControl")}
          />
          <span className="font-medium text-sm">{t("takeControl")}</span>
        </div>
        <Badge variant={badge}>{t(`state.${state}`)}</Badge>
        {state === "error" ? (
          <Button size="sm" variant="outline" onClick={takeControl}>
            {t("retry")}
          </Button>
        ) : null}
      </div>
      <p className="text-muted-foreground text-xs">{t("note")}</p>
      {state === "error" ? <p className="text-muted-foreground text-xs">{t("errorHint")}</p> : null}
      {error ? <p className="text-destructive text-xs">{error}</p> : null}

      {dialog ? (
        <div className="flex flex-col gap-2 border border-warning/40 bg-warning/10 p-3">
          <div className="flex items-center gap-2">
            <Badge variant="outline">{dialog.type ?? "dialog"}</Badge>
            <span className="min-w-0 flex-1 truncate text-sm">{dialog.message}</span>
          </div>
          {dialog.type === "prompt" ? (
            <Input
              value={promptText}
              onChange={(event) => setPromptText(event.target.value)}
              placeholder={t("promptPlaceholder")}
            />
          ) : null}
          <div className="flex gap-2">
            <Button size="sm" onClick={() => void answer(true)}>
              {t("accept")}
            </Button>
            <Button size="sm" variant="outline" onClick={() => void answer(false)}>
              {t("dismiss")}
            </Button>
          </div>
        </div>
      ) : null}

      {page && (page.title || page.url) ? (
        <div className="flex min-w-0 items-baseline gap-2 text-xs" title={page.url}>
          <span className="min-w-0 truncate font-medium">{page.title || page.url}</span>
          {page.title ? <span className="min-w-0 truncate text-muted-foreground">{page.url}</span> : null}
        </div>
      ) : null}

      <div
        ref={surfaceRef}
        role="application"
        // biome-ignore lint/a11y/noNoninteractiveTabindex: the surface is the page's keyboard target; role=application makes it interactive.
        tabIndex={0}
        aria-label={t("canvasLabel")}
        className="relative aspect-[16/10] w-full overflow-hidden border border-border bg-muted outline-none focus-visible:ring-2 focus-visible:ring-ring"
        onMouseDown={onMouseDown}
        onMouseUp={onMouseUp}
        onMouseMove={onMouseMove}
        onKeyDown={onKeyDown}
        onKeyUp={onKeyUp}
      >
        {/* eslint-disable-next-line @next/next/no-img-element */}
        {/* biome-ignore lint/performance/noImgElement: the frame is a live JPEG data URL that next/image cannot optimize. */}
        <img
          src={frame || undefined}
          alt=""
          draggable={false}
          className="pointer-events-none h-full w-full select-none"
        />
        {frame ? null : (
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center px-4 text-center text-muted-foreground text-sm">
            {t("idle")}
          </div>
        )}
      </div>
    </section>
  );
}
