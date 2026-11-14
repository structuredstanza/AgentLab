"use client";

import * as React from "react";

import { useTranslations } from "next-intl";

import { getLocalStorageValue, setLocalStorageValue } from "@/lib/local-storage.client";

// The send/newline key combination for the session input box. This is pure frontend preference, so it is stored only in localStorage
// and not on the server, and it is not synced with the account. As a result, it must be set again when the browser changes.
// it must be configured again. See issue #39: version 0.3.2 changed Ctrl+Enter sending to Enter sending,
// so the old key combination is brought back here as an option.
export type ChatSendMode = "enter" | "ctrl-enter";

const CHAT_SEND_MODE_KEY = "m1nervac0nsole_chat_send_mode";
const DEFAULT_CHAT_SEND_MODE: ChatSendMode = "enter";

// Options for the transport-method dropdown on the settings screen. Because the labels vary by locale, they are returned from a hook rather than a constant
// module. Hardcoding Korean in a pure module would garble the zh locale into Korean.
// The value is a stable identifier, so it is used as-is for the localStorage key and behavior checks.
export function useChatSendModeOptions(): { value: ChatSendMode; label: string }[] {
  const t = useTranslations("chatSendMode.option");
  return [
    { value: "enter", label: t("enter") },
    { value: "ctrl-enter", label: t("ctrlEnter") },
  ];
}

function parseMode(raw: string | null): ChatSendMode {
  return raw === "ctrl-enter" || raw === "enter" ? raw : DEFAULT_CHAT_SEND_MODE;
}

// Subscriber set for the same tab. The storage event on localStorage fires only in "other" tabs, so
// after a setting is changed in the current tab, emit must notify the input fields in that same tab. Otherwise
// the change will only show up after a page refresh.
const listeners = new Set<() => void>();

function subscribe(listener: () => void) {
  listeners.add(listener);
  window.addEventListener("storage", listener);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", listener);
  };
}

// Since it returns string literals, Object.is compares them by value, so useSyncExternalStore does not enter an infinite
// fall into an infinite loop.
function getSnapshot(): ChatSendMode {
  return parseMode(getLocalStorageValue(CHAT_SEND_MODE_KEY));
}

// The server has no localStorage, so first render the default value, and after hydrate, getSnapshot
// corrects the value.
function getServerSnapshot(): ChatSendMode {
  return DEFAULT_CHAT_SEND_MODE;
}

export function useChatSendMode(): ChatSendMode {
  return React.useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
}

export function setChatSendMode(mode: ChatSendMode) {
  setLocalStorageValue(CHAT_SEND_MODE_KEY, mode);
  for (const listener of listeners) listener();
}

// shouldSubmitOnKey determines whether a single key press counts as a submit.
// isComposing / keyCode 229 means the input method (e.g., Korean or Chinese) is composing a character,
// so these must always be passed through. Otherwise, confirming a character with Enter would submit it incorrectly.
// enter mode excludes only Shift, preserving 0.3.2 behavior exactly (so users who have not changed
// the setting keep the same feel). The ctrl-enter mode accepts both Ctrl and Cmd (macOS)
// together.
export function shouldSubmitOnKey(e: React.KeyboardEvent, mode: ChatSendMode): boolean {
  if (e.key !== "Enter") return false;
  if (e.nativeEvent.isComposing || e.nativeEvent.keyCode === 229) return false;
  if (mode === "ctrl-enter") return e.ctrlKey || e.metaKey;
  return !e.shiftKey;
}
