import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { TaskNode } from "@/lib/types";

const messages: Record<string, string> = {
  "live.title": "Live",
  "live.empty": "No live output yet",
  "live.pause": "Pause",
  "live.resume": "Resume",
  "live.cancel": "Cancel intent",
  "live.cancelReason": "Cancelled from the graph by the operator",
  "live.messagePlaceholder": "Message the worker (the intent must be paused)",
  "live.send": "Send",
  "live.paused": "Intent #{id} paused",
  "live.resumed": "Intent #{id} resumed",
  "live.cancelled": "Intent #{id} cancelled",
  "live.messageSent": "Message sent to intent #{id}",
  "live.actionFailed": "Action failed: {msg}",
};

function translate(key: string, values?: Record<string, unknown>): string {
  return (messages[key] ?? key).replace(/\{(\w+)\}/g, (_, name: string) => String(values?.[name] ?? `{${name}}`));
}

const h = vi.hoisted(() => ({
  controlIntent: vi.fn(),
  sendWorkerMessage: vi.fn(),
  success: vi.fn(),
  error: vi.fn(),
}));

vi.mock("next-intl", () => ({ useTranslations: () => translate }));
vi.mock("sonner", () => ({ toast: { success: h.success, error: h.error } }));
vi.mock("@/lib/api", () => ({
  api: { controlIntent: h.controlIntent, sendWorkerMessage: h.sendWorkerMessage },
}));

import { IntentLivePanel } from "@/components/intent-live-panel";

function intent(state: string): TaskNode {
  return { id: "9", type: "intent", state, priority: 5, origin: "planner", ts: "" };
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("IntentLivePanel", () => {
  it("offers pause and cancel while the intent runs", () => {
    render(<IntentLivePanel taskId="t1" node={intent("running")} lines={[]} />);
    expect(screen.getByRole("button", { name: "Pause" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Cancel intent" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Resume" })).toBeNull();
    expect(screen.queryByRole("textbox")).toBeNull();
  });

  it("offers resume, cancel and a message box while paused", () => {
    render(<IntentLivePanel taskId="t1" node={intent("paused")} lines={[]} />);
    expect(screen.getByRole("button", { name: "Resume" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Cancel intent" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Pause" })).toBeNull();
    expect(screen.getByRole("textbox")).toBeInTheDocument();
  });

  it("offers no control for a finished intent", () => {
    render(<IntentLivePanel taskId="t1" node={intent("done")} lines={[]} />);
    expect(screen.queryByRole("button")).toBeNull();
    expect(screen.queryByRole("textbox")).toBeNull();
  });

  it("cancels the intent with the intent id", async () => {
    h.controlIntent.mockResolvedValue({});
    render(<IntentLivePanel taskId="t1" node={intent("running")} lines={[]} />);
    fireEvent.click(screen.getByRole("button", { name: "Cancel intent" }));
    await waitFor(() =>
      expect(h.controlIntent).toHaveBeenCalledWith("t1", "9", "cancel", "Cancelled from the graph by the operator"),
    );
  });

  it("pauses and resumes through the existing control endpoint", async () => {
    h.controlIntent.mockResolvedValue({});
    const { rerender } = render(<IntentLivePanel taskId="t1" node={intent("running")} lines={[]} />);
    fireEvent.click(screen.getByRole("button", { name: "Pause" }));
    await waitFor(() => expect(h.controlIntent).toHaveBeenCalledWith("t1", "9", "pause", ""));

    rerender(<IntentLivePanel taskId="t1" node={intent("paused")} lines={[]} />);
    fireEvent.click(screen.getByRole("button", { name: "Resume" }));
    await waitFor(() => expect(h.controlIntent).toHaveBeenCalledWith("t1", "9", "resume", ""));
  });

  it("sends a worker message and renders the tail newest last", async () => {
    h.sendWorkerMessage.mockResolvedValue({});
    render(<IntentLivePanel taskId="t1" node={intent("paused")} lines={["first step", "second step"]} />);
    expect(screen.getByText(/first step/).textContent).toBe("first step\nsecond step");

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "try the admin path" } });
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    await waitFor(() =>
      expect(h.sendWorkerMessage).toHaveBeenCalledWith("t1", "9", "try the admin path", expect.any(String)),
    );
  });

  it("surfaces a failed action as a toast", async () => {
    h.controlIntent.mockRejectedValue(new Error("only running intents can be paused"));
    render(<IntentLivePanel taskId="t1" node={intent("running")} lines={[]} />);
    fireEvent.click(screen.getByRole("button", { name: "Pause" }));
    await waitFor(() => expect(h.error).toHaveBeenCalledWith("Action failed: only running intents can be paused"));
  });
});
