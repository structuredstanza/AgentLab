import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { LogLine } from "@/lib/types";

// Regression: "Load older" used a bare fetch, so the history request carried no
// bearer token. The backend answered 401 and the page swallowed it, which looked
// exactly like "there are no older logs".
vi.mock("next-intl", () => ({ useTranslations: () => (key: string) => key }));

import LogsPage from "@/app/(main)/system/logs/page";

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  onmessage: ((e: { data: string }) => void) | null = null;
  close = vi.fn();

  constructor(public url: string) {
    FakeEventSource.instances.push(this);
  }

  emit(line: LogLine) {
    this.onmessage?.({ data: JSON.stringify(line) });
  }
}

function line(dbId: number): LogLine {
  return { seq: dbId, ts: "2026-01-01T00:00:00Z", level: "info", tag: "app", text: `line ${dbId}`, db_id: dbId };
}

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

const fetchMock = vi.fn();

beforeEach(() => {
  FakeEventSource.instances = [];
  vi.stubGlobal("EventSource", FakeEventSource);
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
  localStorage.setItem("m1nervac0nsole_token", "session-token");
  // jsdom does not implement scrolling; the page auto-scrolls to the newest line.
  Element.prototype.scrollIntoView = vi.fn();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  localStorage.clear();
});

// The "Load older" button only appears once a line with a db_id above 1 is in
// view, so every test seeds the live tail first.
async function openWithHistory() {
  render(<LogsPage />);
  await waitFor(() => expect(FakeEventSource.instances).toHaveLength(1));
  act(() => FakeEventSource.instances[0].emit(line(5)));
  return screen.findByText("loadOlder");
}

describe("logs history", () => {
  it("sends the bearer token when loading older logs", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ items: [line(3)], has_more: false }));
    fireEvent.click(await openWithHistory());

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/logs/history?before=5&limit=200");
    expect((init as RequestInit).headers).toMatchObject({ Authorization: "Bearer session-token" });
    await waitFor(() => expect(screen.getByText("line 3")).toBeInTheDocument());
  });

  it("shows the failure instead of silently stopping", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ error: "history store unavailable" }, 500));
    fireEvent.click(await openWithHistory());

    await waitFor(() => expect(screen.getByText("history store unavailable")).toBeInTheDocument());
  });
});
