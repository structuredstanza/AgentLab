import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

// Regression: a failed config load left every switch off with Save enabled, and
// Save then persisted an empty scope, silently dropping the operator's rules and
// the model judge for every tool outside the mandatory approvals.
const h = vi.hoisted(() => ({
  getToolConfig: vi.fn(async () => {
    throw new Error("database is down");
  }),
  setToolConfig: vi.fn(async () => ({ ok: true })),
}));

const stableT = (key: string) => key;

vi.mock("next-intl", () => ({ useTranslations: () => stableT }));
vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));
vi.mock("@/lib/api", () => ({
  api: {
    interceptRules: vi.fn(async () => []),
    interceptGetToolConfig: h.getToolConfig,
    interceptSetToolConfig: h.setToolConfig,
    interceptGetJudgeConfig: vi.fn(async () => ({
      enabled: false,
      profile_id: 0,
      prompt: "",
      timeout_seconds: 15,
      fail_action: "allow",
      ask_timeout_seconds: 300,
      ask_timeout_action: "deny",
    })),
    interceptJudgeUsage: vi.fn(async () => null),
    interceptSetJudgeConfig: vi.fn(async () => ({ ok: true })),
    llmProfiles: vi.fn(async () => []),
    tools: vi.fn(async () => [
      { key: "Bash", system: true, description: "", schema: {}, agents: [], enabled: true, kind: "builtin" },
    ]),
    createInterceptRule: vi.fn(async () => ({})),
    updateInterceptRule: vi.fn(async () => ({})),
    deleteInterceptRule: vi.fn(async () => ({})),
    toggleInterceptRule: vi.fn(async () => ({})),
  },
}));

import InterceptPage from "@/app/(main)/system/intercept/page";

describe("interception scope dialog", () => {
  it("keeps Save disabled and sends no update when the config never loaded", async () => {
    render(<InterceptPage />);
    await waitFor(() => expect(h.getToolConfig).toHaveBeenCalled());

    fireEvent.click(screen.getByText("scope.adjust"));

    // The dialog says why it is empty instead of looking like an empty scope.
    await waitFor(() => expect(screen.getByText("scope.loadFailed")).toBeTruthy());

    const save = screen.getByText("editor.save").closest("button");
    expect(save).toBeTruthy();
    expect((save as HTMLButtonElement).disabled).toBe(true);

    fireEvent.click(save as HTMLButtonElement);
    expect(h.setToolConfig).not.toHaveBeenCalled();
  });
});
