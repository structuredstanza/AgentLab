import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Regression: the file-read effect had no liveness guard, so a read that
// resolved after the selection moved on replaced the editor text. The header
// and the Save target showed the new file while the buffer held the old one's
// contents, and Save wrote one file's text into another.
const h = vi.hoisted(() => {
  const pending: Record<string, (value: string) => void> = {};
  // stands in for the real ApiError, whose only use in this page is a 409 check
  class ApiError extends Error {
    status: number;
    constructor(message: string, status = 500) {
      super(message);
      this.status = status;
    }
  }
  return {
    ApiError,
    pending,
    readSkillFile: (_skill: string, path: string) =>
      new Promise<string>((resolve) => {
        pending[path] = resolve;
      }),
    writeSkillFile: vi.fn(async () => ({ ok: true })),
  };
});

const stableT = (key: string) => key;

vi.mock("next-intl", () => ({ useTranslations: () => stableT }));
vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));
vi.mock("@/lib/api", () => ({
  ApiError: h.ApiError,
  api: {
    skills: vi.fn(async () => [
      {
        name: "probe-skill",
        description: "probe",
        files: ["SKILL.md", "heavy.py"],
        calls: 0,
        tasks: 0,
        usage_agents: [],
      },
    ]),
    listSkillFiles: vi.fn(async () => ({
      files: [
        { path: "SKILL.md", name: "SKILL.md", dir: false },
        { path: "heavy.py", name: "heavy.py", dir: false },
      ],
    })),
    readSkillFile: h.readSkillFile,
    writeSkillFile: h.writeSkillFile,
    skillUsage: vi.fn(async () => []),
    skillDetail: vi.fn(async () => ({})),
    updateSkillMeta: vi.fn(async () => ({})),
    deleteSkillPath: vi.fn(async () => ({})),
    createSkill: vi.fn(async () => ({})),
    uploadSkill: vi.fn(async () => ({})),
    setSkillVisibility: vi.fn(async () => ({})),
    missingSkills: vi.fn(async () => []),
    agents: vi.fn(async () => []),
    mcpServers: vi.fn(async () => []),
    skillVisibility: vi.fn(async () => ({})),
    skillMcps: vi.fn(async () => ({})),
  },
}));

import SkillsPage from "@/app/(main)/system/skills/page";

function treeItem(text: string): HTMLElement {
  const found = [...document.querySelectorAll('[role="treeitem"]')].find((el) => (el.textContent || "").includes(text));
  if (!found) throw new Error(`no tree item for ${text}`);
  return found as HTMLElement;
}

describe("skill editor", () => {
  beforeEach(() => {
    h.writeSkillFile.mockClear();
    for (const key of Object.keys(h.pending)) delete h.pending[key];
  });

  it("ignores a stale read so Save never writes one file's text into another", async () => {
    render(<SkillsPage />);
    await waitFor(() => expect(screen.getAllByText("probe-skill").length).toBeGreaterThan(0));

    fireEvent.click(treeItem("probe-skill"));
    fireEvent.click(treeItem("heavy.py"));
    fireEvent.click(treeItem("SKILL.md"));

    // SKILL.md answers first, heavy.py — the file clicked earlier — answers last
    await waitFor(() => expect(h.pending["SKILL.md"]).toBeTruthy());
    h.pending["SKILL.md"]("# SKILL.md contents\n");
    await waitFor(() => expect(h.pending["heavy.py"]).toBeTruthy());
    h.pending["heavy.py"]("print('heavy.py contents')\n");

    const textarea = await waitFor(() => {
      const el = document.querySelector("textarea");
      if (!el) throw new Error("editor not open");
      return el as HTMLTextAreaElement;
    });
    expect(textarea.value).toBe("# SKILL.md contents\n");

    // Save is only enabled once the file is dirty, so type as the operator would
    fireEvent.change(textarea, { target: { value: `${textarea.value}# a note\n` } });
    const save = [...document.querySelectorAll("button")].find((b) => /save/i.test(b.textContent || ""));
    expect(save).toBeTruthy();
    fireEvent.click(save as HTMLButtonElement);
    await waitFor(() => expect(h.writeSkillFile).toHaveBeenCalled());

    const [skill, path, content] = h.writeSkillFile.mock.calls[0] as unknown as [string, string, string];
    expect(skill).toBe("probe-skill");
    expect(path).toBe("SKILL.md");
    expect(content).not.toContain("heavy.py contents");
    expect(content).toBe("# SKILL.md contents\n# a note\n");
  });
});
