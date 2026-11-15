import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  tools: vi.fn(),
  toolManifests: vi.fn(),
  saveToolManifest: vi.fn(),
  deleteToolManifest: vi.fn(),
  installToolManifest: vi.fn(),
}));

const stableT = Object.assign((key: string) => key, { rich: (key: string) => key });

vi.mock("next-intl", () => ({ useTranslations: () => stableT }));
vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));
vi.mock("@/components/curator-chat", () => ({ CuratorChat: () => null }));
vi.mock("@/lib/api", () => ({
  api: {
    tools: h.tools,
    toolManifests: h.toolManifests,
    saveToolManifest: h.saveToolManifest,
    deleteToolManifest: h.deleteToolManifest,
    installToolManifest: h.installToolManifest,
    previewTool: vi.fn(),
    agents: vi.fn(async () => []),
    settings: vi.fn(async () => ({ traffic_capture: true })),
  },
}));

import ToolboxPage from "@/app/(main)/system/toolbox/page";
import type { Tool, ToolManifest } from "@/lib/types";

function manifest(id: string, over: Partial<ToolManifest> = {}): ToolManifest {
  return {
    id,
    name: id,
    description: `${id} description`,
    category: "scan",
    accepts: ["ip"],
    requires: [id],
    available: true,
    source: "builtin",
    toml: `id = "${id}"\n`,
    installable: false,
    params: {},
    timeout_seconds: 60,
    ...over,
  };
}

const customTool: Tool = {
  key: "nuclei_scan",
  system: false,
  description: "Custom: runs nuclei",
  schema: {},
  agents: [],
  enabled: true,
  kind: "command",
};
const systemTool: Tool = { ...customTool, key: "report_finding", system: true, kind: "builtin" };

afterEach(cleanup);

describe("toolbox catalog", () => {
  beforeEach(() => {
    h.tools.mockReset().mockResolvedValue([systemTool, customTool]);
    h.toolManifests.mockReset().mockResolvedValue([manifest("nmap"), manifest("dig", { available: false })]);
    h.saveToolManifest.mockReset();
    h.deleteToolManifest.mockReset();
    h.installToolManifest.mockReset();
  });

  it("shows templates and custom tools together in the default tab, without system tools", async () => {
    render(<ToolboxPage />);
    expect(await screen.findByText("nmap")).toBeTruthy();
    expect(screen.getByText("dig")).toBeTruthy();
    expect(screen.getByText("notInstalled")).toBeTruthy();
    expect(screen.getByText("nuclei_scan")).toBeTruthy();
    expect(screen.queryByText("report_finding")).toBeNull();
  });

  it("shows an error state instead of an empty catalog when loading fails", async () => {
    h.toolManifests.mockRejectedValue(new Error("boom"));
    render(<ToolboxPage />);
    expect((await screen.findByRole("alert")).textContent).toContain("loadFailed");
    expect(screen.queryByText("catalogEmpty")).toBeNull();
  });

  it("displays the server's validation message when saving a template fails", async () => {
    h.saveToolManifest.mockRejectedValue(new Error("nmap: description is required"));
    render(<ToolboxPage />);
    fireEvent.click(await screen.findByText("nmap"));
    fireEvent.click(await screen.findByRole("button", { name: "save" }));
    await waitFor(() => expect(screen.getByRole("alert").textContent).toBe("nmap: description is required"));
    expect(h.saveToolManifest).toHaveBeenCalledWith('id = "nmap"\n');
  });

  it.each([
    ["builtin", false],
    ["custom", false],
    ["modified", true],
  ] as const)("offers Reset to built-in only for a modified template (%s)", async (source, offered) => {
    h.toolManifests.mockResolvedValue([manifest("nmap", { source })]);
    render(<ToolboxPage />);
    fireEvent.click(await screen.findByText("nmap"));
    await screen.findByRole("button", { name: "save" });
    expect(screen.queryByRole("button", { name: "resetBuiltin" }) !== null).toBe(offered);
  });

  // The curator's verification block lives in the stored TOML, so the detail
  // sheet can show what was verified without another API field. A failed install
  // must read as a failure rather than as a finished install.
  it("shows the curator's provenance and a failed install verification", async () => {
    h.toolManifests.mockResolvedValue([
      manifest("nmap", {
        installable: true,
        toml: '# provenance: verified: flags from nmap -h\n# provenance: inferred: default timing\nid = "nmap"\n',
      }),
    ]);
    h.installToolManifest.mockResolvedValue({ output: "no such package", is_error: true, available: false });
    render(<ToolboxPage />);
    fireEvent.click(await screen.findByText("nmap"));
    expect(await screen.findByText("verified: flags from nmap -h")).toBeTruthy();
    expect(screen.getByText("inferred: default timing")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "install" }));
    await waitFor(() => expect(screen.getByText("installFailed")).toBeTruthy());
    expect(h.installToolManifest).toHaveBeenCalledWith("nmap");
  });

  it("warns when an install ran but the tool is still not on PATH", async () => {
    h.toolManifests.mockResolvedValue([manifest("nmap", { installable: true })]);
    h.installToolManifest.mockResolvedValue({ output: "done", is_error: false, available: false });
    render(<ToolboxPage />);
    fireEvent.click(await screen.findByText("nmap"));
    fireEvent.click(screen.getByRole("button", { name: "install" }));
    await waitFor(() => expect(screen.getByText("installUnverified")).toBeTruthy());
    expect(screen.getByText("installNotOnPath")).toBeTruthy();
  });

  // The published artifact is what the operator checks PATH against, so an
  // installed row names the file and its digest, and a row that never installed
  // claims neither.
  it("shows the published artifact of an installed template and nothing for one that never installed", async () => {
    const sha = "9f2c1b7de4a05c6381f0b2d7e9a4c5b8d1e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0";
    h.toolManifests.mockResolvedValue([
      manifest("nmap", {
        installable: true,
        artifact: {
          path: "/state/m1nervac0nsole/toolbox/bin/nmap",
          size: 4_194_304,
          sha256: sha,
          installed_at: "2026-11-15T10:00:00Z",
        },
      }),
      manifest("ffuf", { installable: true }),
    ]);
    render(<ToolboxPage />);
    expect(await screen.findByText("/state/m1nervac0nsole/toolbox/bin/nmap")).toBeTruthy();
    expect(screen.getByText(`sha256 ${sha}`)).toBeTruthy();
    expect(screen.queryByText("/state/m1nervac0nsole/toolbox/bin/ffuf")).toBeNull();
  });
});
