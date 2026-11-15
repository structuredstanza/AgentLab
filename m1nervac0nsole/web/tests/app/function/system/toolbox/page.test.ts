import { describe, expect, it } from "vitest";

import { formatCommand } from "@/app/(main)/system/toolbox/_components/template-sheet";

describe("formatCommand", () => {
  it("leaves ordinary arguments bare", () => {
    expect(formatCommand("nmap", ["-oX", "-", "-p", "22,80", "10.0.0.5"])).toBe("nmap -oX - -p 22,80 10.0.0.5");
  });

  it("quotes an argument a shell would split or expand", () => {
    expect(formatCommand("nuclei", ["-u", "http://10.0.0.5/a b?x=1&y=2"])).toBe(
      "nuclei -u 'http://10.0.0.5/a b?x=1&y=2'",
    );
  });

  it("escapes a single quote so the preview stays copy-pasteable", () => {
    expect(formatCommand("sh", ["-c", "echo 'hi'"])).toBe("sh -c 'echo '\\''hi'\\'''");
  });
});
