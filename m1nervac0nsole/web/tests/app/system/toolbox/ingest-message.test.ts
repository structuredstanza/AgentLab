import { describe, expect, it } from "vitest";

import { composeIngestMessage } from "@/app/(main)/system/toolbox/_components/ingest-tool-dialog";

describe("composeIngestMessage", () => {
  it("names only the tool when nothing else is filled", () => {
    expect(composeIngestMessage({ tool: " nikto ", repo: "", notes: "  ", install: false })).toBe(
      'Ingest the tool "nikto".',
    );
  });

  it("adds the repository, the install sentence and the notes only when present", () => {
    const msg = composeIngestMessage({
      tool: "nikto",
      repo: "https://github.com/sullo/nikto",
      notes: "expose -Tuning",
      install: true,
    });
    expect(msg).toBe(
      'Ingest the tool "nikto". Repository: https://github.com/sullo/nikto. Install it if it is missing. Notes: expose -Tuning',
    );
  });

  it("omits the install sentence when the box is unchecked", () => {
    const msg = composeIngestMessage({ tool: "dig", repo: "", notes: "n", install: false });
    expect(msg).not.toContain("Install");
    expect(msg).not.toContain("Repository");
  });
});
