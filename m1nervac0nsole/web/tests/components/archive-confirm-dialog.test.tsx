import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const messages: Record<string, string> = {
  "archiveDialog.title": "{count, plural, =1 {Archive this task?} other {Archive # tasks?}}",
  "archiveDialog.description": "Archiving compresses the task into cold storage.",
  "archiveDialog.memoryWarning":
    "{count, plural, =1 {# unreviewed memory candidate stays with the archived task and cannot be promoted until it is restored.} other {# unreviewed memory candidates stay with the archived task and cannot be promoted until it is restored.}}",
  "archiveDialog.memoryReview": "Review them",
  "archiveDialog.force": "Archive anyway",
  "archiveDialog.cancel": "Cancel",
  "archiveDialog.confirm": "Confirm archive",
  "deleteDialog.memoryWarning": "{count} candidates",
};

function translate(key: string, values?: Record<string, unknown>): string {
  const template = messages[key] ?? key;
  const plural = template.match(/^\{(\w+), plural, =1 \{(.*?)\} other \{(.*?)\}\}$/);
  if (plural) {
    const count = values?.[plural[1]];
    return (count === 1 ? plural[2] : plural[3]).replace(/#/g, String(count));
  }
  return template.replace(/\{(\w+)\}/g, (_, name: string) => String(values?.[name] ?? `{${name}}`));
}

vi.mock("next-intl", () => ({ useTranslations: () => translate }));

const mocks = vi.hoisted(() => ({ knowledgeReviewCounts: vi.fn() }));
vi.mock("@/lib/api", () => ({ api: { knowledgeReviewCounts: mocks.knowledgeReviewCounts } }));

import { ArchiveConfirmDialog, ArchiveEvidenceGateError } from "@/components/archive-confirm-dialog";

afterEach(() => {
  cleanup();
  mocks.knowledgeReviewCounts.mockReset();
});

describe("ArchiveConfirmDialog", () => {
  it("shows the blocked findings and retries the archive with force", async () => {
    mocks.knowledgeReviewCounts.mockResolvedValue({});
    const onConfirm = vi
      .fn<(force: boolean) => Promise<void>>()
      .mockRejectedValueOnce(
        new ArchiveEvidenceGateError(
          "Cannot archive: 1 finding(s) still have no bound traffic evidence (#12 SSRF). Bind the traffic or set force=true.",
        ),
      )
      .mockResolvedValueOnce(undefined);

    render(
      <ArchiveConfirmDialog taskIds={["7"]} trigger={<button type="button">Archive</button>} onConfirm={onConfirm} />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Archive" }));
    fireEvent.click(await screen.findByRole("button", { name: "Confirm archive" }));

    expect(
      await screen.findByText(/1 finding\(s\) still have no bound traffic evidence \(#12 SSRF\)/),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Archive anyway" }));

    await waitFor(() => expect(onConfirm).toHaveBeenLastCalledWith(true));
    expect(onConfirm).toHaveBeenNthCalledWith(1, false);
  });

  it("keeps the dialog open with no retry when the failure is not the gate", async () => {
    mocks.knowledgeReviewCounts.mockResolvedValue({});
    const onConfirm = vi.fn<(force: boolean) => Promise<void>>().mockRejectedValue(new Error("network down"));

    render(
      <ArchiveConfirmDialog taskIds={["7"]} trigger={<button type="button">Archive</button>} onConfirm={onConfirm} />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Archive" }));
    fireEvent.click(await screen.findByRole("button", { name: "Confirm archive" }));

    await waitFor(() => expect(onConfirm).toHaveBeenCalledWith(false));
    expect(screen.queryByRole("button", { name: "Archive anyway" })).toBeNull();
  });
});
