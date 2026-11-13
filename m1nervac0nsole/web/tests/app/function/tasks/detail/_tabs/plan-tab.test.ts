import { describe, expect, it } from "vitest";

import { pickDrafterConversation } from "@/app/(main)/function/tasks/detail/_tabs/plan-tab";
import type { Conversation } from "@/lib/types";

function conv(id: number, agent_key: string, task_id?: number): Conversation {
  return { id, agent_key, title: "", task_id, created_at: "", updated_at: "" };
}

describe("pickDrafterConversation", () => {
  it("returns the drafter thread bound to this task", () => {
    const list = [conv(1, "drafter", 9), conv(2, "drafter", 4), conv(3, "curator", 4)];
    expect(pickDrafterConversation(list, 4)?.id).toBe(2);
  });

  it("never reuses a thread bound to another task", () => {
    // Sharing one history would put two engagements in one transcript, and the
    // drafter's tools take their task from the binding.
    const list = [conv(1, "drafter", 9), conv(2, "drafter")];
    expect(pickDrafterConversation(list, 4)).toBeNull();
  });

  it("ignores other agents' threads", () => {
    const list = [conv(1, "curator", 4), conv(2, "mainagent", 4)];
    expect(pickDrafterConversation(list, 4)).toBeNull();
  });

  it("returns null when there is no thread at all", () => {
    expect(pickDrafterConversation([], 4)).toBeNull();
  });
});
