import { describe, expect, it } from "vitest";

import { pickConversation } from "@/components/curator-chat";
import type { Conversation } from "@/lib/types";

function conv(id: number, agent_key: string, task_id?: number): Conversation {
  return { id, agent_key, title: "", task_id, created_at: "", updated_at: "" };
}

describe("pickConversation", () => {
  it("returns the drafter thread bound to this task", () => {
    const list = [conv(1, "drafter", 9), conv(2, "drafter", 4), conv(3, "curator", 4)];
    expect(pickConversation(list, "drafter", "4")?.id).toBe(2);
  });

  it("never reuses a thread bound to another task", () => {
    // Sharing one history would put two engagements in one transcript, and the
    // drafter's tools take their task from the binding.
    const list = [conv(1, "drafter", 9), conv(2, "drafter")];
    expect(pickConversation(list, "drafter", "4")).toBeNull();
  });

  it("ignores other agents' threads", () => {
    const list = [conv(1, "curator", 4), conv(2, "mainagent", 4)];
    expect(pickConversation(list, "drafter", "4")).toBeNull();
  });

  it("returns the newest thread of the agent when the pane is not task-bound", () => {
    const list = [conv(1, "curator", 9), conv(2, "drafter", 4)];
    expect(pickConversation(list, "curator")?.id).toBe(1);
  });

  it("returns null when there is no thread at all", () => {
    expect(pickConversation([], "drafter", "4")).toBeNull();
  });
});
