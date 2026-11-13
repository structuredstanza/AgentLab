import { describe, expect, it } from "vitest";

import { getInitials } from "@/lib/utils";

describe("getInitials", () => {
  it("takes the first letter of each word, uppercased", () => {
    expect(getInitials("john doe")).toBe("JD");
    expect(getInitials("  Acme   Corp ")).toBe("AC");
    expect(getInitials("hacker")).toBe("H");
  });

  it("falls back to '?' for empty or non-string input", () => {
    expect(getInitials("")).toBe("?");
    expect(getInitials("   ")).toBe("?");
    expect(getInitials(undefined as unknown as string)).toBe("?");
  });
});
