import { beforeEach, describe, expect, it } from "vitest";

import { sseUrl } from "@/lib/api";
import { auth } from "@/lib/auth";

// Regression: the 7-day JWT was appended to every stream URL, including
// same-origin ones where the artex_token cookie already authenticates the
// request, which wrote the credential into reverse-proxy access logs and
// browser history for no gain.
describe("sseUrl", () => {
  const ENV = process.env as Record<string, string | undefined>;

  beforeEach(() => {
    localStorage.clear();
    delete ENV.NEXT_PUBLIC_SSE_BASE;
  });

  it("keeps the credential out of a same-origin stream URL", () => {
    ENV.NEXT_PUBLIC_SSE_BASE = "";
    auth.setToken("header.payload.signature");
    expect(sseUrl("/api/exploration/activity/stream?limit=1")).toBe("/api/exploration/activity/stream?limit=1");
  });

  it("still sends it for a cross-origin stream, which cannot use the cookie", () => {
    ENV.NEXT_PUBLIC_SSE_BASE = "http://127.0.0.1:8787";
    auth.setToken("header.payload.signature");
    expect(sseUrl("/api/x?a=1")).toBe("http://127.0.0.1:8787/api/x?a=1&token=header.payload.signature");
    expect(sseUrl("/api/x")).toBe("http://127.0.0.1:8787/api/x?token=header.payload.signature");
  });

  it("leaves the URL untouched when there is no token", () => {
    ENV.NEXT_PUBLIC_SSE_BASE = "http://127.0.0.1:8787";
    expect(sseUrl("/api/x")).toBe("http://127.0.0.1:8787/api/x");
  });
});
