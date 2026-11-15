import { beforeEach, describe, expect, it, vi } from "vitest";

import { sseUrl } from "@/lib/api";
import { auth } from "@/lib/auth";

// A same-origin stream authenticates with the HttpOnly m1nervac0nsole_stream
// cookie the backend sets at login, so the JWT stays out of the URL. Only a
// cross-origin stream (dev :8787, or an explicit override) appends ?token=.
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

  it("treats a base equal to the page origin as same-origin", () => {
    ENV.NEXT_PUBLIC_SSE_BASE = window.location.origin;
    auth.setToken("header.payload.signature");
    expect(sseUrl("/api/x")).toBe(`${window.location.origin}/api/x`);
  });

  it("sends the credential on a cross-origin stream", () => {
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

// The guard cookie must not be the session credential: it is readable by any
// script on the page, and the backend only authenticates with the separate
// HttpOnly stream cookie.
describe("auth cookie", () => {
  beforeEach(() => {
    localStorage.clear();
    document.cookie = "m1nervac0nsole_token=; path=/; max-age=0";
  });

  it("carries a marker, never the JWT", () => {
    auth.setToken("header.payload.signature");
    expect(document.cookie).toBe("m1nervac0nsole_token=1");
    expect(localStorage.getItem("m1nervac0nsole_token")).toBe("header.payload.signature");
  });

  it("is cleared with the token", () => {
    auth.setToken("header.payload.signature");
    auth.clearToken();
    expect(document.cookie).toBe("");
    expect(localStorage.getItem("m1nervac0nsole_token")).toBeNull();
  });

  it("asks the backend to clear its HttpOnly stream cookie", () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));
    auth.setToken("header.payload.signature");
    auth.clearToken();
    expect(fetchSpy).toHaveBeenCalledWith("/api/auth/logout", { method: "POST", keepalive: true });
    fetchSpy.mockRestore();
  });
});
