import { describe, expect, it } from "vitest";

import { mapPointerToViewport, nextLiveState } from "@/lib/browser-live";

// The frame is the emulated viewport at one pixel per CSS pixel; the <img> is
// usually smaller, so a click must be scaled back into page coordinates and
// clamped to the page, or the operator clicks outside the viewport.
describe("mapPointerToViewport", () => {
  const rect = { left: 100, top: 50, width: 640, height: 400 };
  const viewport = { width: 1280, height: 800 };

  it("scales a click from the rendered image to CSS pixels", () => {
    expect(mapPointerToViewport(100, 50, rect, viewport)).toEqual({ x: 0, y: 0 });
    expect(mapPointerToViewport(420, 250, rect, viewport)).toEqual({ x: 640, y: 400 });
    expect(mapPointerToViewport(260, 150, rect, viewport)).toEqual({ x: 320, y: 200 });
  });

  it("clamps an edge click into the viewport", () => {
    expect(mapPointerToViewport(740, 450, rect, viewport)).toEqual({ x: 1279, y: 799 });
    expect(mapPointerToViewport(99, 49, rect, viewport)).toEqual({ x: 0, y: 0 });
  });

  it("returns the origin when the image has not been laid out", () => {
    expect(mapPointerToViewport(10, 10, { left: 0, top: 0, width: 0, height: 0 }, viewport)).toEqual({ x: 0, y: 0 });
  });
});

// Taking control opens the stream; the viewport event is the server accepting
// the claim. A dropped stream is an error state, and a reconnect's viewport
// event returns to controlling without a new claim.
describe("nextLiveState", () => {
  it("claims on connect and confirms on the viewport event", () => {
    expect(nextLiveState("idle", "connect")).toBe("connecting");
    expect(nextLiveState("connecting", "open")).toBe("controlling");
  });

  it("reports a failed claim and allows a retry", () => {
    expect(nextLiveState("connecting", "fail")).toBe("error");
    expect(nextLiveState("error", "connect")).toBe("connecting");
    expect(nextLiveState("error", "open")).toBe("controlling");
  });

  it("keeps control through a transient disconnect", () => {
    expect(nextLiveState("controlling", "fail")).toBe("error");
    expect(nextLiveState("controlling", "connect")).toBe("controlling");
  });

  it("releases to idle", () => {
    expect(nextLiveState("controlling", "release")).toBe("idle");
    expect(nextLiveState("connecting", "release")).toBe("idle");
    expect(nextLiveState("idle", "fail")).toBe("idle");
  });
});
