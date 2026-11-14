// Pure helpers for the task Browser tab. They live outside the component so
// the pointer mapping and the take-control state machine are testable without
// React or a browser.

export type LiveState = "idle" | "connecting" | "controlling" | "error";

export type LiveEvent = "connect" | "open" | "fail" | "release";

// nextLiveState is the take-control state machine. Opening the stream claims
// the task's one operator slot; the first viewport event means the claim was
// accepted. A failure after that is a dropped stream, not a lost claim, so a
// reconnect's viewport event returns to controlling.
export function nextLiveState(state: LiveState, event: LiveEvent): LiveState {
  switch (event) {
    case "connect":
      return state === "controlling" ? state : "connecting";
    case "open":
      return state === "connecting" || state === "error" ? "controlling" : state;
    case "fail":
      return state === "idle" ? state : "error";
    case "release":
      return "idle";
  }
}

// mapPointerToViewport turns a pointer position inside the rendered frame into
// the page's CSS pixel coordinate. The screencast frame is the viewport at one
// pixel per CSS pixel, so only the displayed scale differs; the result is
// clamped to the viewport so a click on the image edge cannot land outside it.
export function mapPointerToViewport(
  clientX: number,
  clientY: number,
  rect: { left: number; top: number; width: number; height: number },
  viewport: { width: number; height: number },
): { x: number; y: number } {
  if (rect.width <= 0 || rect.height <= 0 || viewport.width <= 0 || viewport.height <= 0) {
    return { x: 0, y: 0 };
  }
  const x = ((clientX - rect.left) / rect.width) * viewport.width;
  const y = ((clientY - rect.top) / rect.height) * viewport.height;
  return {
    x: Math.min(Math.max(Math.round(x), 0), viewport.width - 1),
    y: Math.min(Math.max(Math.round(y), 0), viewport.height - 1),
  };
}
