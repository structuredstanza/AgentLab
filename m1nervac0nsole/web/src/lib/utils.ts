import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// Helper for the onInteractOutside close check on Drawer/Dialog (Sheet/Dialog).
//
// Background: Radix popovers inside the drawer (Select dropdowns, DropdownMenu, Popover, etc.) portal into the drawer
// the drawer. When one is open and the user clicks the overlay or outside the drawer to dismiss it, this single pointerdown is handled by both the Select and Sheet
// DismissableLayer handles it simultaneously; Select closes first and is a discrete event, and React will flush synchronously, so
// By the time it is the Sheet's handler's turn, the popup's data-state has already flipped to closed — detect whether the popup is open "right now"
// Naturally unreliable (verified by actual testing).
//
// The correct approach: Radix's pointerdown listener runs in the bubble phase; we use the capture phase (which runs earlier than it) to first
// record "whether any popover is open right now", and onInteractOutside then reads this recorded value to decide whether to allow closing.
function isRadixOverlayOpenNow(): boolean {
  if (typeof document === "undefined") return false;
  return !!document.querySelector(
    [
      "[data-slot='select-trigger'][data-state='open']",
      "[data-slot='select-content'][data-state='open']",
      "[role='listbox'][data-state='open']",
      "[data-radix-popper-content-wrapper]",
      "[aria-expanded='true'][data-state='open']",
    ].join(","),
  );
}

let overlayOpenAtLastPointerDown = false;
if (typeof document !== "undefined") {
  document.addEventListener(
    "pointerdown",
    () => {
      overlayOpenAtLastPointerDown = isRadixOverlayOpenNow();
    },
    true, // capture: record before Radix's bubble-phase pointerdown handler runs
  );
}

// radixOverlayWasOpenAtPointerDown returns whether a Radix overlay was open when the most recent pointerdown occurred.
// open. Drawers/dialogs use this: when an overlay is open and the backdrop is clicked, only close the overlay, not the component itself.
export function radixOverlayWasOpenAtPointerDown(): boolean {
  return overlayOpenAtLastPointerDown;
}

// copyText writes the text to the clipboard and returns whether it succeeded.
// Background: navigator.clipboard is only available in secure contexts (HTTPS / localhost); via IP + HTTP
// When accessed, it is undefined, so fall back to execCommand("copy").
export async function copyText(text: string): Promise<boolean> {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Continue with the fallback scheme
    }
  }
  try {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.left = "-9999px";
    textarea.style.top = "0";
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(textarea);
    return ok;
  } catch {
    return false;
  }
}

export const getInitials = (str: string): string => {
  if (typeof str !== "string" || !str.trim()) return "?";

  return (
    str
      .trim()
      .split(/\s+/)
      .filter(Boolean)
      .map((word) => word[0])
      .join("")
      .toUpperCase() || "?"
  );
};
