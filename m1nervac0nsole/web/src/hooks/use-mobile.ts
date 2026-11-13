import * as React from "react";

const MOBILE_BREAKPOINT = 768;
// If the sidebar stays expanded while the content width narrows, tables and cards overlap (in the 768~1279px range).
// Below this width, automatically collapse the sidebar to icon mode to secure space for the main content.
export const TABLET_BREAKPOINT = 1280;

function useBreakpoint(breakpoint: number) {
  const [below, setBelow] = React.useState<boolean | undefined>(undefined);

  React.useEffect(() => {
    const mql = window.matchMedia(`(max-width: ${breakpoint - 1}px)`);
    const onChange = () => setBelow(window.innerWidth < breakpoint);
    mql.addEventListener("change", onChange);
    setBelow(window.innerWidth < breakpoint);
    return () => mql.removeEventListener("change", onChange);
  }, [breakpoint]);

  return below;
}

export function useIsMobile() {
  return !!useBreakpoint(MOBILE_BREAKPOINT);
}

// Whether the viewport is tablet-width (768~1279px). During the initial render (before measurement), return undefined as-is,
// so that callers can distinguish between "not yet known" and "false".
export function useIsTablet() {
  return useBreakpoint(TABLET_BREAKPOINT);
}
