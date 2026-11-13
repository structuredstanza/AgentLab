"use client";

import type { ReactNode } from "react";
import * as React from "react";

import { AppSidebar } from "@/app/(main)/_components/sidebar/app-sidebar";
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";
import { auth } from "@/lib/auth";
import { getClientCookie } from "@/lib/cookie.client";

import { MainContent } from "./_components/main-content";

export default function Layout({ children }: Readonly<{ children: ReactNode }>) {
  // Client-side auth gate — replaces the Next proxy/middleware that static export
  // disables. No token → bounce to /login; render nothing until confirmed so no
  // protected UI (or its API calls) flashes for a logged-out visitor.
  const [authed, setAuthed] = React.useState(false);
  React.useEffect(() => {
    if (auth.getToken()) {
      setAuthed(true);
    } else {
      // When the client-side guard decides the user is not logged in, it must also clear the cookie at the same time; otherwise proxy.ts relies solely on
      // When the cookie exists, we get redirected from /login back to the main screen, bouncing back and forth with this guard.
      // This forms an infinite redirect → white screen (triggered when the cookie and localStorage are out of sync).
      auth.clearToken();
      window.location.href = "/login";
    }
  }, []);

  // Only the open/closed state is a user preference: the shell itself is a fixed
  // flat console, so variant and collapse mode are no longer configurable.
  const defaultOpen = typeof document === "undefined" ? true : getClientCookie("sidebar_state") !== "false";

  if (!authed) return null;

  return (
    <SidebarProvider
      defaultOpen={defaultOpen}
      style={
        {
          "--sidebar-width": "calc(var(--spacing) * 64)",
        } as React.CSSProperties
      }
    >
      {/* First focusable element: bypasses the whole sidebar. Kept off-screen
          rather than sr-only so the focused state can't depend on utility order. */}
      <a
        href="#main-content"
        className="fixed top-2 left-2 z-50 -translate-y-24 rounded-sm border border-border bg-card px-2 py-1 font-mono text-xs focus:translate-y-0 focus:outline-none focus:ring-2 focus:ring-ring"
      >
        Skip to content
      </a>
      <AppSidebar variant="sidebar" collapsible="icon" />
      <SidebarInset className="min-w-0 overflow-x-hidden [--dashboard-header-height:--spacing(12)]">
        <MainContent>{children}</MainContent>
      </SidebarInset>
    </SidebarProvider>
  );
}
