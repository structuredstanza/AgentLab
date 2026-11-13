"use client";

import { type ReactNode, useEffect, useState } from "react";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { ClipboardList } from "lucide-react";
import { useTranslations } from "next-intl";

import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { useCurrentUser } from "@/hooks/use-current-user";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

import { AccountSwitcher } from "./sidebar/account-switcher";
import { SearchDialog } from "./sidebar/search-dialog";
import { useInterceptPendingCount } from "./use-intercept-pending";

// The task detail page stays as it is: it has its own header/Tabs and padding, so the global header and padding are not layered on top here.
function isFullBleed(pathname: string) {
  const p = (() => {
    try {
      return decodeURIComponent(pathname);
    } catch {
      return pathname;
    }
  })();
  // Static export has trailingSlash enabled, so the list page's own pathname is "/function/tasks/",
  // Strip the trailing slash before checking the prefix; otherwise the list page would be mistaken for a detail page and lose the global header.
  const normalized = p.replace(/\/+$/, "");
  return normalized.startsWith("/function/tasks/");
}

// Approvals stay reachable from every screen: the header shows the live pending
// count and links straight to the records page.
function ApprovalIndicator() {
  const tNav = useTranslations("nav");
  const count = useInterceptPendingCount();
  const pending = count > 0;
  const label = tNav("item.approvals");

  return (
    <Link
      prefetch={false}
      href="/system/intercept/approvals"
      aria-label={pending ? `${label} (${count})` : label}
      title={label}
      className={cn(
        "inline-flex h-7 items-center gap-1.5 rounded-sm border px-2 font-mono text-[11px] tabular-nums transition-colors",
        pending
          ? "border-warning/40 bg-warning/10 text-warning hover:bg-warning/20"
          : "border-border text-muted-foreground hover:bg-muted hover:text-foreground",
      )}
    >
      <ClipboardList className="size-3.5" aria-hidden="true" />
      {pending && count}
    </Link>
  );
}

export function MainContent({ children }: { children: ReactNode }) {
  const currentUser = useCurrentUser();
  const pathname = usePathname();
  const t = useTranslations("header");
  const [version, setVersion] = useState("");

  useEffect(() => {
    api
      .health()
      .then((h) => setVersion((h.version ?? "").replace(/^v(?=\d)/, "")))
      .catch(() => setVersion(""));
  }, []);

  // The skip target lives in both branches: full-bleed workspaces keep their own
  // header, so the layout-level skip link must still land somewhere focusable.
  if (isFullBleed(pathname)) {
    return (
      <div id="main-content" tabIndex={-1} className="flex min-h-0 min-w-0 flex-1 flex-col outline-none">
        {children}
      </div>
    );
  }

  return (
    <>
      {/* Single hairline header. Height stays 48px: full-height workspaces
          (memory, task detail) subtract exactly this value from the viewport. */}
      <header className="sticky top-0 z-30 flex h-12 shrink-0 items-center border-b bg-background">
        <div className="flex w-full min-w-0 items-center justify-between gap-2 px-3 lg:px-4">
          <div className="flex min-w-0 items-center gap-1">
            <SidebarTrigger className="-ml-1" />
            <Separator
              orientation="vertical"
              className="mx-1.5 data-[orientation=vertical]:h-4 data-[orientation=vertical]:self-center"
            />
            <SearchDialog />
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            <ApprovalIndicator />
            {version && (
              <span className="hidden font-mono text-[11px] text-muted-foreground tabular-nums sm:inline">
                {t("version", { version })}
              </span>
            )}
            <AccountSwitcher users={[currentUser]} />
          </div>
        </div>
      </header>
      {/* SidebarInset already renders the single <main>; this is only the skip
          target, so it must stay a non-landmark element. */}
      <div
        id="main-content"
        tabIndex={-1}
        className="min-h-0 min-w-0 flex-1 overflow-x-hidden p-4 outline-none has-data-[content-padding=false]:p-0 md:p-6 md:has-data-[content-padding=false]:p-0"
      >
        {children}
      </div>
    </>
  );
}
