"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowUpCircleIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { api } from "@/lib/api";

/**
 * "New version available" hint in the top bar: checks once on full page load, and if an update exists, shows it next to the version number,
 * clicking it goes straight to the "Version & Updates" card on the system settings page.
 *
 * The backend caches GitHub query results for 30 minutes, so it is safe to check on every mount here.
 * Unauthenticated GitHub API calls are limited to 60 per hour per IP; without that cache layer, having a few tabs open
 * would exhaust the quota, and then a real update check would fail when it's actually needed.
 *
 * Query failures are always silent: the top bar is not the place to report errors. Users who click "Check for updates" on the settings page will see the reason.
 */
export function UpdateBadge() {
  const t = useTranslations("header");
  const [latest, setLatest] = React.useState("");

  React.useEffect(() => {
    let alive = true;
    api
      .checkUpdate()
      .then((r) => {
        // has_update already includes the check that the version number is comparable, so development builds will not show this hint.
        if (alive && r.has_update && r.latest) setLatest(r.latest.replace(/^v(?=\d)/, ""));
      })
      .catch(() => {
        // Silent: being offline or hitting GitHub rate limits should never show an error in the top bar.
      });
    return () => {
      alive = false;
    };
  }, []);

  if (!latest) return null;

  return (
    <Link
      href="/system/settings"
      title={t("updateTitle", { latest })}
      className="inline-flex items-center gap-1.5 rounded-full bg-primary px-2.5 py-1 font-medium text-primary-foreground text-xs transition-opacity hover:opacity-90"
    >
      {/* Breathing point: the top bar has many elements, and plain text is easy to overlook. The animation makes it visible at a glance. */}
      <span className="relative flex size-1.5">
        <span className="absolute inline-flex size-full animate-ping rounded-full bg-primary-foreground opacity-75" />
        <span className="relative inline-flex size-1.5 rounded-full bg-primary-foreground" />
      </span>
      <ArrowUpCircleIcon className="size-3.5" />
      <span className="hidden sm:inline">{t("updateBadge", { latest })}</span>
      <span className="sm:hidden">{t("updateBadgeShort")}</span>
    </Link>
  );
}
