"use client";

import { useTranslations } from "next-intl";

import type { FindingScreenshot } from "@/lib/types";

// A screenshot under this size is small enough to render inline; a bigger one is
// only linked, so the detail page never pulls a large image just to show it.
const THUMBNAIL_MAX_BYTES = 1 << 20;

export function FindingScreenshots({ items }: { items?: FindingScreenshot[] }) {
  const t = useTranslations("findings");
  if (!items || items.length === 0) return null;
  return (
    <div className="flex flex-col gap-2">
      <p className="font-medium text-sm">{t("detail.screenshots")}</p>
      <ul className="flex flex-wrap gap-3">
        {items.map((shot) => {
          // Same-origin download route, so the auth cookie authenticates it
          // without a token in the URL.
          const href = `/api/workspace/download?path=${encodeURIComponent(shot.path)}`;
          const name = shot.path.split("/").pop() || shot.path;
          return (
            <li key={shot.path} className="flex max-w-[16rem] flex-col gap-1">
              {shot.size > 0 && shot.size < THUMBNAIL_MAX_BYTES && (
                // biome-ignore lint/performance/noImgElement: a workspace PNG served by the API; next/image cannot optimize it.
                <img src={href} alt={name} loading="lazy" className="max-h-40 rounded-md border object-contain" />
              )}
              <a href={href} title={shot.path} className="truncate text-primary text-xs hover:underline">
                {name}
              </a>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
