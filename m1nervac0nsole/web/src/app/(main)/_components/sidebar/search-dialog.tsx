"use client";

import * as React from "react";

import { useRouter } from "next/navigation";

import { Search } from "lucide-react";
import { useTranslations } from "next-intl";

import { Button } from "@/components/ui/button";
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import type { NavItem } from "@/navigation/sidebar/sidebar-items";
import { sidebarItems } from "@/navigation/sidebar/sidebar-items";

// Display strings are not stored in the data; only the nav namespace keys are kept. The actual labels and headings
// are translated at render time in the component via useTranslations("nav") (same message source as the sidebar).
type SearchItem = {
  id: string;
  headingKey: string; // Relative key under nav (group heading). E.g., "group.operations"
  headingFallback: string; // Authored group label
  labelKey: string; // Relative key based on nav (item label). E.g. "item.dashboard"
  fallbackLabel: string; // Source text to use when the message has no key
  url: string;
  icon?: NavItem["icon"];
};

// The palette is derived from the same sidebar data, so it can never drift from
// the shell: every destination in the navigation is searchable here.
const searchItems: SearchItem[] = sidebarItems.flatMap((group) =>
  group.items.map((item) => ({
    id: item.id,
    headingKey: group.labelKey,
    headingFallback: group.label,
    labelKey: `item.${item.id}`,
    fallbackLabel: item.title,
    url: item.url,
    icon: item.icon,
  })),
);

function groupBy(items: SearchItem[]) {
  const headings = [...new Set(items.map((item) => item.headingFallback))];
  return headings.map((heading) => ({
    heading,
    headingKey: items.find((item) => item.headingFallback === heading)?.headingKey,
    items: items.filter((item) => item.headingFallback === heading),
  }));
}

export function SearchDialog() {
  const [open, setOpen] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const router = useRouter();
  const t = useTranslations("search");
  const tNav = useTranslations("nav");

  React.useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === "j" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    };
    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, []);

  const handleOpenChange = (value: boolean) => {
    setOpen(value);
    if (!value) setQuery("");
  };

  const handleSelect = (item: SearchItem) => {
    handleOpenChange(false);
    router.push(item.url);
  };

  const renderGroups = (items: SearchItem[]) =>
    groupBy(items).map(({ heading, headingKey, items: groupItems }, index) => {
      const label = headingKey && tNav.has(headingKey) ? tNav(headingKey) : heading;
      return (
        <React.Fragment key={heading}>
          {index > 0 && <CommandSeparator />}
          <CommandGroup heading={label}>
            {groupItems.map((item) => {
              const itemLabel = tNav.has(item.labelKey) ? tNav(item.labelKey) : item.fallbackLabel;
              return (
                <CommandItem
                  key={`${heading}-${item.id}`}
                  value={`${label} ${itemLabel}`}
                  className="font-mono text-xs"
                  onSelect={() => handleSelect(item)}
                >
                  <span className="flex min-w-0 items-center gap-2">
                    {item.icon && <item.icon />}
                    <span className="truncate">{itemLabel}</span>
                  </span>
                </CommandItem>
              );
            })}
          </CommandGroup>
        </React.Fragment>
      );
    });

  return (
    <>
      <Button
        onClick={() => handleOpenChange(true)}
        variant="ghost"
        size="sm"
        aria-label={t("button")}
        className="h-7 gap-1.5 rounded-sm px-2 font-mono font-normal text-muted-foreground text-xs hover:text-foreground"
      >
        <Search data-icon="inline-start" />
        <span className="hidden sm:inline">{t("button")}</span>
        <kbd className="hidden h-5 select-none items-center gap-0.5 rounded-sm border border-border bg-muted px-1 font-mono text-[10px] sm:inline-flex">
          <span className="text-[11px]">⌘</span>J
        </kbd>
      </Button>
      <CommandDialog open={open} onOpenChange={handleOpenChange}>
        <Command>
          <CommandInput placeholder={t("placeholder")} value={query} onValueChange={setQuery} />
          <CommandList>
            <CommandEmpty>{t("empty")}</CommandEmpty>
            {query ? renderGroups(searchItems) : renderGroups(searchItems)}
          </CommandList>
        </Command>
      </CommandDialog>
    </>
  );
}
