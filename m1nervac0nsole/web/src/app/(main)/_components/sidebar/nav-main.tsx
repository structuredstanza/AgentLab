"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { useTranslations } from "next-intl";

import {
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";
import type { NavGroup, NavItem } from "@/navigation/sidebar/sidebar-items";

import { useInterceptPendingCount } from "../use-intercept-pending";

// Flat console navigation: one near-square hit area per destination, monospace
// labels, no decorative chrome.
const NAV_BUTTON_CLASS = "rounded-sm font-mono text-xs";

export function NavMain({ items }: { readonly items: readonly NavGroup[] }) {
  const t = useTranslations("nav");
  const rawPath = usePathname();
  // Route segments contain Chinese characters, so pathname may be percent-encoded. Decode it before comparing with the nav url, so that highlighting matches correctly.
  // Static export has trailingSlash enabled, so strip the trailing slash before
  // matching; otherwise no item is ever active on a directly loaded route.
  const path = (() => {
    try {
      return decodeURIComponent(rawPath).replace(/\/+$/, "");
    } catch {
      return rawPath.replace(/\/+$/, "");
    }
  })();

  return (
    <>
      {items.map((group) => (
        <SidebarGroup key={group.id} className="px-2 py-1.5">
          <SidebarGroupLabel className="h-7 font-mono text-[10px] uppercase tracking-[0.08em] group-data-[collapsible=icon]:pointer-events-none">
            {t.has(group.labelKey) ? t(group.labelKey) : group.label}
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {group.items.map((item) => (
                <NavLinkItem key={item.id} item={item} isActive={path === item.url} />
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      ))}
    </>
  );
}

function NavLinkItem({ item, isActive }: { readonly item: NavItem; readonly isActive: boolean }) {
  const t = useTranslations("nav");
  const title = t.has(`item.${item.id}`) ? t(`item.${item.id}`) : item.title;
  const Icon = item.icon;

  return (
    <SidebarMenuItem>
      <SidebarMenuButton asChild tooltip={title} isActive={isActive}>
        <Link prefetch={false} href={item.url} className={NAV_BUTTON_CLASS}>
          {Icon && <Icon />}
          <span>{title}</span>
        </Link>
      </SidebarMenuButton>
      {item.id === "approvals" && <InterceptPendingBadge />}
    </SidebarMenuItem>
  );
}

// Pending intercept approvals stay visible in the navigation: the warning
// semantic, not an accent decoration.
function InterceptPendingBadge() {
  const count = useInterceptPendingCount();
  if (count === 0) return null;
  return (
    <SidebarMenuBadge className="flex h-4 min-w-[18px] items-center justify-center rounded-sm border border-warning/40 bg-warning/15 px-1 font-mono font-semibold text-[10px] text-warning tabular-nums leading-none">
      {count > 99 ? "99+" : count}
    </SidebarMenuBadge>
  );
}
