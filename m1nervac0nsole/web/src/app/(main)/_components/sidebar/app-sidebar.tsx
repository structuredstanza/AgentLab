"use client";

import Link from "next/link";

import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";
import { APP_CONFIG } from "@/config/app-config";
import { useCurrentUser } from "@/hooks/use-current-user";
import { sidebarItems } from "@/navigation/sidebar/sidebar-items";

import { NavMain } from "./nav-main";
import { NavUser } from "./nav-user";

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  const currentUser = useCurrentUser();

  return (
    <Sidebar {...props}>
      <SidebarHeader className="h-12 shrink-0 justify-center gap-0 border-b p-0">
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              asChild
              size="lg"
              className="h-12 justify-start gap-2 rounded-none px-3 group-data-[collapsible=icon]:justify-center"
            >
              <Link prefetch={false} href="/function/tasks" aria-label={APP_CONFIG.name}>
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img src="/logo.svg" alt="" width={20} height={20} className="size-5 shrink-0" />
                <span className="truncate font-medium font-mono text-[13px] tracking-tight group-data-[collapsible=icon]:hidden">
                  {APP_CONFIG.name}
                </span>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <NavMain items={sidebarItems} />
      </SidebarContent>
      <SidebarFooter className="border-t p-2">
        <NavUser user={currentUser} />
      </SidebarFooter>
    </Sidebar>
  );
}
