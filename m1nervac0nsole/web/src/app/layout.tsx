import type { ReactNode } from "react";

import type { Metadata, Viewport } from "next";

import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { APP_CONFIG } from "@/config/app-config";
import { IntlRuntimeProvider } from "@/i18n/intl-runtime-provider";
import { fontVars } from "@/lib/fonts/registry";

import "./globals.css";

export const metadata: Metadata = {
  title: APP_CONFIG.meta.title,
  description: APP_CONFIG.meta.description,
};

export const viewport: Viewport = {
  colorScheme: "dark",
  themeColor: "#000000",
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  // Appearance is fixed brand, not a user preference: one dark console palette,
  // Manrope + DM Mono, flat sticky shell. No stored cookie can override it.
  return (
    <html lang="en" className={`${fontVars} dark`}>
      <body className="min-h-screen antialiased">
        <IntlRuntimeProvider>
          <TooltipProvider>
            {children}
            <Toaster />
          </TooltipProvider>
        </IntlRuntimeProvider>
      </body>
    </html>
  );
}
