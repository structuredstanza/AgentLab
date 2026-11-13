"use client";

import type { ReactNode } from "react";

import { NextIntlClientProvider } from "next-intl";

import enMessages from "../../messages/en.json";

// Browser and prerender time zone; NextIntlClientProvider needs it explicitly.
const TIME_ZONE = Intl.DateTimeFormat().resolvedOptions().timeZone;

export function IntlRuntimeProvider({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <NextIntlClientProvider locale="en" messages={enMessages} timeZone={TIME_ZONE}>
      {children}
    </NextIntlClientProvider>
  );
}
