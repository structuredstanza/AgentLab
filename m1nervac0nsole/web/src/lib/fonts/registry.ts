// Locally packaged fonts only: no runtime fetch, no network dependency at build or boot.
// Manrope (SIL OFL 1.1) and DM Mono (SIL OFL 1.1) ship under ./files with their license texts.
import localFont from "next/font/local";

const manrope = localFont({
  src: [{ path: "./files/Manrope-Variable-latin.woff2", weight: "200 800", style: "normal" }],
  variable: "--font-manrope",
  display: "swap",
  fallback: ["system-ui", "sans-serif"],
});

const dmMono = localFont({
  src: [
    { path: "./files/DM-Mono-400-latin.woff2", weight: "400", style: "normal" },
    { path: "./files/DM-Mono-500-latin.woff2", weight: "500", style: "normal" },
  ],
  variable: "--font-dm-mono",
  display: "swap",
  fallback: ["ui-monospace", "monospace"],
});

/** Font variables for the root <html>: Manrope for text, DM Mono for navigation and metadata. */
export const fontVars = `${manrope.variable} ${dmMono.variable}`;
