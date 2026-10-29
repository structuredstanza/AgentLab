import createNextIntlPlugin from "next-intl/plugin";

import { fileURLToPath } from "node:url";

// Static export: `NEXT_EXPORT=1 next build` produces a pure static directory at web/out, which can be dropped directly into
// Runs from the nginx web root. Do not set this variable for development (next dev); keep the /api reverse proxy and hot reloading.
const isExport = process.env.NEXT_EXPORT === "1";
// Vercel demo: the whole site serves mock data, with no backend, so no /api reverse proxy is needed.
const isMock = process.env.NEXT_PUBLIC_MOCK === "1";

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Avoid a lockfile in a parent directory affecting root inference and asset path generation.
  turbopack: { root: fileURLToPath(new URL(".", import.meta.url)) },
  reactCompiler: true,
  // Allow dev resources (HMR) to be accessed from LAN IPs; add or remove entries as needed.
  // In dev, allow access to /_next/* and HMR from any IPv4 source (changes to the LAN IP do not affect this).
  // Note: For security, Next forbids a bare "*", so use segmented wildcards; "*.*.*.*" matches any IPv4 address.
  allowedDevOrigins: ["*.*.*.*"],
  compiler: {
    removeConsole: process.env.NODE_ENV === "production",
  },
  ...(isExport
    ? {
        // Pure static export: no Node runtime; images are not optimized; each route produces <route>/index.html.
        output: "export",
        images: { unoptimized: true },
        trailingSlash: true,
      }
    : isMock
      ? {
          // Vercel mock demo: no backend, so no /api reverse proxy is needed.
          images: { unoptimized: true },
        }
      : {
          // Development: reverse-proxy /api/* to the Go backend (default :8787, can be overridden with AUTOPENTEST_API).
          async rewrites() {
            const backend = process.env.AUTOPENTEST_API ?? "http://localhost:8787";
            return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }];
          },
        }),
};

// next-intl plugin. The request configuration lives in src/i18n/request.ts. i18n path routing
// is not used, no middleware is added (compatible with static export output: "export").
const withNextIntl = createNextIntlPlugin("./src/i18n/request.ts");

export default withNextIntl(nextConfig);
