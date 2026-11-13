---
name: obscura
description: Drive the Obscura headless browser (Rust, V8) for JavaScript page loading, stealth browsing, screenshots, PDF export, CDP automation and MCP interaction. Use when a target needs a real JS engine, when Chromium is unavailable, or when a lighter, fingerprint-consistent browser is preferable.
mcps: obscura
---

# Obscura

Obscura is a Rust headless browser with an embedded V8 engine. It renders pages,
runs scripts, speaks the Chrome DevTools Protocol, and exposes an MCP server —
without Chromium. Use it for JS-rendered pages, screenshots, PDFs and scripted
interaction.

Adapted from the Obscura project's own skill (Apache-2.0),
<https://github.com/h4ckf0r0day/obscura>; this version is rewritten for this
console and may differ from upstream.

## Availability

The image installs the stealth build (`obscura` and `obscura-worker` on `PATH`).
On a host, install a release archive:

```bash
curl -LO https://github.com/h4ckf0r0day/obscura/releases/latest/download/obscura-x86_64-linux-stealth.tar.gz
tar xzf obscura-x86_64-linux-stealth.tar.gz
./obscura fetch https://example.com --eval "document.title"
```

`obscura --help` is the source of truth for the installed version. A
render-enabled build is required for screenshots, screencasts and PDFs.

## Fetch and capture

```bash
obscura fetch https://target/ --dump text
obscura fetch https://target/ --eval "document.title"
obscura fetch https://target/ --dump html --output page.html
obscura fetch https://target/ --dump links
obscura fetch https://target/ --screenshot page.png
obscura fetch https://target/ --wait-until networkidle0 --timeout 20
obscura fetch https://target/ --dump original > body.bin
```

- `--dump original` streams the raw response and bypasses the DOM/JS layer.
- `--dump assets` lists every sub-resource the page would fetch (NDJSON).
- An omitted `--wait` settles adaptively with a five-second cap; `--wait N` is a
  fixed delay.
- Loopback and private targets need `--allow-private-network` (or
  `OBSCURA_ALLOW_PRIVATE_NETWORK=1`); the SSRF guard also checks DNS results.

## CDP and MCP

```bash
obscura serve --port 9222            # CDP endpoint for Puppeteer/Playwright clients
obscura mcp                          # stdio MCP server (the seeded `obscura` server)
obscura mcp --http --port 3000       # HTTP MCP transport
```

With CDP, connect a Puppeteer/Playwright client via `connectOverCDP`. After any
navigation, click, scroll or framework rerender, refresh snapshots and element
references before acting on them.

## Stealth and proxies

`--stealth` (global flag) uses browser-matching TLS fingerprints, a consistent
UA/navigator/WebGL identity, masks `navigator.webdriver`, and blocks a tracker
list. It also bundles its own root certificates.

```bash
obscura --stealth fetch https://target/ --dump text
obscura --proxy socks5://127.0.0.1:1080 fetch https://target/ --dump text
```

Obscura ignores `HTTP_PROXY`/`HTTPS_PROXY`; pass `--proxy` explicitly, or
`OBSCURA_PROXY` for `serve`/workers. Keep `OBSCURA_TIMEZONE`,
`OBSCURA_GEOLOCATION` and the proxy region consistent.

## Working rules

- Prefer `fetch --dump text` for reading and `--eval` for one value; use CDP or
  MCP only when interaction is required.
- Obscura is not Chromium: long-tail CSS, some Web APIs, media playback and
  compositor effects can differ. Verify a rendering difference against a
  deterministic fixture before reporting it as a target issue.
- A screenshot or PDF proves what the engine rendered, not what a full Chrome
  build would show. Say which engine produced the evidence.
- When the engagement requires recorded browser traffic, use the capture-routed
  browser MCP instead: Obscura does not trust the recording proxy's CA.
