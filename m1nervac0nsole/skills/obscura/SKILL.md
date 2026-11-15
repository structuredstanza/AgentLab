---
name: obscura
description: Research browser. Read public documentation, repositories, advisories, CVE writeups and vendor pages that need a real JavaScript engine, without touching an engagement target and without a task. Use it for any lookup outside the engagement; a page on the target is the native browser's job.
---

# Obscura

Obscura is a Rust headless browser with an embedded V8 engine. It renders pages,
runs scripts, speaks the Chrome DevTools Protocol, and exposes an MCP server -
without Chromium.

Adapted from the Obscura project's own skill (Apache-2.0),
<https://github.com/h4ckf0r0day/obscura>; this version is rewritten for this
console and may differ from upstream.

## What it is for

This is the **research** browser: public documentation, repositories, advisories,
CVE writeups, vendor release notes. It needs no task, so a chat can use it.

It is not a testing browser. A page on the engagement target - a login, a form, a
session, anything whose traffic has to become evidence - is the native browser's
job (`browser_*`, see the `browser` skill), inside a task, under that task's
scope. Obscura never carries the engagement's cookies or credentials.

## The boundary it enforces

The research boundary is the public web **minus** every live task's authorized
targets and minus private, loopback, link-local and metadata addresses. A
destination that is either is refused before the page loads, and a redirect that
lands on one is refused after it. There is no setting, flag or argument that
widens it from inside a run: do not try `--allow-private-network`, and do not
retry a refused URL. A refusal means "look this up somewhere else", and a target
system is tested with the native browser.

## The tools you get

The server offers more than this console exposes. Only reading and extraction are
assembled:

- `browser_navigate` - load a URL. `browser_back`, `browser_forward`,
  `browser_reload` move through its history.
- `browser_snapshot` - URL, title, actionable elements and visible text. Pass
  `max_chars: 0` for the URL and title alone.
- `browser_markdown`, `browser_links`, `browser_extract` - the page as markdown,
  its links, or structured content.
- `browser_search` - find text on the loaded page. `browser_wait_for_text` waits
  for it to appear.
- `browser_close` - drop the page.

There is no evaluate, no cookie or storage tool, no fill, no click and no second
tab. If a task seems to need one, it is a testing job, not a research one.

## Reading a page

1. `browser_navigate` to the URL. The result names the page it landed on, which
   may differ from the URL you asked for.
2. `browser_markdown` for prose, `browser_links` to find the next page,
   `browser_extract` for structured content, `browser_snapshot` when you need the
   page's controls and visible text.
3. `browser_close` when you are done with the source.

Cite what you read: the URL, the title and the date if the page shows one. A
research answer without its source is a guess.

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

## CLI reference

The MCP server is the only surface this console exposes. The CLI is useful when
you are diagnosing the install from Bash, and it obeys the same boundary:

```bash
obscura fetch https://example.com/ --dump text
obscura fetch https://example.com/ --eval "document.title"
obscura fetch https://example.com/ --dump html --output page.html
obscura fetch https://example.com/ --dump links
obscura fetch https://example.com/ --wait-until networkidle0 --timeout 20
obscura serve --port 9222            # CDP endpoint for Puppeteer/Playwright clients
obscura mcp                          # stdio MCP server (the seeded `obscura` server)
```

- `--dump original` streams the raw response and bypasses the DOM/JS layer.
- `--dump assets` lists every sub-resource the page would fetch (NDJSON).
- An omitted `--wait` settles adaptively with a five-second cap; `--wait N` is a
  fixed delay.

## Stealth and egress

`--stealth` (global flag, and how the seeded server starts) uses
browser-matching TLS fingerprints, a consistent UA/navigator/WebGL identity,
masks `navigator.webdriver`, and blocks a tracker list.

The platform routes the server through the gateway, which is the only egress a
tool session has. Obscura ignores `HTTP_PROXY`/`HTTPS_PROXY`, so the console
passes the gateway as `--proxy` at launch with the session's credential; do not
add a proxy flag of your own, and do not expect a direct connection to work.

## Working rules

- Prefer `browser_markdown` for reading and `browser_links` to navigate the docs;
  reach for `browser_snapshot` only when you need the page's controls.
- Obscura is not Chromium: long-tail CSS, some Web APIs, media playback and
  compositor effects can differ. Verify a rendering difference against a
  deterministic fixture before reporting it as a target issue.
- A screenshot or PDF proves what the engine rendered, not what a full Chrome
  build would show. Say which engine produced the evidence.
- Research is not evidence of a target finding. When the traffic has to become
  evidence, the native browser inside a task is the surface that records it.
