---
name: browser
description: "Drive the real headless Chromium through the Playwright MCP server: open a URL, read the page as an accessibility snapshot, and click, type, select or wait on elements. Use it when a target needs JavaScript to render, when a login or multi-step form must be completed, or when curl and raw HTTP show nothing useful. With traffic capture on, every request the browser makes is recorded by the proxy, so it is the tool to use when the traffic must become evidence."
---

# Browser

Two surfaces drive the Chromium installed in the image, and the operator selects
one with the `browser_driver` setting:

- `native` (the built-in driver): tools named `browser_open`, `browser_navigate`,
  `browser_snapshot`, `browser_click`, `browser_type`, `browser_press`,
  `browser_select`, `browser_wait`, `browser_screenshot`, `browser_upload`,
  `browser_log` (console and JS errors, with a cursor) and `browser_close`.
- `mcp` (the Playwright server): tools named `mcp__browser__browser_*`.

Both are available directly - no skill load is needed to call them - and both
speak the same snapshot/ref contract and go through the same scope guard, so the
guidance below applies to either. When the driver is `native`, the MCP row is
disabled, so you will see exactly one set.

Under an **authorized** engagement only.

## When to use it

- The page renders with JavaScript and the HTML source is an empty shell.
- The target is a login, MFA or multi-step form that needs a real session.
- A request must be visible in the task's recorded traffic: with capture on, the
  browser is launched through the recording proxy and its CA, so every request
  it makes is indexed and can be pinned to a finding.
- A CAPTCHA, consent wall or other human step blocks the flow (hand it off, see
  below).

Do not use it for what `curl`, `httpx` or a manifest tool already answers: a
static page, a JSON API, or a header check is cheaper and clearer as a command.

Obscura is the alternative for stealth fetches, but it bypasses the recording
proxy and its CA. When the traffic has to become evidence, use this browser, not
Obscura.

## Limits of the native driver

- `browser_select` drives a native `<select>` element. A custom dropdown (a div
  that opens a list) needs a click on the trigger and a click on the option,
  each followed by a new snapshot.
- The snapshot covers the top-level document. Content inside an iframe is not
  listed, so a login rendered in one cannot be driven; say so in a fact rather
  than guessing at refs that are not there.
- There is no `browser_eval`. Use Bash for anything that needs a script.

## The snapshot-then-act loop

The browser is driven by element references from a snapshot, not by selectors.

1. `browser_navigate` to the URL. The result reports the page URL and title.
2. `browser_snapshot` to read the page as an accessibility tree. Each element
   carries a `ref` such as `e12`.
3. Act on exactly one element, passing the `ref` (and the element description
   the snapshot showed). Native: `browser_click`, `browser_type`,
   `browser_select`, `browser_press`. MCP: `browser_click`, `browser_type`,
   `browser_select_option`, `browser_hover`, `browser_press_key`.
4. Take a **new snapshot before the next action**. A navigation, a click that
   rerenders the page, or any DOM change invalidates the old refs; reusing one
   fails or, worse, acts on the wrong element. Never batch several actions
   against refs from a single snapshot.
5. Use `browser_wait_for` when the page needs time (text to appear, an element
   to go away), then snapshot again.
6. `browser_take_screenshot` (native: `browser_screenshot`) when a visual state
   matters, and `browser_close` when the flow is finished: the session otherwise
   lives until the idle reaper, holding a browser process.

Record what the page showed as facts as you go: the URL, the form fields, the
responses that matter. A browser session leaves no useful trace for the next
intent unless you write it down.

## Boundary

Navigation is judged against the task's scope before the page opens. A URL on an
excluded host is refused with the host named; do not retry it or work around it,
record the boundary and continue elsewhere. Only absolute `http` and `https`
URLs are accepted: `file:`, `chrome:` and `data:` are refused.

`browser_evaluate` runs JavaScript in the page and is **not** judged. Do not use
it to fetch or drive a host the boundary excludes; a redirect or a script can
still leave the boundary, and the recording proxy will show it.

## Handing a human step to the operator

On a CAPTCHA, an MFA or OTP prompt, or a consent wall you cannot pass, stop and
call `ask_operator` instead of guessing, brute-forcing or abandoning the flow:

- State precisely what is on screen and what you need: the page URL, the exact
  prompt text, and the value or action required (for example "the login page
  shows a 6-digit code field; give me the code sent to the account's email").
- Attach a screenshot with `image_path` when a picture helps. With provider
  credentials configured (the normal case) the image cannot be redacted and is
  therefore not attached to the conversation: the hand-off text names the staged
  file (`uploads/...`) and the operator opens it in the task workspace. That is
  the intended behaviour, not an error - do not resend without the image.
- `ask_operator` waits for the operator for `timeout_seconds` (default 120,
  maximum 600). An answer arrives in the result. On timeout it returns
  `{pending: true, ask_id}` and the ask stays open: record what you already know
  as facts, and either continue with what you can do without the answer or call
  `ask_operator` again later with the same question - a late answer is kept for
  30 minutes and a retry collects it immediately. A second call while one is
  pending joins the same ask instead of asking twice.

## Practical notes

- The browser is headless. Anything only visible in a screenshot is not
  available to the model, so prefer the snapshot for reading the page.
- One page per flow is enough for most work. Close tabs you opened.
- Downloads and uploads: `browser_file_upload` takes a path on the container
  filesystem; save downloads under the task directory so later intents can find
  them.
- If the MCP server is not running, its tools are absent from the deferred list.
  Say so in the intent summary instead of retrying; the operator enables it in
  Settings -> MCP.
