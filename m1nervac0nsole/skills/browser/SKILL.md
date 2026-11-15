---
name: browser
description: "Drive the real headless Chromium against an engagement target: open a URL, read the page as an accessibility snapshot, and click, type, select or wait on elements. Use it when a target needs JavaScript to render, when a login or multi-step form must be completed, or when curl and raw HTTP show nothing useful. With traffic capture on, every request the browser makes is recorded by the proxy, so it is the tool to use when the traffic must become evidence. Public documentation, repositories and advisories are the research browser's job instead."
---

# Browser

These tools drive the Chromium installed in the image. They are the **testing**
browser: they work on an engagement target, inside a task, under that task's
scope, and with traffic capture on every request they make is recorded.

They are available directly - no skill load is needed to call them.

## Research is a different browser

Looking up public documentation, repositories, advisories or a CVE writeup is
**not** this browser's job: that is the research browser, `mcp__obscura__*` (see
the `obscura` skill). It needs no task, it refuses engagement targets and private
addresses, and it will not touch the engagement's cookies.

The reverse is the rule that matters: a page on the engagement is this browser's
job, and a chat with no task has no testing browser at all.

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

## Limits

- `browser_select` drives a native `<select>` element. A custom dropdown (a div
  that opens a list) needs a click on the trigger and a click on the option,
  each followed by a new snapshot.
- The snapshot covers the top-level document. Content inside an iframe is not
  listed, so a login rendered in one cannot be driven; say so in a fact rather
  than guessing at refs that are not there.
- There is no `browser_eval`. Use Bash for anything that needs a script.
- The browser is headless. Anything only visible in a screenshot is not
  available to the model, so prefer the snapshot for reading the page.

## The snapshot-then-act loop

The browser is driven by element references from a snapshot, not by selectors.

1. `browser_navigate` to the URL. The result reports the page URL and title.
2. `browser_snapshot` to read the page as an accessibility tree. Each element
   carries a `ref` such as `e12`.
3. Act on exactly one element, passing the `ref` (and the element description
   the snapshot showed): `browser_click`, `browser_type`, `browser_select`,
   `browser_press`.
4. Take a **new snapshot before the next action**. A navigation, a click that
   rerenders the page, or any DOM change invalidates the old refs; reusing one
   fails or, worse, acts on the wrong element. Never batch several actions
   against refs from a single snapshot.
5. Use `browser_wait` when the page needs time (text to appear, an element to go
   away), then snapshot again.
6. `browser_screenshot` when a visual state matters, and `browser_close` when the
   flow is finished: the session otherwise lives until the idle reaper, holding a
   browser process.

Record what the page showed as facts as you go: the URL, the form fields, the
responses that matter. A browser session leaves no useful trace for the next
intent unless you write it down.

## Boundary

Navigation is judged against the task's scope before the page opens. A URL on an
excluded host is refused with the host named; do not retry it or work around it,
record the boundary and continue elsewhere. Only absolute `http` and `https`
URLs are accepted: `file:`, `chrome:` and `data:` are refused.

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

- One page per flow is enough for most work. Close tabs you opened.
- Uploads: `browser_upload` takes a path relative to the task workspace. Save
  downloads under the task directory so later intents can find them.
- If the tools are absent from your prompt, the operator has not bound them to
  your agent. Say so in the intent summary instead of retrying.
