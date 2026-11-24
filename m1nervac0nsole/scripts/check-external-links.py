#!/usr/bin/env python3
"""Check whether external links (http·https) referenced by tracked Markdown documents are still live.

The sibling script, `check-doc-links.py`, checks only internal repository links and anchors;
it deliberately skips external URLs because network dependence makes it flaky for merge gates.
This script handles that "separate check." If an external link directing visitors
to a destination (incident-reporting portals, CISA KEV, OWASP, SigmaHQ, Suricata,
MITRE, MISP, GitHub badges, etc.) in the README or dated feature docs changes,
moves, or closes, it would otherwise remain silently broken. This
script catches those links periodically and manually.

Rules for choosing URLs to check
- Scan every tracked `.md`, but skip URLs inside fenced code blocks (``` or ~~~) and inline code
  spans (`` `...` ``). URLs there are command examples, configuration values, or quoted external
  assets (e.g. `id.redhaze.top` in a side-question verification document), not reference links
  readers are expected to follow.
- Collect http·https addresses from Markdown links and images (`[text](url)`·`![alt](url)`),
  autolinks (`<url>`), and bare URLs in remaining prose.
- Exclude reserved and placeholder hosts: localhost; private/loopback IPs (127.·10.·192.168.·
  169.254.·172.16–31.·0.0.0.0·::1); RFC 2606/6761 reserved domains (example.com/org/net/edu·
  `*.example.*`·`.test`·`.invalid`·`.local`·`.tld`); and names without a dot that are not FQDNs
  (e.g. `target`).

How liveness is checked (the lesson learned from the first liveness runs)
Public government and security sites may reject HEAD requests or the default User-Agent,
or redirect several times, so a simple check can misclassify a working link as broken. This
script therefore checks **with a browser User-Agent, using GET, and following redirects**. It
uses three categories:
- OK: final status is 2xx·3xx. The link is valid.
- RESTRICTED: 401·403·405·429. The host is live, but its access policy (bot blocking, rejected
  method, or rate limiting) prevents this check; the link is not considered broken. It is
  reported, but does not count as a failure.
- DOWN: 404·410·5xx (even after retries) or DNS/connection/timeout/SSL errors (even after retries).
  The link is likely broken.

Network errors, 5xx, and 429 responses are retried with a short delay to distinguish temporary
flakiness from a real outage. This uses only the standard library. It sends GET requests only to
reference URLs already linked from the repository's **public documents** to check liveness; it
does not scan or probe any target.

Known exceptions (allowlist)
If a URL listed in `scripts/external-links-allowlist.txt` is DOWN, it is classified separately
as "ALLOWED" and excluded from the strict exit code. This transparently records dead links
inherited from upstream, unmodified source-preservation files (e.g. an upstream changelog) that
we do not own and cannot fix. That way, a periodic strict check does not stay red forever because
of one such link; it turns red only when a **newly broken link appears**.

Usage
- Default (report only; exit code 0): `python3 -I scripts/check-external-links.py`
- Periodic or release check, not a merge gate (fail on newly broken links): `--strict` (exit
  code 1 if any DOWN URL is not on the allowlist). RESTRICTED and ALLOWED do not fail strict mode.
- Preview the extracted set without network access: `--list` (print URLs to check and their
  sources without making requests).
"""
import argparse
import http.client
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from urllib.parse import urlsplit

# [text](url) for body links (not images) and ![alt](url) for images. The path runs up to whitespace or the closing parenthesis.
MD_LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)")
MD_IMAGE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)")
# <https://...> autolinks.
AUTOLINK = re.compile(r"<(https?://[^>\s]+)>")
# Bare URL inside prose. Strip trailing punctuation from the end.
BARE_URL = re.compile(r"https?://[^\s)>\]\"'`]+")
# Inline code spans `...` (single backticks). They are blanked out with spaces before extraction.
INLINE_CODE = re.compile(r"`[^`]*`")
# Punctuation that commonly trails a URL in prose.
TRAILING_PUNCT = ".,;:!?\"'»)]}>"

# IPv4 private/loopback/link-local ranges (172.16~31. is a separate pattern).
PRIVATE_IPV4 = re.compile(r"^(127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0$)")
PRIVATE_IPV4_172 = re.compile(r"^172\.(1[6-9]|2\d|3[01])\.")

BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"
)

# Host is alive, but the server policy blocks the status code used for verification (not broken).
RESTRICTED_CODES = {401, 403, 405, 429}

ALLOWLIST_PATH = os.path.join("m1nervac0nsole", "scripts", "external-links-allowlist.txt")


# Scan scope: the module, the two root docs and the repository templates. The
# root is the git root so relative links resolve from where they are authored.
MODULE = "m1nervac0nsole/"
ROOT_DOCS = ("README.md", "AGENTS.md")


def in_scope(path: str) -> bool:
    return path.startswith(MODULE) or path in ROOT_DOCS or path.startswith(".github/")


def load_allowlist(root: str) -> set:
    """Read the set of known DOWN URLs we cannot fix (empty set if the file is missing).

    One URL per line. Text after `#` is a comment; blank and comment-only lines are ignored.
    """
    path = os.path.join(root, ALLOWLIST_PATH)
    allow = set()
    if not os.path.exists(path):
        return allow
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                allow.add(line)
    return allow


def strip_code(line: str) -> str:
    """Remove inline code spans from a line outside a fence (URLs inside them are not references)."""
    return INLINE_CODE.sub(" ", line)


def is_checkable(url: str) -> bool:
    """Filter out reserved and placeholder hosts, keeping only external URLs worth checking."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return False
    host = parts.hostname
    if not host:
        return False
    host = host.lower()
    if host == "localhost" or host.endswith(".localhost"):
        return False
    if host == "::1":
        return False
    if PRIVATE_IPV4.match(host) or PRIVATE_IPV4_172.match(host):
        return False
    if host in ("example.com", "example.org", "example.net", "example.edu"):
        return False
    if host.endswith((".example.com", ".example.org", ".example.net", ".example")):
        return False
    if host.endswith((".test", ".invalid", ".local", ".localdomain", ".tld")):
        return False
    if "." not in host:  # Bare name, not an FQDN (e.g., target)
        return False
    return True


def extract(root: str, md_files: list) -> dict:
    """Build a dict mapping external URLs to check in tracked .md files to [(file, line number), ...]."""
    found = defaultdict(list)
    for md in md_files:
        with open(os.path.join(root, md), encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
        in_fence = False
        for lineno, raw in enumerate(lines, 1):
            stripped = raw.lstrip()
            if stripped.startswith("```") or stripped.startswith("~~~"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            line = strip_code(raw)
            candidates = []
            for pattern in (MD_LINK, MD_IMAGE, AUTOLINK):
                candidates.extend(m.group(1) for m in pattern.finditer(line))
            for m in BARE_URL.finditer(line):
                candidates.append(m.group(0).rstrip(TRAILING_PUNCT))
            for url in candidates:
                url = url.strip().rstrip(TRAILING_PUNCT)
                if is_checkable(url):
                    where = (md, lineno)
                    if where not in found[url]:
                        found[url].append(where)
    return found


def probe(url: str, timeout: float, retries: int, delay: float):
    """Send a GET to the URL with a browser UA and return (verdict, detail).

    Verdict is "OK", "RESTRICTED", or "DOWN". Network errors, 5xx, and 429 are retried.
    """
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": BROWSER_UA,
            "Accept": "*/*",
            "Accept-Language": "ko,en;q=0.8",
        },
    )
    last = ""
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                code = resp.getcode()
                if code in RESTRICTED_CODES:
                    return "RESTRICTED", f"HTTP {code}"
                return "OK", f"HTTP {code}"
        except urllib.error.HTTPError as exc:
            code = exc.code
            if code in RESTRICTED_CODES:
                return "RESTRICTED", f"HTTP {code}"
            if code >= 500 or code == 408:
                last = f"HTTP {code}"  # May be transient, so retry
            else:
                return "DOWN", f"HTTP {code}"  # 404, 410, etc. are definitive; no retry needed
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            ssl.SSLError,
            socket.timeout,
            ConnectionError,
            TimeoutError,
            OSError,
        ) as exc:
            reason = getattr(exc, "reason", exc)
            last = f"{type(exc).__name__}: {reason}"
        if attempt < retries:
            time.sleep(delay * (attempt + 1))
    return "DOWN", last


def main() -> int:
    ap = argparse.ArgumentParser(description="Check external link liveness in tracked Markdown")
    ap.add_argument("--strict", action="store_true",
                    help="Exit with code 1 if any DOWN link is found (for periodic/release checks)")
    ap.add_argument("--list", action="store_true",
                    help="Print the URLs to check and their sources without making network calls")
    ap.add_argument("--timeout", type=float, default=15.0, help="Request timeout (seconds)")
    ap.add_argument("--retries", type=int, default=2, help="Retries for network errors, 5xx, and 429")
    ap.add_argument("--delay", type=float, default=0.5, help="Base delay between calls and retries (seconds)")
    args = ap.parse_args()

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    try:
        tracked = {p for p in subprocess.check_output(["git", "ls-files", "."], cwd=root, text=True).splitlines() if in_scope(p)}
        deleted = {p for p in subprocess.check_output(["git", "ls-files", "--deleted", "."], cwd=root, text=True).splitlines() if in_scope(p)}
    except Exception:
        tracked = set()
        for dirpath, _, filenames in os.walk(root):
            if "/.git" in dirpath or "/node_modules" in dirpath:
                continue
            for f in filenames:
                rel = os.path.relpath(os.path.join(dirpath, f), root).replace(os.sep, "/")
                tracked.add(rel)
        deleted = set()
    for path in sorted(p for p in deleted if p.endswith(".md")):
        print(f"note: tracked but deleted from worktree, not scanned: {path}", file=sys.stderr)
    md_files = sorted(f for f in tracked - deleted if f.endswith(".md"))

    allow = load_allowlist(root)
    found = extract(root, md_files)
    urls = sorted(found)
    print(f"Collected {len(urls)} external URLs to check from {len(md_files)} tracked Markdown files")

    if args.list:
        for url in urls:
            where = ", ".join(f"{f}:{ln}" for f, ln in found[url])
            tag = " [allowlist]" if url in allow else ""
            print(f"  {url}{tag}  ({where})")
        return 0

    results = {"OK": [], "RESTRICTED": [], "ALLOWED": [], "DOWN": []}
    for i, url in enumerate(urls):
        if i:
            time.sleep(args.delay)  # Slight delay between calls (to avoid sandbox throttling)
        verdict, detail = probe(url, args.timeout, args.retries, args.delay)
        if verdict == "DOWN" and url in allow:
            verdict = "ALLOWED"  # Known upstream-inherited DOWN that cannot be fixed
        results[verdict].append((url, detail))
        print(f"  [{verdict:10}] {url} — {detail}")

    print(
        f"\nSummary: OK {len(results['OK'])} · RESTRICTED {len(results['RESTRICTED'])} · "
        f"ALLOWED {len(results['ALLOWED'])} · DOWN {len(results['DOWN'])}"
    )
    if results["RESTRICTED"]:
        print("RESTRICTED (host is live, but the check is blocked; not a broken link):")
        for url, detail in results["RESTRICTED"]:
            print(f"  {url} — {detail}")
    if results["ALLOWED"]:
        print("ALLOWED (known DOWN in allowlist — we cannot fix it, so excluded from strict):")
        for url, detail in results["ALLOWED"]:
            where = ", ".join(f"{f}:{ln}" for f, ln in found[url])
            print(f"  {url} — {detail}  (ref: {where})")
    if results["DOWN"]:
        print("DOWN (likely broken — needs review):")
        for url, detail in results["DOWN"]:
            where = ", ".join(f"{f}:{ln}" for f, ln in found[url])
            print(f"  {url} — {detail}  (ref: {where})")

    if args.strict and results["DOWN"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
