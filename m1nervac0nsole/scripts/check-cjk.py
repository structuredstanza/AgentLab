#!/usr/bin/env python3
"""Fail when non-English text (Hangul, Han, or CJK punctuation) reaches shipped code or the web UI.

Surfaces checked
----------------
1. Built HTML under `web/out`, raw, including inline scripts and React Server
   Components flight data, because user-visible strings travel there too.
2. Every authored source file in the repository: Go, Python, TypeScript,
   JavaScript, JSON, CSS, SQL and TOML. This is what catches a Chinese prompt
   string that no browser ever renders but every model reads.

Test files are exempt by rule, not by exception entry: `_test.go` and
`*.test.*` deliberately feed non-ASCII input to prove the system handles it,
and they ship nothing.

Hangul covers syllables (U+AC00-U+D7A3), Jamo (U+1100-U+11FF, U+3130-U+318F).
Han covers CJK Unified Ideographs (extension A and the main block), compatibility
ideographs, and supplementary-plane extensions. CJK punctuation and fullwidth
forms (U+3000-U+303F, U+FE30-U+FE4F, U+FF01-U+FF60, U+FFE0-U+FFE6) are checked
too, so bracketed or joined CJK cannot slip through.

Exceptions
----------
There are none, and the tables below are empty on purpose: every match string
that must recognise non-English input is now written with ASCII escapes
(`\\u6a21\\u578b`, `\\x{...}`, `U&'...'`), so the source stays pure ASCII while
the compiled value is unchanged. A content exemption is therefore never needed;
if a new one looks necessary, spell the string with escapes instead.

Run: `python3 -I scripts/check-cjk.py [out directory]`
Default out directory: `<repo>/web/out`. When it is absent the HTML phase is
skipped with a warning, so the source scan still works before a build.

Only the standard library is used, and no network access is performed.
"""
import os
import re
import subprocess
import sys

NON_ENGLISH = re.compile(
    r"[\uAC00-\uD7A3\u1100-\u11FF\u3130-\u318F"  # Hangul
    r"\u3400-\u4DBF\u4E00-\u9FFF\uF900-\uFAFF"  # Han
    # CJK punctuation and fullwidth forms (U+3000-303F, U+FE30-FE4F,
    # fullwidth U+FF01-FF60, U+FFE0-FFE6) so bracketed/joined CJK cannot pass.
    r"\u3000-\u303F\uFE30-\uFE4F\uFF01-\uFF60\uFFE0-\uFFE6"
    r"\U00020000-\U0002FFFF]"
)

SOURCE_EXTENSIONS = (
    ".go", ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".json", ".css", ".sql", ".toml",
)

# Never authored by this project, or generated from it.
SKIP_DIRS = {
    "node_modules", ".next", "dist", "out", ".git",
    ".translation-work", ".upstream-work", "vendor", "third_party",
}

# Tests feed non-ASCII input on purpose to prove the system handles it.
TEST_PATTERNS = ("_test.go", ".test.ts", ".test.tsx", ".test.js", ".test.mjs", ".test.cjs")

# (repo-relative path, exact substring on the flagged line, reason)
# Whole files that are recorded evidence or the checker's own pattern tables.
# Every match string is now spelled with ASCII escapes, so there are no content
# exceptions: the gate rejects any CJK codepoint outright.
FILE_EXEMPTIONS: dict = {}

# Lines exempted one by one: (path, exact substring on the line, reason).
EXCEPTIONS: list = []

# Multi-line constants and migrations. Each entry names a substring that appears on
# the first line and the number of following lines the constant spans, so a string
# literal split across lines is covered exactly rather than by proximity.
# (path, substring on the anchor line, extra following lines, reason)
BLOCK_EXCEPTIONS: list = []


def repo_root() -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.abspath(os.path.join(script_dir, ".."))
    if os.path.isdir(os.path.join(candidate, "web")):
        return candidate
    try:
        git_top = subprocess.check_output(
            ["git", "-C", script_dir, "rev-parse", "--show-toplevel"],
            text=True, stderr=subprocess.DEVNULL
        ).strip()
        if os.path.isdir(os.path.join(git_top, "m1nervac0nsole", "web")):
            return os.path.join(git_top, "m1nervac0nsole")
        if os.path.isdir(os.path.join(git_top, "web")):
            return git_top
    except Exception:
        pass
    return candidate


def find_out_dir(root: str) -> str:
    if len(sys.argv) > 1:
        return os.path.abspath(sys.argv[1])
    return os.path.join(root, "web", "out")


def is_test(rel: str) -> bool:
    return any(rel.endswith(p) for p in TEST_PATTERNS)


def iter_files(directory: str, suffixes: tuple, skip_tests: bool = False):
    for dirpath, dirnames, filenames in os.walk(directory):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if not name.endswith(suffixes):
                continue
            if skip_tests and any(name.endswith(p.lstrip(".")) or p in name for p in TEST_PATTERNS):
                continue
            yield os.path.join(dirpath, name)


def scan_file(path: str, root: str, exceptions_hit: set, offenders: list) -> None:
    rel = os.path.relpath(path, root).replace(os.sep, "/")
    if is_test(rel) or rel in FILE_EXEMPTIONS:
        return
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return

    # Lines covered by a block exception, keyed by BLOCK_EXCEPTIONS index.
    covered = {}
    for index, (b_path, anchor, span, _reason) in enumerate(BLOCK_EXCEPTIONS):
        if b_path != rel:
            continue
        for number, line in enumerate(lines, start=1):
            if anchor not in line:
                continue
            exceptions_hit.add(("block", index))
            for offset in range(span + 1):
                if number + offset <= len(lines):
                    covered[number + offset] = True

    for number, line in enumerate(lines, start=1):
        if not NON_ENGLISH.search(line) or covered.get(number):
            continue
        matched = False
        for index, (ex_path, fragment, _reason) in enumerate(EXCEPTIONS):
            if ex_path == rel and fragment in line:
                exceptions_hit.add(("line", index))
                matched = True
        if not matched:
            offenders.append((rel, number, line.strip()[:120]))


def report(message: str = "") -> None:
    print(message, file=sys.stderr)


def main() -> int:
    root = repo_root()
    out_dir = find_out_dir(root)

    offenders: list = []
    exceptions_hit: set = set()

    html_files: list = []
    if os.path.isdir(out_dir):
        html_files = list(iter_files(out_dir, (".html",)))
    else:
        report(f"warning: out directory not found, skipping built HTML: {out_dir}")

    source_files = list(iter_files(root, SOURCE_EXTENSIONS, skip_tests=True))

    for path in html_files + source_files:
        scan_file(path, root, exceptions_hit, offenders)

    stale = [f"line {EXCEPTIONS[i][0]} [{EXCEPTIONS[i][1]}] ({EXCEPTIONS[i][2]})"
             for i in range(len(EXCEPTIONS)) if ("line", i) not in exceptions_hit]
    stale += [f"block {BLOCK_EXCEPTIONS[i][0]} [{BLOCK_EXCEPTIONS[i][1]}] ({BLOCK_EXCEPTIONS[i][3]})"
              for i in range(len(BLOCK_EXCEPTIONS)) if ("block", i) not in exceptions_hit]

    print(
        f"checked {len(html_files)} HTML file(s) under {out_dir} and "
        f"{len(source_files)} source file(s) under {root}"
    )
    if offenders:
        report(f"non-English text found on {len(offenders)} line(s):")
        for rel, number, text in offenders:
            report(f"  {rel}:{number}: {text}")
    if stale:
        report("stale exception(s) matched nothing; remove or correct them:")
        for entry in stale:
            report(f"  {entry}")
    if offenders or stale:
        report(
            "\nTranslate the text to English. If it is genuine machine data "
            "(wire ID, protocol token, migration match), add a narrow EXCEPTIONS "
            "entry with the reason."
        )
        return 1
    print("no non-English text found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
