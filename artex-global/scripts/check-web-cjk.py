#!/usr/bin/env python3
"""Fail when non-English text (Hangul or Han) reaches the English web UI.

Two surfaces are checked:

1. Built HTML under `web/out` (raw content, including inline scripts and React
   Server Components flight data, because user-visible strings travel there too).
2. Authored UI source under `web/src` (TS/TSX/JS/MJS/CJS/JSON/CSS), including
   tests and client-side mock data. Mock data renders at runtime and never
   appears in `out`, so this scan is the only gate for it.

Hangul covers syllables (U+AC00-U+D7A3), Jamo (U+1100-U+11FF, U+3130-U+318F).
Han covers CJK Unified Ideographs (extension A and the main block), compatibility
ideographs, and supplementary-plane extensions. Kana and CJK punctuation are not
checked.

Exceptions
----------
`EXCEPTIONS` is the only way to pass a non-English line. Each entry names one
repo-relative path, an exact substring that must appear on the flagged line, and
the reason it is machine data rather than UI text. An exception that no longer
matches anything fails the check, so stale entries cannot pile up.

Run: `python3 -I scripts/check-web-cjk.py [out directory]`
Default out directory: `<git root>/web/out`. The source directory is the sibling
`src` of that out directory. CI runs it from `web/` as
`python3 -I ../scripts/check-web-cjk.py`.

Only the standard library is used, and no network access is performed.
"""
import os
import re
import subprocess
import sys

NON_ENGLISH = re.compile(
    r"[\uAC00-\uD7A3\u1100-\u11FF\u3130-\u318F"  # Hangul
    r"\u3400-\u4DBF\u4E00-\u9FFF\uF900-\uFAFF"  # Han
    r"\U00020000-\U0002FFFF]"
)

SOURCE_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json", ".css")

# (repo-relative path, exact substring on the flagged line, reason)
EXCEPTIONS: list = [
    ("web/src/lib/chat-mentions.ts", 'label: "漏洞"', "LEGACY READ: label map maps stored Chinese kind 漏洞 to finding; new mentions serialize English kinds"),
    ("web/src/lib/chat-mentions.ts", 'label: "资产"', "LEGACY READ: label map maps stored Chinese kind 资产 to asset; new mentions serialize English kinds"),
    ("web/src/lib/chat-mentions.ts", 'label: "企业"', "LEGACY READ: label map maps stored Chinese kind 企业 to company; new mentions serialize English kinds"),
    ("web/src/lib/chat-mentions.ts", 'label: "接口"', "LEGACY READ: label map maps stored Chinese kind 接口 to endpoint; new mentions serialize English kinds"),
    ("web/src/lib/chat-mentions.ts", 'label: "应用"', "LEGACY READ: label map maps stored Chinese kind 应用 to app; new mentions serialize English kinds"),
    ("web/src/lib/chat-mentions.ts", 'label: "域名"', "LEGACY READ: label map maps stored Chinese kind 域名 to root_domain; new mentions serialize English kinds"),
    ("web/src/lib/chat-mentions.ts", 'label: "子域名"', "LEGACY READ: label map maps stored Chinese kind 子域名 to subdomain; new mentions serialize English kinds"),
    ("web/src/lib/chat-mentions.ts", 'label: "服务"', "LEGACY READ: label map maps stored Chinese kind 服务 to service; new mentions serialize English kinds"),
    ("web/src/lib/chat-mentions.ts", "|漏洞|资产|企业|接口|IP|应用|域名|子域名|服务)#", "LEGACY READ: mention parser regex accepts stored Chinese kind tokens; new mentions serialize English kinds"),
    ("web/src/lib/chat-mentions.test.mjs", "已选 @[漏洞#1", "fixture: multilingual mention input"),
    ("web/src/lib/chat-mentions.test.mjs", "查看@漏洞", "fixture: multilingual mention input"),
    ("web/src/lib/chat-mentions.test.mjs", "下一行", "fixture: multiline mention input"),
    ("web/src/lib/chat-mentions.test.mjs", 'mentionSearch("漏', "fixture: multilingual search query"),
    ("web/src/lib/chat-mentions.test.mjs", "接口 GET /api", "fixture: multilingual search query"),
    ("web/src/lib/chat-mentions.test.mjs", "标题[1]", "fixture: multilingual token label"),
    ("web/src/lib/chat-mentions.test.mjs", "分析 ${first}", "fixture: multilingual message text"),
    ("web/src/lib/chat-mentions.test.mjs", "标题（1） 描述", "fixture: expected multilingual output"),
    ("web/src/lib/company-scope.ts", "/icp|备案/i", "ICP filing input rule; matches Chinese filing text by design"),
    ("web/src/components/approval-records.tsx", 'startsWith("[模型]")', "legacy reason prefix; decision_source is checked first"),
    ("web/src/components/approval-records.tsx", r'/^\[(Model|模型)\]\s*/', "legacy reason prefix strip; canonical [Model] and historical [模型] rows"),
    ("web/src/lib/mock/handler.ts", 'startsWith("[模型]")', "legacy reason prefix fallback in demo data"),
    ("web/src/lib/mock/data.ts", '"[模型] Deletes', "historical demo reason with legacy marker"),
    ("web/src/lib/mock/data.ts", '"[模型] Suspected', "historical demo reason with legacy marker"),
    ("web/src/lib/mock/data.ts", '"[模型] Recording', "historical demo reason with legacy marker"),
]


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
        if os.path.isdir(os.path.join(git_top, "artex-global", "web")):
            return os.path.join(git_top, "artex-global")
        if os.path.isdir(os.path.join(git_top, "web")):
            return git_top
    except Exception:
        pass
    return candidate


def find_out_dir(root: str) -> str:
    if len(sys.argv) > 1:
        return os.path.abspath(sys.argv[1])
    return os.path.join(root, "web", "out")


def iter_files(directory: str, suffixes: tuple):
    for dirpath, _dirnames, filenames in os.walk(directory):
        for name in sorted(filenames):
            if name.endswith(suffixes):
                yield os.path.join(dirpath, name)


def scan_file(path: str, root: str, exceptions_hit: set, offenders: list) -> None:
    rel = os.path.relpath(path, root).replace(os.sep, "/")
    with open(path, encoding="utf-8", errors="ignore") as fh:
        lines = fh.read().splitlines()
    for number, line in enumerate(lines, start=1):
        if not NON_ENGLISH.search(line):
            continue
        matched = False
        for index, (ex_path, fragment, _reason) in enumerate(EXCEPTIONS):
            if ex_path == rel and fragment in line:
                exceptions_hit.add(index)
                matched = True
        if not matched:
            offenders.append((rel, number, line.strip()[:120]))


def report(message: str = "") -> None:
    print(message, file=sys.stderr)


def main() -> int:
    root = repo_root()
    out_dir = find_out_dir(root)
    src_dir = os.path.join(os.path.dirname(out_dir), "src")
    if not os.path.isdir(out_dir):
        report(
            f"error: out directory not found: {out_dir}\n"
            "Run `npm run build:static` first, then rerun this check."
        )
        return 2

    html_files = list(iter_files(out_dir, (".html",)))
    if not html_files:
        report(f"error: no HTML files under {out_dir}; confirm the build succeeded.")
        return 2

    offenders: list = []
    exceptions_hit: set = set()
    source_files = list(iter_files(src_dir, SOURCE_EXTENSIONS)) if os.path.isdir(src_dir) else []
    for path in html_files + source_files:
        scan_file(path, root, exceptions_hit, offenders)

    stale = [
        EXCEPTIONS[i] for i in range(len(EXCEPTIONS)) if i not in exceptions_hit
    ]

    print(
        f"checked {len(html_files)} HTML file(s) under {out_dir} and "
        f"{len(source_files)} source file(s) under {src_dir}"
    )
    if offenders:
        report(f"non-English text found on {len(offenders)} line(s):")
        for rel, number, text in offenders:
            report(f"  {rel}:{number}: {text}")
    if stale:
        report("stale exception(s) matched nothing; remove or correct them:")
        for ex_path, fragment, reason in stale:
            report(f"  {ex_path} [{fragment}] ({reason})")
    if offenders or stale:
        report(
            "\nTranslate the text to English. If it is genuine machine data "
            "(wire ID, protocol token, fixture), add a narrow EXCEPTIONS entry "
            "with the reason."
        )
        return 1
    print("no non-English text found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
