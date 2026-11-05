#!/usr/bin/env python3
"""Fail when non-English text (Hangul or Han) reaches shipped code or the web UI.

Surfaces checked
----------------
1. Built HTML under `web/out`, raw, including inline scripts and React Server
   Components flight data, because user-visible strings travel there too.
2. Every authored source file in the repository: Go, Python, TypeScript,
   JavaScript, JSON, CSS, SQL and TOML. This is what catches a Chinese prompt
   string that no browser ever renders but every model reads.

Test files are exempt by rule, not by exception entry: `_test.go` and
`*.test.*` deliberately feed non-ASCII input to prove the system handles it,
and they ship nothing. Everything else needs a narrow EXCEPTIONS entry.

Hangul covers syllables (U+AC00-U+D7A3), Jamo (U+1100-U+11FF, U+3130-U+318F).
Han covers CJK Unified Ideographs (extension A and the main block), compatibility
ideographs, and supplementary-plane extensions. Kana and CJK punctuation are not
checked.

Exceptions
----------
`EXCEPTIONS` is the only way to pass a non-English line. Each entry names one
repo-relative path, an exact substring that must appear on the flagged line, and
the reason it is machine data rather than authored text. An exception that no
longer matches anything fails the check, so stale entries cannot pile up.

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
    r"\U00020000-\U0002FFFF]"
)

SOURCE_EXTENSIONS = (
    ".go", ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".json", ".css", ".sql", ".toml",
)

# Never authored by this project, or generated from it.
SKIP_DIRS = {
    "node_modules", ".next", "dist", "out", "graft", ".git",
    ".translation-work", ".upstream-work", "vendor", "third_party",
}

# Tests feed non-ASCII input on purpose to prove the system handles it.
TEST_PATTERNS = ("_test.go", ".test.ts", ".test.tsx", ".test.js", ".test.mjs", ".test.cjs")

# (repo-relative path, exact substring on the flagged line, reason)
# Whole files that are recorded evidence or the checker's own pattern tables.
FILE_EXEMPTIONS = {
    "sidequestion/validation-2026-09-10.json":
        "recorded validation run: transcripts of a real session, kept as evidence",
    # This checker necessarily contains the patterns it looks for.
    "scripts/check-cjk.py": "the checker's own exception table",
}

# Lines exempted one by one: (path, exact substring on the line, reason).
EXCEPTIONS: list = [
    # --- the model's own error text, which upstream chooses -------------------
    ("agent/provider.go", '"余额不足", "额度不足", "额度已用尽", "欠费"',
     "quota classifier: an upstream provider may answer in Chinese, so the marker must match"),
    # --- ICP filing numbers are Chinese by definition -------------------------
    ("db/company_scope.go", 'strings.Contains(raw, "备案")',
     "ICP filing keyword; a Chinese filing number is the input being matched"),
    ("web/src/lib/company-scope.ts", "/icp|备案/i",
     "ICP filing input rule; matches Chinese filing text by design"),
    # --- historical rows still carry the Chinese marker ----------------------
    ("db/intercept.go", "'[模型]%'",
     "legacy reason prefix in SQL; historical rows still carry it"),
    ("db/intercept.go", 'strings.HasPrefix(reason, "[模型]")',
     "legacy reason prefix; canonical [Model] is checked first"),
    ("db/task_archives_restore.go", 'strings.HasPrefix(reason, "[模型]")',
     "legacy reason prefix; canonical [Model] is checked first"),
    ("db/schema.sql", "reason LIKE '[模型]%'",
     "legacy reason prefix in a schema migration"),
    ("intercept/intercept.go", 'strings.HasPrefix(out.Message, "[模型]")',
     "legacy reason prefix; canonical [Model] is checked first"),
    ("web/src/components/approval-records.tsx", 'startsWith("[模型]")',
     "legacy reason prefix; decision_source is checked first"),
    ("web/src/components/approval-records.tsx", "/^\\[(Model|模型)\\]\\s*/",
     "legacy reason prefix strip; canonical [Model] and historical [模型] rows"),
    ("web/src/lib/mock/handler.ts", 'startsWith("[模型]")',
     "legacy reason prefix fallback in demo data"),
    # --- historical mention syntax must keep parsing -------------------------
                # --- log severity keywords from process output ---------------------------
    ("server/logsink.go", '"失败", "丢弃", "拒绝"',
     "log severity keywords; child process output may be Chinese"),
    ("server/logsink.go", '"禁用", "⚠", "重试"',
     "log severity keywords; child process output may be Chinese"),
    # --- a shipped skill recognises a Chinese login page ---------------------
    ("skills/api-recon/scripts/preload.js", "/未登录|未授权|授权|",
     "login-page detector: a target's page may say 未登录, so the pattern must match it"),
]

# Multi-line constants and migrations. Each entry names a substring that appears on
# the first line and the number of following lines the constant spans, so a string
# literal split across lines is covered exactly rather than by proximity.
# (path, substring on the anchor line, extra following lines, reason)
BLOCK_EXCEPTIONS: list = [
    ("db/db.go", '{"[内置]', 0,
     "relabel migration: matches the original seeded name/message so a user-edited row is spared"),
    ("server/finding_retests.go", "name='漏洞复测'", 0,
     "relabel migration: matches the original seeded agent name"),
    ("server/finding_retests.go", "description='从漏洞详情手动启动", 0,
     "relabel migration: matches the original seeded agent description"),
    ("server/finding_workflow.go", 'legacy := "查询记录代理已抓取的目标流量', 0,
     "description migration: matches the original seeded tool description"),
    ("server/orchestration.go", "const reporterToolCallMessageV1", 2,
     "legacy trigger message: the migration matches this text to replace it"),
    ("server/orchestration.go", "const reporterToolCallMessageV2", 4,
     "legacy trigger message: the migration matches this text to replace it"),
    ("server/orchestration.go", "const reporterAgentNameV1", 0,
     "legacy seeded agent label: recognised so an untouched row can be relabelled"),
    ("server/orchestration.go", "const reporterAgentDescriptionV1", 0,
     "legacy seeded agent description: recognised so an untouched row can be relabelled"),
    ("server/server.go", 'strings.HasPrefix(m, "意图")', 1,
     "legacy mention directive prefix; historical input still parses"),
    ("server/server.go", 'strings.HasPrefix(m, "提示")', 1,
     "legacy mention directive prefix; historical input still parses"),
    ("server/conversations.go", 'legacyConvDefaultTitle = "새 대화"', 0,
     "legacy auto-generated title: recognised as a default, never written"),
    ("server/chat_mentions.go", "var chatMentionPattern", 0,
     "mention parser accepts stored Chinese kind tokens; new mentions serialize English"),
    ("server/chat_mentions.go", '"漏洞": "finding"', 1,
     "mention kind map: stored Chinese tokens resolve to English kinds"),
    ("web/src/lib/chat-mentions.ts", "/@\\[(finding|asset|", 0,
     "mention parser accepts stored Chinese kind tokens; new mentions serialize English"),
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
