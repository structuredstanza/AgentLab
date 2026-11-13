#!/usr/bin/env python3
"""Check the integrity of internal links, images, and anchor references in Markdown documents in the repository.

Scans every tracked `.md` document and checks two things.

1. Whether relative path links to other files in the repository (`[text](path)`) and image
   references (`![alt](path)`, `<img src="path">`) point to files that actually exist.
2. Whether document anchor links (`[text](#heading)`, `[text](other.md#heading)`) point to
   headings that actually exist in the target `.md` document. Anchor slugs are reproduced with
   the standard library using GitHub's rules (lowercase, keep only `\\p{Word}`, hyphens, and
   spaces, then turn spaces into hyphens; duplicate slugs get `-1`, `-2` suffixes in order of
   appearance).

If any broken reference exists, the script exits with code 1. It can therefore be used as-is
in the CI merge gate (`.github/workflows/docs.yml` at the git root) and for contributors' local verification.

Not checked:
- External URLs (`http://`, `https://`, `mailto:`, `tel:`, `data:`): they depend on the network
  and are flaky, so this deterministic gate does not handle them. External link status is
  checked separately.
- The `#` fragment of links to non-`.md` files (e.g. source code line numbers): it is not a
  heading anchor, so only file existence is checked and the anchor is not verified.
- The `#` fragment of image references: headings have no meaning for images.
- Example links and heading-like lines inside fenced code blocks (``` or ~~~): they are code
  examples, not real references or headings, so they are skipped.

Standard library only; does not connect to the network. Run: `python3 -I scripts/check-doc-links.py`
"""
import os
import re
import subprocess
import urllib.parse
import sys
import unicodedata
from collections import defaultdict

# A link in [text](path) that is not an image (`![...]`). The path runs up to the first space (excluding the title "...").
MD_LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)")
# ![alt](path) image link.
MD_IMAGE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)")
# <img ... src="path" ...> HTML image.
HTML_IMAGE = re.compile(r"<img[^>]*\bsrc=[\"']([^\"']+)[\"']", re.IGNORECASE)

# Network or non-file schemes. Anchors (`#`) refer to the same document, so they are not included here.
EXTERNAL_PREFIXES = ("http://", "https://", "mailto:", "tel:", "data:")

ATX_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
# Strip inline Markdown from the heading text, leaving only plain text.
MD_INLINE_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")


def is_external(target: str) -> bool:
    return target.startswith(EXTERNAL_PREFIXES)


def _is_word_char(ch: str) -> bool:
    """Determine whether a character is a `\\p{Word}` character that GitHub's anchor slug rules keep.

    Ruby regex `\\p{Word}` = Letter(L*) + Mark(M*) + Decimal_Number(Nd)
    + Connector_Punctuation(Pc) + Join_Control(U+200C·U+200D). Hangul, Hanja,
    underscores, and emoji variation selectors (Mn) are preserved.
    """
    if ch == "_":
        return True
    if ch in ("‌", "‍"):
        return True
    category = unicodedata.category(ch)
    if category[0] in ("L", "M"):
        return True
    return category in ("Nd", "Pc")


def slugify(text: str) -> str:
    """Convert heading text to a GitHub anchor slug (excluding duplicate-suffix handling)."""
    text = text.strip().lower()
    out = []
    for ch in text:
        if ch == " ":
            out.append("-")
        elif ch == "-" or _is_word_char(ch):
            out.append(ch)
    return "".join(out)


def heading_slugs(root: str, md: str) -> set:
    """Build the set of GitHub anchor slugs from every ATX heading in a file.

    When slugs collide, append `-1`, `-2`, ... in order of appearance, as GitHub does.
    """
    slugs = set()
    counts = defaultdict(int)
    in_fence = False
    with open(os.path.join(root, md), encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            stripped = line.lstrip()
            if stripped.startswith("```") or stripped.startswith("~~~"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            match = ATX_HEADING.match(line.rstrip("\n"))
            if not match:
                continue
            raw = match.group(2)
            raw = MD_INLINE_LINK.sub(r"\1", raw)
            raw = raw.replace("`", "").replace("*", "").replace("_", "")
            base = slugify(raw)
            seen = counts[base]
            counts[base] += 1
            slugs.add(base if seen == 0 else f"{base}-{seen}")
    return slugs


# Scan scope: the module, the two root docs and the repository templates. The
# root is the git root so relative links resolve from where they are authored.
MODULE = "m1nervac0nsole/"
ROOT_DOCS = ("README.md", "AGENTS.md")


def in_scope(path: str) -> bool:
    return path.startswith(MODULE) or path in ROOT_DOCS or path.startswith(".github/")


def main() -> int:
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    try:
        tracked = {p for p in subprocess.check_output(
            ["git", "ls-files", "."], cwd=root, text=True).splitlines() if in_scope(p)}
        deleted = {p for p in subprocess.check_output(
            ["git", "ls-files", "--deleted", "."], cwd=root, text=True).splitlines() if in_scope(p)}
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

    slug_cache: dict = {}

    def slugs_of(md_path: str) -> set:
        if md_path not in slug_cache:
            slug_cache[md_path] = heading_slugs(root, md_path)
        return slug_cache[md_path]

    checked_files = 0
    checked_anchors = 0
    broken_files = []
    broken_anchors = []
    for md in md_files:
        with open(os.path.join(root, md), encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
        base_dir = os.path.dirname(md)
        in_fence = False
        for lineno, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("```") or stripped.startswith("~~~"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            for pattern in (MD_LINK, MD_IMAGE, HTML_IMAGE):
                for match in pattern.finditer(line):
                    target = match.group(1).strip()
                    if is_external(target):
                        continue

                    if target.startswith("#"):
                        file_part, anchor = "", target[1:]
                    elif "#" in target:
                        file_part, anchor = target.split("#", 1)
                    else:
                        file_part, anchor = target, ""
                    file_part = file_part.split("?", 1)[0]
                    # Percent-escaped fragments are the same anchor to GitHub (e.g. %EF%B8%8F for U+FE0F).
                    anchor = urllib.parse.unquote(anchor).strip()

                    # The .md document being referenced (subject to anchor checking). If it is a link to another file, that file,
                    # A `#anchor` with no file component refers to the current document.
                    target_md = None
                    if file_part:
                        checked_files += 1
                        resolved = os.path.normpath(
                            os.path.join(root, base_dir, file_part)
                        )
                        if not os.path.exists(resolved):
                            broken_files.append((md, lineno, target))
                            continue
                        if file_part.endswith(".md"):
                            target_md = os.path.normpath(
                                os.path.join(base_dir, file_part)
                            )
                    else:
                        target_md = md

                    # Anchors are meaningful only for body links (MD_LINK). For image references,
                    # the `#` fragment is skipped.
                    if anchor and target_md is not None and pattern is MD_LINK:
                        checked_anchors += 1
                        if anchor not in slugs_of(target_md):
                            broken_anchors.append((md, lineno, target, target_md))

    print(
        f"Tracked Markdown: {len(md_files)} · file references: {checked_files} · "
        f"anchor references: {checked_anchors} checked"
    )
    if broken_files:
        print(f"Broken file references: {len(broken_files)} — the target file does not exist in the repository:")
        for md, lineno, target in broken_files:
            print(f"  {md}:{lineno} -> {target}")
    if broken_anchors:
        print(f"Broken anchor references: {len(broken_anchors)} — the target document has no such heading:")
        for md, lineno, target, target_md in broken_anchors:
            print(f"  {md}:{lineno} -> {target}  (target: {target_md})")
    if broken_files or broken_anchors:
        return 1
    print("Broken references: 0 — all internal links, images, and anchors point to existing targets.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
