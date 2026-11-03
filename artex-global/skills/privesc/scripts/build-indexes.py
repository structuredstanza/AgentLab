#!/usr/bin/env python3
"""Build the compact GTFOBins and LOLBAS indexes shipped with the privesc skill.

The upstream repositories are large Jekyll/YAML trees; an agent in a task needs a
small lookup table, not a site generator. Run this from a checkout of each source
repository, then commit the resulting JSON.

    python3 build-indexes.py --gtfobins /path/to/GTFOBins.github.io \
                             --lolbas   /path/to/LOLBAS \
                             --out      ../reference

Only the fields a decision depends on are kept: which escape classes a binary
supports (sudo, suid, capabilities, ...) and one example command per class.
"""
import argparse
import json
import pathlib
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")


def gtfobins(root: pathlib.Path) -> dict:
    """One entry per executable: functions -> contexts -> example code."""
    entries = {}
    for path in sorted((root / "_gtfobins").iterdir()):
        if not path.is_file():
            continue
        # GTFOBins entries are a single YAML document opened by "---" with no
        # closing delimiter, so the whole file parses as YAML.
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        functions = doc.get("functions") or {}
        summary = {}
        for fname, variants in functions.items():
            if not isinstance(variants, list):
                continue
            contexts = set()
            example = ""
            for variant in variants:
                if not isinstance(variant, dict):
                    continue
                for ctx in (variant.get("contexts") or {}):
                    contexts.add(ctx)
                if not example and variant.get("code"):
                    example = variant["code"].strip()
            if contexts:
                summary[fname] = {
                    "contexts": sorted(contexts),
                    "example": example.splitlines()[0][:200] if example else "",
                }
        if summary:
            entries[path.name] = {"functions": summary}
    return entries


def lolbas(root: pathlib.Path) -> dict:
    """One entry per Windows binary: categories and one example command."""
    entries = {}
    for path in sorted((root / "yml").rglob("*.yml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict) or not doc.get("Name"):
            continue
        commands = doc.get("Commands") or []
        categories, example, mitre = set(), "", set()
        for cmd in commands:
            if not isinstance(cmd, dict):
                continue
            if cmd.get("Category"):
                categories.add(cmd["Category"])
            if cmd.get("MitreID"):
                mitre.add(cmd["MitreID"])
            if not example and cmd.get("Command"):
                example = cmd["Command"].strip()
        entries[doc["Name"]] = {
            "description": (doc.get("Description") or "").strip()[:300],
            "categories": sorted(categories),
            "mitre": sorted(mitre),
            "example": example[:200],
            "path": ((doc.get("Full_Path") or [{}])[0].get("Path") or "")[:200],
        }
    return entries


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gtfobins", type=pathlib.Path)
    ap.add_argument("--lolbas", type=pathlib.Path)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    if args.gtfobins:
        data = gtfobins(args.gtfobins)
        (args.out / "gtfobins.json").write_text(
            json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"gtfobins: {len(data)} executables")
    if args.lolbas:
        data = lolbas(args.lolbas)
        (args.out / "lolbas.json").write_text(
            json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"lolbas: {len(data)} binaries")


if __name__ == "__main__":
    main()
