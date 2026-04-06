#!/usr/bin/env python3
"""Lightweight lint for hodlxxi-wiki structure and links."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WIKI_ROOT = ROOT / "hodlxxi-wiki" / "wiki"
RAW_ROOT = ROOT / "hodlxxi-wiki" / "raw"

REQUIRED_FILES = [
    "index.md",
    "log.md",
    "Overview.md",
    "Trust-Model.md",
    "Runtime-State.md",
    "Agent-Capabilities.md",
    "Auth-Surfaces.md",
    "Lightning-Payments.md",
    "Covenant-Model.md",
    "Reputation-Surface.md",
    "Architecture.md",
    "What-Works-Now.md",
    "Experimental.md",
    "Roadmap.md",
]

RAW_SUBDIRS = ["repo", "docs", "runtime", "logs", "external"]

LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
TOP_HEADING_RE = re.compile(r"(?m)^#\s+\S+")


def main() -> int:
    errors: list[str] = []

    if not WIKI_ROOT.exists():
        print("ERROR: wiki directory not found:", WIKI_ROOT)
        return 1

    for file_name in REQUIRED_FILES:
        path = WIKI_ROOT / file_name
        if not path.exists():
            errors.append(f"Missing required file: {path.relative_to(ROOT)}")
            continue

        text = path.read_text(encoding="utf-8")
        if not text.strip():
            errors.append(f"Empty wiki file: {path.relative_to(ROOT)}")
            continue

        if not TOP_HEADING_RE.search(text):
            errors.append(f"Missing top-level heading in: {path.relative_to(ROOT)}")

    existing = {p.name for p in WIKI_ROOT.glob("*.md")}
    for file_name in sorted(existing):
        path = WIKI_ROOT / file_name
        text = path.read_text(encoding="utf-8")
        for link in LINK_RE.findall(text):
            if not link.endswith(".md"):
                continue
            target = (path.parent / link).resolve()
            if not target.exists():
                errors.append(f"Broken markdown link in {path.relative_to(ROOT)} -> {link}")

    index_text = (WIKI_ROOT / "index.md").read_text(encoding="utf-8") if (WIKI_ROOT / "index.md").exists() else ""
    for file_name in REQUIRED_FILES:
        if file_name == "index.md":
            continue
        if file_name not in index_text:
            errors.append(f"index.md missing reference to {file_name}")

    linked_targets = set(LINK_RE.findall(index_text))
    for file_name in REQUIRED_FILES:
        if file_name == "index.md":
            continue
        expected = f"./{file_name}"
        if expected not in linked_targets:
            errors.append(f"index.md missing direct link target {expected}")

    for subdir in RAW_SUBDIRS:
        path = RAW_ROOT / subdir
        if not path.exists() or not path.is_dir():
            errors.append(f"Missing raw subdirectory: {path.relative_to(ROOT)}")
            continue

        has_readme = (path / "README.md").exists()
        has_any_file = any(p.is_file() for p in path.iterdir())
        if not has_readme and not has_any_file:
            errors.append(f"Raw subdirectory missing README.md or files: {path.relative_to(ROOT)}")

    if errors:
        print("wiki_lint: FAILED")
        for err in errors:
            print(" -", err)
        return 1

    print("wiki_lint: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
