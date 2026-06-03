#!/usr/bin/env python3
"""Verify HODLXXI NIP-59 builder/client source obeys import policy.

This scanner is intentionally conservative. It checks future builder/client
source paths only. It does not scan docs, tests, JSON policy records, or this
script's own source, because those files must mention forbidden terms in order
to document and test the policy.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "frontend/nip59/import-policy.json"

DEFAULT_SCAN_PATHS = [
    ROOT / "app/static/js/nip59_client_bundle.js",
    ROOT / "scripts/build_nip59_client_bundle.mjs",
    ROOT / "frontend/nip59/src",
    ROOT / "frontend/nip59/client",
    ROOT / "frontend/nip59/builder",
]

SOURCE_SUFFIXES = {
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
}


def load_policy() -> dict:
    return json.loads(POLICY.read_text(encoding="utf-8"))


def iter_source_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if not path.exists():
            continue
        if path.is_file():
            if path.suffix in SOURCE_SUFFIXES:
                yield path
            continue
        for child in path.rglob("*"):
            if child.is_file() and child.suffix in SOURCE_SUFFIXES:
                yield child


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def scan_file(path: Path, forbidden_terms: list[str]) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    violations = []
    rel = display_path(path)
    for term in forbidden_terms:
        if term in text:
            violations.append(f"{rel}: contains forbidden term {term!r}")
    return violations


def main() -> int:
    policy = load_policy()
    forbidden_terms = list(policy.get("forbiddenImports", [])) + list(policy.get("forbiddenIdentifiers", []))

    violations: list[str] = []
    scanned: list[Path] = []

    for path in iter_source_files(DEFAULT_SCAN_PATHS):
        scanned.append(path)
        violations.extend(scan_file(path, forbidden_terms))

    if violations:
        print("ERROR: NIP-59 import policy violations found")
        for violation in violations:
            print(f"- {violation}")
        return 1

    print("ok: NIP-59 import policy holds")
    print(f"scanned_files={len(scanned)}")
    for path in scanned:
        print(f"- {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
