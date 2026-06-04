#!/usr/bin/env python3
"""Run the NIP-59 release gate verifier suite.

This script is a release-gate entrypoint. It does not install npm, generate a
lockfile, build a bundle, approve browser crypto, or enable send.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CHECKS = [
    "scripts/verify_nip59_builder_safety.py",
    "scripts/verify_nip59_import_policy.py",
    "scripts/verify_nip59_static_bundle.py",
]


def run_check(relative_path: str) -> int:
    path = ROOT / relative_path
    print(f"== {relative_path} ==")
    result = subprocess.run(
        [sys.executable, str(path)],
        cwd=ROOT,
        check=False,
    )
    return result.returncode


def main() -> int:
    failures: list[str] = []

    for check in CHECKS:
        rc = run_check(check)
        if rc != 0:
            failures.append(f"{check} exited {rc}")

    if failures:
        print("ERROR: NIP-59 release gate failed")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("ok: NIP-59 release gate holds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
