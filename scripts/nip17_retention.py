#!/usr/bin/env python
"""Preview or apply NIP-17 opaque envelope retention.

Dry-run is the default. This script never prints envelope_json or message content.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _load_runtime_env_from_pid(pid: str) -> None:
    for item in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
        if not item or b"=" not in item:
            continue
        key, value = item.split(b"=", 1)
        os.environ[key.decode(errors="ignore")] = value.decode(errors="ignore")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-age-days", type=int, default=90)
    parser.add_argument("--max-rows", type=int, default=10000)
    parser.add_argument("--apply", action="store_true", help="Actually delete rows. Default is dry-run.")
    parser.add_argument(
        "--runtime-pid",
        default=os.getenv("MAINPID"),
        help="Optional service MainPID to import runtime env without printing secrets.",
    )
    args = parser.parse_args()

    if args.runtime_pid:
        _load_runtime_env_from_pid(str(args.runtime_pid))

    from wsgi import app

    with app.app_context():
        from app.services.nip17_storage import (
            apply_nip17_envelope_retention,
            preview_nip17_envelope_retention,
        )

        if args.apply:
            result = apply_nip17_envelope_retention(
                max_age_days=args.max_age_days,
                max_rows=args.max_rows,
            )
        else:
            result = preview_nip17_envelope_retention(
                max_age_days=args.max_age_days,
                max_rows=args.max_rows,
            )

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
