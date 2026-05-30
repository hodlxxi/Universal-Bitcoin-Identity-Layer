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
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _load_runtime_env_from_pid(pid: str) -> None:
    for item in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
        if not item or b"=" not in item:
            continue
        key, value = item.split(b"=", 1)
        os.environ[key.decode(errors="ignore")] = value.decode(errors="ignore")


def _is_memory_database_url(db_url: str) -> bool:
    normalized = (db_url or "").strip().lower()
    return normalized in {"sqlite://", "sqlite:///:memory:", "sqlite:///:memory"} or ":memory:" in normalized


def _safe_database_target(db_url: str) -> dict[str, object]:
    parsed = urlparse(db_url)
    return {
        "scheme": parsed.scheme,
        "host": parsed.hostname or "",
        "database_path": parsed.path,
        "is_memory": _is_memory_database_url(db_url),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-age-days", type=int, default=90)
    parser.add_argument("--max-rows", type=int, default=10000)
    parser.add_argument("--apply", action="store_true", help="Actually delete rows. Default is dry-run.")
    parser.add_argument("--allow-memory-db", action="store_true", help="Allow sqlite memory DB for tests only.")
    parser.add_argument(
        "--runtime-pid",
        default=os.getenv("MAINPID"),
        help="Optional service MainPID to import runtime env without printing secrets.",
    )
    args = parser.parse_args()

    if args.runtime_pid:
        _load_runtime_env_from_pid(str(args.runtime_pid))

    from app.database import get_database_url

    db_url = get_database_url()
    db_target = _safe_database_target(db_url)

    if db_target["is_memory"] and not args.allow_memory_db:
        raise SystemExit(
            "Refusing to run NIP-17 retention against sqlite memory DB. "
            "Pass --runtime-pid for a real service DB or --allow-memory-db for tests only."
        )

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

    result["database"] = db_target
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
