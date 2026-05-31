#!/usr/bin/env python
"""Verify NIP-17 receiver inbox metadata using the runtime DB context.

This script prints metadata only. It never prints envelope_json, event content,
ciphertext, plaintext, signatures, or secrets.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _is_hex(value: str, length: int) -> bool:
    value = str(value or "").strip()
    return len(value) == length and all(ch in "0123456789abcdefABCDEF" for ch in value)


def _load_runtime_env_from_pid(pid: str) -> None:
    environ = Path(f"/proc/{pid}/environ")
    if not environ.exists():
        raise RuntimeError(f"runtime pid environ not found: {pid}")

    for item in environ.read_bytes().split(b"\0"):
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


def _redact_runtime_path(target: dict[str, object]) -> dict[str, object]:
    redacted = dict(target)
    path = str(redacted.get("database_path") or "")
    redacted["database_path"] = path.replace("/srv/ubid-staging", "<staging>").replace("/srv/ubid", "<prod>")
    return redacted


def _query_receiver_inbox(receiver: str, *, limit: int) -> dict[str, object]:
    """Query receiver inbox metadata.

    Imports and app initialization can emit startup logs. Callers that need
    machine-readable stdout should wrap this function with stdout capture.
    """

    from wsgi import app
    from app.database import session_scope
    from app.models import NIP17Envelope

    with app.app_context():
        with session_scope() as session:
            total = (
                session.query(NIP17Envelope.id)
                .filter(
                    NIP17Envelope.receiver_pubkey == receiver,
                    NIP17Envelope.status == "received",
                )
                .count()
            )

            rows = (
                session.query(NIP17Envelope)
                .filter(NIP17Envelope.receiver_pubkey == receiver)
                .order_by(NIP17Envelope.received_at.desc(), NIP17Envelope.id.desc())
                .limit(limit)
                .all()
            )

            items = [
                {
                    "event_id": row.event_id,
                    "envelope_hash": row.envelope_hash,
                    "receiver_pubkey_tail": row.receiver_pubkey[-8:],
                    "wrapper_pubkey_tail": row.wrapper_pubkey[-8:],
                    "kind": row.kind,
                    "source": row.source,
                    "status": row.status,
                    "received_at": row.received_at.isoformat() if row.received_at else None,
                }
                for row in rows
            ]

    return {
        "ok": True,
        "receiver_pubkey_tail": receiver[-8:],
        "total": int(total),
        "count": len(items),
        "items": items,
    }


def verify_receiver_inbox(receiver_pubkey: str, *, limit: int = 10, quiet: bool = True) -> dict[str, object]:
    receiver = str(receiver_pubkey or "").strip().lower()
    if not _is_hex(receiver, 64):
        raise ValueError("receiver_pubkey must be 64 hex chars")
    if limit < 1 or limit > 100:
        raise ValueError("limit must be between 1 and 100")

    if not quiet:
        return _query_receiver_inbox(receiver, limit=limit)

    captured_stdout = io.StringIO()
    with contextlib.redirect_stdout(captured_stdout):
        return _query_receiver_inbox(receiver, limit=limit)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receiver-pubkey", required=True, help="64-hex receiver Nostr pubkey")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument(
        "--runtime-pid",
        default=os.getenv("MAINPID"),
        help="Service MainPID to load runtime env without printing secrets.",
    )
    parser.add_argument("--allow-memory-db", action="store_true", help="Allow sqlite memory DB for tests only.")
    args = parser.parse_args()

    if args.runtime_pid:
        _load_runtime_env_from_pid(str(args.runtime_pid))

    from app.database import get_database_url

    db_target = _safe_database_target(get_database_url())
    if db_target["is_memory"] and not args.allow_memory_db:
        raise SystemExit(
            "Refusing to verify NIP-17 inbox against sqlite memory DB. "
            "Pass --runtime-pid for a real service DB or --allow-memory-db for tests only."
        )

    result = verify_receiver_inbox(args.receiver_pubkey, limit=args.limit)
    result["database"] = _redact_runtime_path(db_target)

    rendered = json.dumps(result, indent=2, sort_keys=True)
    forbidden = [
        "envelope_json",
        '"content"',
        '"sig"',
        "opaque-test-envelope-",
        "ciphertext",
        "plaintext message",
        "private key",
        "macaroon",
        "DATABASE_URL",
        "REDIS_URL",
    ]
    hits = [marker for marker in forbidden if marker in rendered]
    if hits:
        raise SystemExit(f"Refusing to print forbidden markers: {hits}")

    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
