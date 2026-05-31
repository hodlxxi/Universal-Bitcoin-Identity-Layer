#!/usr/bin/env python
"""Send a staging-only opaque NIP-17/NIP-59 test envelope.

This tool generates a valid relay-visible kind-1059 gift-wrap shaped event and
POSTs it to /api/messages/nip17/envelopes.

Safety:
- staging localhost only by default
- no plaintext message support
- no key custody
- no signing with real user keys
- no relay publishing
- no secrets printed
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DEFAULT_BASE = "http://127.0.0.1:5055"
DEFAULT_PATH = "/api/messages/nip17/envelopes"


def _hex(length_bytes: int) -> str:
    return secrets.token_hex(length_bytes)


def _is_hex(value: str, length: int) -> bool:
    value = str(value or "").strip()
    return len(value) == length and all(ch in "0123456789abcdefABCDEF" for ch in value)


def _normalize_base_url(base_url: str) -> str:
    parsed = urlparse(str(base_url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("base URL must be http(s) with host")

    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", "")).rstrip("/")


def _is_default_staging_base(base_url: str) -> bool:
    parsed = urlparse(_normalize_base_url(base_url))
    return parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"} and parsed.port == 5055


def build_test_gift_wrap(receiver_pubkey: str, *, created_at: int | None = None) -> dict:
    receiver = str(receiver_pubkey or "").strip().lower()
    if not _is_hex(receiver, 64):
        raise ValueError("receiver_pubkey must be 64 hex chars")

    return {
        "id": _hex(32),
        "pubkey": _hex(32),
        "created_at": int(created_at or time.time()),
        "kind": 1059,
        "tags": [["p", receiver]],
        "content": f"opaque-test-envelope-{_hex(16)}",
        "sig": _hex(64),
    }


def post_envelope(base_url: str, envelope: dict, *, timeout: float = 10.0) -> tuple[int, dict]:
    base = _normalize_base_url(base_url)
    url = f"{base}{DEFAULT_PATH}"
    body = json.dumps({"envelope": envelope}, separators=(",", ":")).encode("utf-8")

    request = Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Forwarded-Proto": "https",
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return int(response.status), json.loads(raw or "{}")
    except Exception as exc:
        # urllib raises for HTTP 4xx/5xx, but still carries response data.
        response = getattr(exc, "fp", None)
        code = int(getattr(exc, "code", 0) or 0)
        if response is not None:
            raw = response.read().decode("utf-8")
            try:
                payload = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload = {"error": "non_json_response", "body": raw[:200]}
            return code, payload
        raise


def safe_result(status_code: int, payload: dict, envelope: dict) -> dict:
    return {
        "ok": 200 <= status_code < 300,
        "status_code": status_code,
        "event_id": envelope.get("id"),
        "receiver_pubkey": envelope.get("tags", [["", ""]])[0][1],
        "receiver_pubkey_tail": str(envelope.get("tags", [["", ""]])[0][1])[-8:],
        "server_response": payload,
        "published": False,
        "plaintext_sent": False,
        "relay_publishing": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receiver-pubkey", required=True, help="64-hex receiver Nostr pubkey")
    parser.add_argument("--base", default=DEFAULT_BASE, help="Base URL. Defaults to staging localhost.")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--allow-non-staging-base",
        action="store_true",
        help="Allow non-default base URL. Do not use for production unless deliberately testing a rollout.",
    )
    args = parser.parse_args()

    if not args.allow_non_staging_base and not _is_default_staging_base(args.base):
        raise SystemExit(
            "Refusing non-staging base URL. Default allowed base is http://127.0.0.1:5055. "
            "Pass --allow-non-staging-base only for deliberate operator testing."
        )

    envelope = build_test_gift_wrap(args.receiver_pubkey)
    status_code, payload = post_envelope(args.base, envelope, timeout=args.timeout)

    result = safe_result(status_code, payload, envelope)

    rendered = json.dumps(result, indent=2, sort_keys=True)
    forbidden = [envelope["content"], envelope["sig"], "envelope_json"]
    if any(marker and marker in rendered for marker in forbidden):
        raise SystemExit("Refusing to print response: forbidden envelope material detected in output")

    print(rendered)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
