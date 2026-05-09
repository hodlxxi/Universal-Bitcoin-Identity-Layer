#!/usr/bin/env python3
"""Safe HODLXXI SDK Nostr auth challenge example.

The SDK does not hold Nostr private keys.

This script:
1. creates a HODLXXI challenge with method="nostr"
2. prints an unsigned Nostr event template
3. optionally submits a fully signed event JSON file to /api/verify
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any

from hodlxxi_sdk import HODLXXIClient


def nostr_pubkey_for_event(pubkey: str) -> str:
    """Return x-only 64-char hex pubkey expected inside Nostr event."""
    lowered = pubkey.strip().lower()
    if len(lowered) == 66 and lowered[:2] in {"02", "03"}:
        return lowered[2:]
    return lowered


def unsigned_event_template(*, pubkey: str, challenge: str, verify_url: str) -> dict[str, Any]:
    """Build the event shape an external Nostr signer must sign."""
    return {
        "pubkey": nostr_pubkey_for_event(pubkey),
        "created_at": int(time.time()),
        "kind": 22242,
        "tags": [
            ["challenge", challenge],
            ["u", verify_url],
        ],
        "content": "HODLXXI Nostr auth",
        "id": "<external signer fills event id>",
        "sig": "<external signer fills signature>",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="HODLXXI SDK Nostr auth challenge example")
    parser.add_argument("--base-url", default=os.getenv("HODLXXI_BASE_URL", "https://hodlxxi.com"))
    parser.add_argument("--pubkey", required=True, help="Nostr x-only hex pubkey or compressed 02/03... pubkey")
    parser.add_argument("--signed-event-json", help="Optional path to fully signed Nostr event JSON")
    args = parser.parse_args()

    try:
        client = HODLXXIClient(args.base_url)
        challenge = client.create_challenge(pubkey=args.pubkey, method="nostr")

        challenge_id = challenge["challenge_id"]
        challenge_text = challenge["challenge"]
        verify_url = client._url("/api/verify")

        event_template = unsigned_event_template(
            pubkey=args.pubkey,
            challenge=challenge_text,
            verify_url=verify_url,
        )

        print("challenge_id:", challenge_id)
        print("challenge:", challenge_text)
        print("expires_in:", challenge.get("expires_in"))
        print("verify_url:", verify_url)
        print()
        print("unsigned_nostr_event_template:")
        print(json.dumps(event_template, indent=2, sort_keys=True))

        if not args.signed_event_json:
            print()
            print("dry_run: not verifying")
            print("next step: sign the event externally, then pass --signed-event-json signed-event.json")
            return 0

        with open(args.signed_event_json, "r", encoding="utf-8") as f:
            signed_event = json.load(f)

        result = client.verify_challenge(
            challenge_id=challenge_id,
            nostr_event=signed_event,
        )
        print("verified:", result)
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
