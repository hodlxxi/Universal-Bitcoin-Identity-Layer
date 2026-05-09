#!/usr/bin/env python3
"""Safe HODLXXI SDK auth challenge example.

The SDK never handles private keys. This script only demonstrates the flow:
create challenge -> sign externally -> verify.
"""

from __future__ import annotations

import argparse
import os
import sys

from hodlxxi_sdk import HODLXXIClient


def external_signer(message: str) -> str:
    """Replace with a wallet-backed signer.

    Do not paste private keys into this script.
    """
    raise RuntimeError(
        "No signer configured. Replace external_signer() with a wallet-backed "
        "Bitcoin message signer that signs the challenge string."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="HODLXXI SDK auth challenge example")
    parser.add_argument("--base-url", default=os.getenv("HODLXXI_BASE_URL", "https://hodlxxi.com"))
    parser.add_argument("--pubkey", required=True, help="Compressed 33-byte hex pubkey, e.g. 02...")
    parser.add_argument("--dry-run", action="store_true", help="Create challenge but do not sign or verify")
    args = parser.parse_args()

    try:
        client = HODLXXIClient(args.base_url)
        challenge = client.create_challenge(pubkey=args.pubkey)

        print("challenge_id:", challenge["challenge_id"])
        print("challenge:", challenge["challenge"])
        print("expires_in:", challenge.get("expires_in"))

        if args.dry_run:
            print()
            print("dry_run: not signing or verifying")
            print("next step: signature = external_signer(challenge)")
            return 0

        signature = external_signer(challenge["challenge"])
        result = client.verify_challenge(
            challenge_id=challenge["challenge_id"],
            pubkey=args.pubkey,
            signature=signature,
        )
        print("verified:", result)
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
