#!/usr/bin/env python3
"""Minimal inter-agent demo harness for /agent/message MVP.

Proves:
Agent A (local key) -> Agent B (/agent/message) -> signed result -> local verification.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from typing import Any

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def derive_pubkey_hex(privkey_hex: str) -> str:
    private_value = int(privkey_hex, 16)
    key = ec.derive_private_key(private_value, ec.SECP256K1())
    pubkey = key.public_key()
    compressed = pubkey.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )
    return compressed.hex()


def sign_bytes(privkey_hex: str, message: bytes) -> str:
    private_value = int(privkey_hex, 16)
    key = ec.derive_private_key(private_value, ec.SECP256K1())
    sig = key.sign(message, ec.ECDSA(hashes.SHA256()))
    return sig.hex()


def verify_bytes(message: bytes, signature_hex: str, pubkey_hex: str) -> bool:
    try:
        pubkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), bytes.fromhex(pubkey_hex))
        pubkey.verify(bytes.fromhex(signature_hex), message, ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, InvalidSignature):
        return False


def sign_envelope(envelope: dict[str, Any], privkey_hex: str) -> str:
    unsigned = dict(envelope)
    unsigned.pop("signature", None)
    return sign_bytes(privkey_hex, canonical_json_bytes(unsigned))


def verify_envelope_signature(envelope: dict[str, Any]) -> bool:
    unsigned = dict(envelope)
    signature = str(unsigned.pop("signature", ""))
    pubkey = str(unsigned.get("from_pubkey", ""))
    if not signature or not pubkey:
        return False
    return verify_bytes(canonical_json_bytes(unsigned), signature, pubkey)


def now_rfc3339() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_request_envelope(agent_a_privkey_hex: str, agent_b_pubkey_hex: str, message_text: str) -> dict[str, Any]:
    from_pubkey = derive_pubkey_hex(agent_a_privkey_hex)
    envelope: dict[str, Any] = {
        "message_id": str(uuid.uuid4()),
        "conversation_id": str(uuid.uuid4()),
        "thread_id": "thread-1",
        "type": "job_proposal",
        "from_pubkey": from_pubkey,
        "to_pubkey": agent_b_pubkey_hex,
        "created_at": now_rfc3339(),
        "payload": {
            "job_type": "ping",
            "payload": {"message": message_text},
        },
    }
    envelope["signature"] = sign_envelope(envelope, agent_a_privkey_hex)
    return envelope


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send a signed Agent A -> Agent B /agent/message demo request.")
    parser.add_argument("--agent-b-url", default="http://127.0.0.1:5000/agent/message", help="Target Agent B /agent/message URL")
    parser.add_argument("--agent-b-pubkey", default=os.getenv("AGENT_B_PUBKEY_HEX", ""), help="Agent B compressed pubkey hex")
    parser.add_argument("--agent-a-privkey", default=os.getenv("AGENT_A_PRIVKEY_HEX", ""), help="Agent A private key hex")
    parser.add_argument("--message", default="hello from agent a", help="Ping payload message")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.agent_a_privkey:
        print("ERROR: missing --agent-a-privkey (or AGENT_A_PRIVKEY_HEX)", file=sys.stderr)
        return 2

    if not args.agent_b_pubkey:
        print("ERROR: missing --agent-b-pubkey (or AGENT_B_PUBKEY_HEX)", file=sys.stderr)
        return 2

    request_envelope = build_request_envelope(args.agent_a_privkey, args.agent_b_pubkey, args.message)

    print("=== Agent A signed request envelope ===")
    print(json.dumps(request_envelope, indent=2))

    resp = requests.post(args.agent_b_url, json=request_envelope, timeout=20)
    print(f"\\n=== Agent B HTTP status: {resp.status_code} ===")
    response_json = resp.json()
    print(json.dumps(response_json, indent=2))

    if resp.status_code != 200:
        print("DEMO FAILED: Agent B did not return success", file=sys.stderr)
        return 1

    if response_json.get("type") != "result":
        print("DEMO FAILED: expected response envelope type=result", file=sys.stderr)
        return 1

    if not verify_envelope_signature(response_json):
        print("DEMO FAILED: Agent B response signature verification failed", file=sys.stderr)
        return 1

    print("\\nOK: Agent B result signature verified by Agent A")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
