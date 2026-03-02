"""Signing helpers for Agent UBID receipts and capabilities."""

import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_privkey_hex() -> str:
    key_hex = os.getenv("AGENT_PRIVKEY_HEX", "").strip()
    if key_hex:
        return key_hex

    key_path = os.getenv("AGENT_PRIVKEY_PATH", "").strip()
    if not key_path:
        raise RuntimeError("Missing AGENT_PRIVKEY_HEX or AGENT_PRIVKEY_PATH")

    path = Path(key_path)
    if not path.exists():
        raise RuntimeError("AGENT_PRIVKEY_PATH does not exist")

    return path.read_text(encoding="utf-8").strip()


def _private_key() -> ec.EllipticCurvePrivateKey:
    key_hex = _load_privkey_hex()
    private_value = int(key_hex, 16)
    return ec.derive_private_key(private_value, ec.SECP256K1())


def get_agent_pubkey_hex() -> str:
    pubkey = _private_key().public_key()
    compressed = pubkey.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )
    return compressed.hex()


def sign_message(message: bytes) -> str:
    signature = _private_key().sign(message, ec.ECDSA(hashes.SHA256()))
    return signature.hex()


def verify_message(message: bytes, signature_hex: str, pubkey_hex: str) -> bool:
    try:
        pubkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), bytes.fromhex(pubkey_hex))
        pubkey.verify(bytes.fromhex(signature_hex), message, ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, InvalidSignature):
        return False
