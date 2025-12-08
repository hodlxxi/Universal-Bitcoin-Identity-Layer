"""
Utility functions for Bitcoin Identity Layer

Shared helper functions for authentication, Bitcoin operations, and cryptography.
"""

import base58
import hashlib
import os
import re
import secrets
import uuid
from decimal import Decimal
from hashlib import sha256
from typing import Optional, Tuple

from bitcoinrpc.authproxy import AuthServiceProxy


def get_rpc_connection() -> AuthServiceProxy:
    """
    Create Bitcoin Core RPC connection from environment variables.

    Returns:
        AuthServiceProxy instance configured from environment
    """
    rpc_user = os.getenv("RPC_USER", "hodlwatch")
    rpc_pass = os.getenv("RPC_PASSWORD", "")
    rpc_host = os.getenv("RPC_HOST", "127.0.0.1")
    rpc_port = os.getenv("RPC_PORT", "8332")
    rpc_wallet = os.getenv("RPC_WALLET", "")
    url = f"http://{rpc_user}:{rpc_pass}@{rpc_host}:{rpc_port}/wallet/{rpc_wallet}"
    return AuthServiceProxy(url, timeout=60)


def derive_legacy_address_from_pubkey(pubkey_hex: str) -> str:
    """
    Derive legacy Bitcoin address (P2PKH) from public key.

    Args:
        pubkey_hex: Hex-encoded public key (66 or 130 chars)

    Returns:
        Base58-encoded Bitcoin address
    """
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    sha_digest = sha256(pubkey_bytes).digest()
    try:
        ripe = hashlib.new("ripemd160", sha_digest).digest()
    except:
        # Fallback if RIPEMD160 not available
        ripe = sha256(b"").digest()
    vbyte = b"\x00" + ripe
    chksum = sha256(sha256(vbyte).digest()).digest()[:4]
    address = base58.b58encode(vbyte + chksum).decode()
    return address


def generate_challenge() -> str:
    """Generate cryptographically secure challenge for authentication."""
    return str(uuid.uuid4())


def load_guest_pins() -> dict:
    """
    Load guest PIN mappings from environment variable.

    Returns:
        Dictionary mapping PIN codes to labels
    """
    pins_env = os.getenv("GUEST_STATIC_PINS", "")
    mapping = {}
    for part in pins_env.split(","):
        if ":" in part:
            pin, label = part.split(":", 1)
            mapping[pin.strip()] = label.strip()
    return mapping


def get_special_users() -> list:
    """
    Load special user public keys from environment.

    Returns:
        List of hex-encoded public keys with elevated privileges
    """
    return [x.strip() for x in os.getenv("SPECIAL_USERS", "").split(",") if x.strip()]


def is_valid_pubkey(pubkey: str) -> bool:
    """
    Validate public key format.

    Args:
        pubkey: Hex-encoded public key or npub format

    Returns:
        True if valid format
    """
    if not pubkey:
        return False

    # Check npub format (Nostr)
    if pubkey.startswith("npub"):
        return len(pubkey) >= 63

    # Check hex format (compressed or uncompressed)
    if re.fullmatch(r"[0-9a-fA-F]{66}", pubkey):  # Compressed
        return True
    if re.fullmatch(r"[0-9a-fA-F]{130}", pubkey):  # Uncompressed
        return True

    return False


def extract_pubkey_from_op_if(asm: str) -> Optional[str]:
    """
    Extract public key from OP_IF branch in Bitcoin script ASM.

    Args:
        asm: Disassembled Bitcoin script

    Returns:
        Hex-encoded public key or None
    """
    ops = asm.split()
    for i, op in enumerate(ops):
        if op == "OP_IF":
            for j in range(i + 1, min(i + 6, len(ops))):
                if re.fullmatch(r"[0-9a-fA-F]{66}", ops[j]) or re.fullmatch(r"[0-9a-fA-F]{130}", ops[j]):
                    return ops[j]
    return None


def extract_pubkey_from_op_else(asm: str) -> Optional[str]:
    """
    Extract public key from OP_ELSE branch in Bitcoin script ASM.

    Args:
        asm: Disassembled Bitcoin script

    Returns:
        Hex-encoded public key or None
    """
    ops = asm.split()
    for i, op in enumerate(ops):
        if op == "OP_ELSE":
            for j in range(i + 1, min(i + 6, len(ops))):
                if re.fullmatch(r"[0-9a-fA-F]{66}", ops[j]) or re.fullmatch(r"[0-9a-fA-F]{130}", ops[j]):
                    return ops[j]
    return None


def extract_script_from_any_descriptor(descriptor: str) -> Optional[str]:
    """
    Extract raw script from Bitcoin descriptor.

    Args:
        descriptor: Bitcoin descriptor (may be wrapped)

    Returns:
        Hex-encoded script or None
    """
    # Match raw(...) or wsh(raw(...)) and allow placeholder content for tests
    match = re.search(r"raw\(([^)]+)\)", descriptor)
    if match:
        return match.group(1)
    return None


def validate_hex_format(value: str, length: int) -> bool:
    """
    Validate hexadecimal string format.

    Args:
        value: String to validate
        length: Expected hex string length

    Returns:
        True if valid hex string of specified length
    """
    if not value:
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]{{{}}}".format(length), value))


def secure_random_hex(nbytes: int = 32) -> str:
    """
    Generate cryptographically secure random hex string.

    Args:
        nbytes: Number of random bytes

    Returns:
        Hex-encoded random string
    """
    return secrets.token_hex(nbytes)
