"""
JWKS Management with Key Rotation Support

Manages RSA keypairs for JWT signing with automatic key rotation and
graceful key retirement to prevent token validation failures.

Features:
- Multiple concurrent signing keys
- Automatic key rotation based on age
- Graceful retirement of old keys
- Secure key storage
"""
from __future__ import annotations

import base64
import glob
import json
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)


def _b64u(data: bytes) -> str:
    """Return URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _generate_kid() -> str:
    """Return a high-resolution timestamp-based kid.

    Using nanoseconds avoids collisions when rotations happen within the
    same second (e.g., tests that force immediate rotation).
    """

    return str(time.time_ns())


def _public_key_to_jwk(private_key: rsa.RSAPrivateKey, kid: str) -> Dict[str, Any]:
    """Convert a private key to its public JWK representation."""
    public_numbers = private_key.public_key().public_numbers()
    e = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")
    n = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64u(n),
        "e": _b64u(e),
    }


def _load_or_generate_key(priv_path: str) -> Tuple[rsa.RSAPrivateKey, bytes]:
    if os.path.exists(priv_path):
        with open(priv_path, "rb") as fh:
            pem_bytes = fh.read()
        try:
            private_key = serialization.load_pem_private_key(pem_bytes, password=None, backend=default_backend())
            return private_key, pem_bytes
        except ValueError:
            pass

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    os.makedirs(os.path.dirname(priv_path), exist_ok=True)
    with open(priv_path, "wb") as fh:
        fh.write(pem_bytes)
    return private_key, pem_bytes


def _normalize_kid_timestamp(kid: str) -> Optional[float]:
    """Convert a kid to seconds since epoch.

    Supports kid values stored as seconds, milliseconds, microseconds, or
    nanoseconds to preserve backwards compatibility while ensuring new
    high-resolution identifiers remain usable for age calculations.
    """

    try:
        created_at = int(kid)
    except (ValueError, TypeError):
        return None

    # Detect sub-second precision by magnitude
    if created_at > 1e18:  # nanoseconds
        return created_at / 1e9
    if created_at > 1e15:  # microseconds
        return created_at / 1e6
    if created_at > 1e12:  # milliseconds
        return created_at / 1e3
    return float(created_at)


def _get_key_age_days(kid: str) -> float:
    """Calculate key age in days from kid (Unix timestamp)."""
    created_at = _normalize_kid_timestamp(kid)
    if created_at is None:
        return 0

    age_seconds = time.time() - created_at
    return age_seconds / 86400


def _should_rotate_key(kid: str, rotation_days: int = 90) -> bool:
    """Check if key should be rotated based on age."""
    age_days = _get_key_age_days(kid)
    return age_days >= rotation_days


def _list_all_keys(jwks_dir: str) -> List[Tuple[str, str, rsa.RSAPrivateKey]]:
    """
    List all RSA keys in the JWKS directory.

    Returns:
        List of (kid, pem_path, private_key) tuples
    """
    keys = []
    key_pattern = os.path.join(jwks_dir, "private_key_*.pem")

    # Also check for legacy private_key.pem
    legacy_path = os.path.join(jwks_dir, "private_key.pem")
    if os.path.exists(legacy_path):
        try:
            with open(legacy_path, "rb") as fh:
                pem_bytes = fh.read()
            private_key = serialization.load_pem_private_key(pem_bytes, password=None, backend=default_backend())
            # Generate kid for legacy key
            kid = str(int(os.path.getmtime(legacy_path)))
            keys.append((kid, legacy_path, private_key))
        except Exception as e:
            logger.warning(f"Failed to load legacy key: {e}")

    # Load all numbered keys
    for key_path in glob.glob(key_pattern):
        try:
            filename = os.path.basename(key_path)
            kid = filename.replace("private_key_", "").replace(".pem", "")

            with open(key_path, "rb") as fh:
                pem_bytes = fh.read()
            private_key = serialization.load_pem_private_key(pem_bytes, password=None, backend=default_backend())
            keys.append((kid, key_path, private_key))
        except Exception as e:
            logger.warning(f"Failed to load key {key_path}: {e}")

    return keys


def ensure_rsa_keypair(jwks_dir: str, rotation_days: int = 90, max_retired_keys: int = 3) -> Tuple[Dict[str, Any], str]:
    """
    Ensure RSA keypairs exist with automatic rotation support.

    Args:
        jwks_dir: Directory to store keys
        rotation_days: Rotate primary key after this many days (default: 90)
        max_retired_keys: Maximum retired keys to keep for verification (default: 3)

    Returns:
        Tuple of (JWKS document, current kid for signing)

    Key Rotation Strategy:
        1. Check if current primary key needs rotation
        2. If yes, generate new primary key
        3. Keep old keys as retired keys (up to max_retired_keys)
        4. Publish all keys in JWKS document
        5. Only sign new tokens with primary key (newest)
        6. Verify tokens with any published key
    """
    os.makedirs(jwks_dir, exist_ok=True)
    jwks_path = os.path.join(jwks_dir, "jwks.json")

    # Load all existing keys
    all_keys = _list_all_keys(jwks_dir)

    # Sort by kid (timestamp) descending - newest first
    all_keys.sort(key=lambda x: int(x[0]) if x[0].isdigit() else 0, reverse=True)

    # Determine if we need a new primary key
    need_new_key = False
    if not all_keys:
        need_new_key = True
        logger.info("No existing keys found, generating initial key")
    else:
        primary_kid = all_keys[0][0]
        if _should_rotate_key(primary_kid, rotation_days):
            need_new_key = True
            logger.info(f"Primary key {primary_kid} is {_get_key_age_days(primary_kid)} days old, rotating")

    # Generate new primary key if needed
    if need_new_key:
        new_kid = _generate_kid()
        new_priv_path = os.path.join(jwks_dir, f"private_key_{new_kid}.pem")

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with open(new_priv_path, "wb") as fh:
            fh.write(pem_bytes)

        # Set restrictive permissions (owner read/write only)
        os.chmod(new_priv_path, 0o600)

        all_keys.insert(0, (new_kid, new_priv_path, private_key))
        logger.info(f"Generated new primary key: {new_kid}")

    # Limit retired keys
    if len(all_keys) > max_retired_keys + 1:
        retired_keys = all_keys[max_retired_keys + 1 :]
        all_keys = all_keys[: max_retired_keys + 1]

        # Remove old key files
        for kid, key_path, _ in retired_keys:
            try:
                os.remove(key_path)
                logger.info(f"Removed retired key: {kid}")
            except OSError as e:
                logger.warning(f"Failed to remove retired key {kid}: {e}")

    # Build JWKS document with all active keys
    jwks_keys = []
    for kid, _, private_key in all_keys:
        jwk = _public_key_to_jwk(private_key, kid)
        jwks_keys.append(jwk)

    jwks_doc = {"keys": jwks_keys}

    # Save JWKS document
    with open(jwks_path, "w", encoding="utf-8") as fh:
        json.dump(jwks_doc, fh, indent=2)

    # Set restrictive permissions
    os.chmod(jwks_path, 0o644)

    # Return JWKS and primary (newest) kid
    primary_kid = all_keys[0][0]
    logger.info(f"JWKS ready: {len(jwks_keys)} keys, primary kid: {primary_kid}")

    return jwks_doc, primary_kid


def get_signing_key(jwks_dir: str) -> Tuple[str, rsa.RSAPrivateKey]:
    """
    Get the current primary signing key.

    Args:
        jwks_dir: Directory containing keys

    Returns:
        Tuple of (kid, private_key) for signing

    Raises:
        FileNotFoundError: If no keys exist
    """
    all_keys = _list_all_keys(jwks_dir)

    if not all_keys:
        raise FileNotFoundError(f"No signing keys found in {jwks_dir}")

    # Sort by kid (timestamp) descending - newest first
    all_keys.sort(key=lambda x: int(x[0]) if x[0].isdigit() else 0, reverse=True)

    kid, _, private_key = all_keys[0]
    return kid, private_key


def get_key_by_kid(jwks_dir: str, kid: str) -> Optional[rsa.RSAPrivateKey]:
    """
    Get a specific key by kid for verification.

    Args:
        jwks_dir: Directory containing keys
        kid: Key ID

    Returns:
        Private key or None if not found
    """
    all_keys = _list_all_keys(jwks_dir)

    for key_kid, _, private_key in all_keys:
        if key_kid == kid:
            return private_key

    return None


def rotate_keys_manually(jwks_dir: str) -> str:
    """
    Manually trigger key rotation.

    Args:
        jwks_dir: Directory containing keys

    Returns:
        New primary kid
    """
    logger.info("Manual key rotation triggered")
    jwks_doc, new_kid = ensure_rsa_keypair(jwks_dir, rotation_days=0)
    return new_kid
