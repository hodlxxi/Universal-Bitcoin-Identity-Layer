"""Helpers for issuing signed JWTs."""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

import jwt
from cryptography.hazmat.primitives import serialization

from .config import get_config
from .jwks import get_signing_key


def _resolve_ttl(cfg: Dict[str, Any]) -> int:
    if cfg.get("TOKEN_TTL") is not None:
        try:
            return int(cfg["TOKEN_TTL"])
        except (TypeError, ValueError):
            pass
    hours = cfg.get("JWT_EXPIRATION_HOURS", 1)
    try:
        return int(hours) * 3600
    except (TypeError, ValueError):
        return 3600


def issue_rs256_jwt(
    sub: str,
    claims: Optional[Dict[str, Any]] = None,
    cfg: Optional[Dict[str, Any]] = None,
) -> str:
    """Issue an RS256 JWT using the existing active signing key."""
    if cfg is None:
        cfg = get_config()
    ttl = _resolve_ttl(cfg)
    now = int(time.time())

    payload: Dict[str, Any] = {
        "iss": cfg.get("JWT_ISSUER") or "https://example.com",
        "aud": cfg.get("JWT_AUDIENCE") or cfg.get("OAUTH_AUDIENCE") or "hodlxxi",
        "sub": sub,
        "iat": now,
        "exp": now + ttl,
    }
    if claims:
        payload.update(claims)

    jwks_dir = str(cfg.get("JWKS_DIR") or "keys")
    kid, private_key = get_signing_key(jwks_dir)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(
        payload,
        private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )


__all__ = ["issue_rs256_jwt"]
