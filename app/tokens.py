"""Helpers for issuing signed JWTs."""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

import jwt

from .config import get_config
from .jwks import ensure_rsa_keypair


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


def issue_rs256_jwt(sub: str, claims: Optional[Dict[str, Any]] = None) -> str:
    """Issue a JWT using RS256 when configured, falling back to HS256."""
    cfg = get_config()
    alg = str(cfg.get("JWT_ALGORITHM") or "RS256").upper()
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

    if alg == "RS256":
        private_pem, jwks_doc = ensure_rsa_keypair(str(cfg.get("JWKS_DIR") or "keys"))
        kid = None
        keys = jwks_doc.get("keys") if isinstance(jwks_doc, dict) else None
        if keys and isinstance(keys, list) and keys and isinstance(keys[0], dict):
            kid = keys[0].get("kid")
        headers = {"kid": kid} if kid else None
        return jwt.encode(payload, private_pem, algorithm="RS256", headers=headers)

    secret = cfg.get("JWT_SECRET", "dev-secret-CHANGE-ME-IN-PRODUCTION")
    signing_key = secret if isinstance(secret, (bytes, bytearray)) else str(secret)
    return jwt.encode(payload, signing_key, algorithm="HS256")


__all__ = ["issue_rs256_jwt"]
