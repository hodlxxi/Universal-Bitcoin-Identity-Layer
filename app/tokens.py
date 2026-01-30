"""Helpers for issuing signed JWTs."""

from __future__ import annotations

import time
from pathlib import Path
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
    if True:
        # Always prefer RS256 for OIDC id_token when JWKS_DIR is available
        import os

        jwks_dir = str(cfg.get("JWKS_DIR") or "keys")
        jwks_doc, kid = ensure_rsa_keypair(jwks_dir)

        # Load private key PEM from jwks_dir/private_key_<kid>.pem (or legacy private_key.pem)
        priv_path = (
            os.path.join(jwks_dir, f"private_key_{kid}.pem") if kid else os.path.join(jwks_dir, "private_key.pem")
        )
        if not os.path.exists(priv_path):
            legacy = os.path.join(jwks_dir, "private_key.pem")
            priv_path = legacy

        private_pem = Path(priv_path).read_bytes()
        headers = {"kid": kid} if kid else None
        return jwt.encode(payload, private_pem, algorithm="RS256", headers=headers)

    secret = cfg.get("JWT_SECRET", "dev-secret-CHANGE-ME-IN-PRODUCTION")
    signing_key = secret if isinstance(secret, (bytes, bytearray)) else str(secret)
    return jwt.encode(payload, signing_key, algorithm="HS256")


__all__ = ["issue_rs256_jwt"]
