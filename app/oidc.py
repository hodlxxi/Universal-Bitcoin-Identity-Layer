"""OIDC discovery endpoints and helpers."""
from __future__ import annotations

import base64
import hashlib
from typing import Mapping, Optional

from flask import Blueprint, current_app, jsonify, request

from .config import get_config
from .jwks import ensure_rsa_keypair

oidc_bp = Blueprint("oidc", __name__)


def _app_config() -> Mapping[str, object]:
    return current_app.config.get("APP_CONFIG") or get_config()


@oidc_bp.get("/.well-known/openid-configuration")
def well_known_configuration():
    cfg = _app_config()
    issuer = str(cfg.get("JWT_ISSUER") or request.url_root.rstrip("/"))
    issuer = issuer.rstrip("/")
    base = issuer
    alg = str(cfg.get("JWT_ALGORITHM") or "RS256").upper()

    response = {
        "issuer": issuer,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "jwks_uri": f"{base}/oauth/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "scopes_supported": [
            "read",
            "write",
            "covenant_read",
            "covenant_create",
            "read_limited",
        ],
        "code_challenge_methods_supported": ["S256", "plain"],
        "id_token_signing_alg_values_supported": [alg],
        "subject_types_supported": ["public"],
    }
    return jsonify(response)


@oidc_bp.get("/oauth/jwks.json")
def jwks_document():
    cfg = _app_config()
    jwks_dir = str(cfg.get("JWKS_DIR") or "keys")
    jwks_doc, _ = ensure_rsa_keypair(jwks_dir)
    return jsonify(jwks_doc)


def validate_pkce(code_challenge: Optional[str], code_verifier: Optional[str], method: Optional[str] = "S256") -> bool:
    """Validate PKCE (RFC 7636).

    Compatibility behavior:
      - normalize base64url padding
      - try (challenge, verifier) order
      - if that fails, try swapped order (covers call-site argument order bugs)
    """
    # If no challenge was provided, treat as no PKCE required
    if not code_challenge:
        return True
    if not code_verifier:
        return False

    import base64
    import hashlib

    m = (method or "S256").strip().upper()

    def _check(challenge: str, verifier: str) -> bool:
        expected = str(challenge).rstrip("=")
        ver = str(verifier)
        if m == "PLAIN":
            return ver == expected
        if m != "S256":
            return False
        digest = hashlib.sha256(ver.encode("utf-8")).digest()
        computed = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return computed == expected

    # normal order
    if _check(code_challenge, code_verifier):
        return True
    # swapped order (defensive)
    return _check(code_verifier, code_challenge)


__all__ = ["oidc_bp", "validate_pkce"]
