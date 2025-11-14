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
    """Validate a PKCE code verifier against the stored challenge."""
    if not code_challenge or not code_verifier:
        return False

    method_normalised = (method or "S256").strip().upper()
    if method_normalised == "PLAIN":
        return code_verifier == code_challenge

    if method_normalised != "S256":
        return False

    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    calculated = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return calculated == code_challenge


__all__ = ["oidc_bp", "validate_pkce"]
