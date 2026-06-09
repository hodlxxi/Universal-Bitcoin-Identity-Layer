"""OIDC discovery endpoints and helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Mapping, Optional

from flask import Blueprint, Response, current_app, jsonify, request

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
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "subject_types_supported": ["public"],
    }
    return jsonify(response)


@oidc_bp.get("/.well-known/oauth-authorization-server")
def oauth_authorization_server_metadata():
    cfg = _app_config()
    issuer = str(cfg.get("JWT_ISSUER") or request.url_root.rstrip("/")).rstrip("/")
    base = issuer
    response = {
        "issuer": issuer,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "jwks_uri": f"{base}/oauth/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
        ],
        "scopes_supported": [
            "read",
            "write",
            "covenant_read",
            "covenant_create",
            "read_limited",
        ],
        "code_challenge_methods_supported": ["S256"],
        "agent_auth": {
            "register_uri": f"{base}/oauthx/docs",
            "supported_identity_types": [
                "public_key",
                "operator_key",
                "oauth_client",
            ],
            "supported_credential_types": [
                "client_secret_basic",
                "client_secret_post",
                "pkce_authorization_code",
            ],
            "metadata_uri": f"{base}/auth.md",
            "protected_resource_metadata": f"{base}/.well-known/oauth-protected-resource",
        },
    }
    return jsonify(response)


@oidc_bp.get("/.well-known/oauth-protected-resource")
def oauth_protected_resource_metadata():
    cfg = _app_config()
    issuer = str(cfg.get("JWT_ISSUER") or request.url_root.rstrip("/")).rstrip("/")
    base = issuer
    response = {
        "resource": base,
        "authorization_servers": [base],
        "jwks_uri": f"{base}/oauth/jwks.json",
        "scopes_supported": [
            "read",
            "write",
            "covenant_read",
            "covenant_create",
            "read_limited",
        ],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{base}/docs",
        "service_documentation": f"{base}/oauthx/docs",
    }
    return jsonify(response)


@oidc_bp.get("/auth.md")
def auth_md():
    cfg = _app_config()
    issuer = str(cfg.get("JWT_ISSUER") or request.url_root.rstrip("/")).rstrip("/")
    body = f"""# HODLXXI Agent Authentication

HODLXXI exposes Bitcoin-native identity and agent runtime surfaces for public discovery.

## Issuer

`{issuer}`

## Discovery

- OpenID Connect metadata: `/.well-known/openid-configuration`
- OAuth authorization server metadata: `/.well-known/oauth-authorization-server`
- OAuth protected resource metadata: `/.well-known/oauth-protected-resource`
- JWKS: `/oauth/jwks.json`
- OAuth developer docs: `/oauthx/docs`
- Public agent descriptor: `/.well-known/agent.json`
- API catalog: `/.well-known/api-catalog`

## OAuth endpoints

- Authorization endpoint: `/oauth/authorize`
- Token endpoint: `/oauth/token`

## Supported scopes

- `read`
- `write`
- `covenant_read`
- `covenant_create`
- `read_limited`

## Supported client authentication

- `client_secret_basic`
- `client_secret_post`
- PKCE authorization code flow with `S256`

## Agent registration

Operator-approved agent registration is documented through `/oauthx/docs`.
Automated agents should discover the protected resource metadata first, then use the authorization server metadata to determine supported scopes and token endpoints.

## Messaging safety

NIP-17 / NIP-59 messaging remains staged. Sending, intake, and relay publishing are disabled unless explicitly enabled by the operator.
"""
    return Response(body, mimetype="text/markdown")


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
    """
    if not code_challenge:
        return False
    if not code_verifier:
        return False

    import base64
    import hashlib

    m = (method or "S256").strip().upper()

    def _check(challenge: str, verifier: str) -> bool:
        expected = str(challenge).rstrip("=")
        ver = str(verifier)
        if m == "PLAIN":
            return hmac.compare_digest(ver, expected)
        if m != "S256":
            return False
        digest = hashlib.sha256(ver.encode("utf-8")).digest()
        computed = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return hmac.compare_digest(computed, expected)

    return _check(code_challenge, code_verifier)


__all__ = ["oidc_bp", "validate_pkce"]
