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
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "urn:workos:agent-auth:grant-type:claim",
        ],
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
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "urn:workos:agent-auth:grant-type:claim",
        ],
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
            "skill": f"{base}/auth.md",
            "register_uri": f"{base}/oauthx/docs",
            "identity_endpoint": f"{base}/agent/identity",
            "claim_endpoint": f"{base}/agent/identity/claim",
            "claim_uri": f"{base}/agent/identity/claim",
            "events_endpoint": f"{base}/agent/event/notify",
            "metadata_uri": f"{base}/auth.md",
            "protected_resource_metadata": f"{base}/.well-known/oauth-protected-resource",
            "identity_types_supported": [
                "anonymous",
                "identity_assertion",
                "public_key",
                "operator_key",
                "oauth_client",
            ],
            "credential_types_supported": [
                "access_token",
                "client_secret_basic",
                "client_secret_post",
                "pkce_authorization_code",
            ],
            "anonymous": {
                "claim_uri": f"{base}/agent/identity/claim",
                "credential_types_supported": [
                    "access_token",
                    "client_secret_basic",
                    "client_secret_post",
                    "pkce_authorization_code",
                ],
            },
            "identity_assertion": {
                "claim_uri": f"{base}/agent/identity/claim",
                "assertion_types_supported": [
                    "urn:ietf:params:oauth:token-type:id-jag",
                    "verified_email",
                    "public_key",
                    "operator_key",
                    "oauth_client",
                ],
                "credential_types_supported": [
                    "access_token",
                    "client_secret_basic",
                    "client_secret_post",
                    "pkce_authorization_code",
                ],
            },
            "events_supported": ["https://schemas.workos.com/events/agent/auth/identity/assertion/revoked"],
        },
    }
    return jsonify(response)


@oidc_bp.post("/agent/identity")
def agent_identity_registration():
    response = {
        "error": "not_implemented",
        "error_description": (
            "Auth.md agent identity registration is advertised for discovery "
            "but disabled until the operator enables agent registration."
        ),
        "enabled": False,
    }
    return jsonify(response), 501


@oidc_bp.post("/agent/identity/claim")
def agent_identity_claim():
    response = {
        "error": "not_implemented",
        "error_description": (
            "Auth.md agent identity claim flow is advertised for discovery "
            "but disabled until the operator enables agent registration."
        ),
        "enabled": False,
    }
    return jsonify(response), 501


@oidc_bp.post("/agent/event/notify")
def agent_event_notify():
    response = {
        "error": "not_implemented",
        "error_description": (
            "Auth.md agent event notifications are advertised for discovery "
            "but disabled until the operator enables agent registration."
        ),
        "enabled": False,
    }
    return jsonify(response), 501


def _public_base_url() -> str:
    cfg = _app_config()
    return str(cfg.get("JWT_ISSUER") or request.url_root.rstrip("/")).rstrip("/")


def _agent_skill_docs(base: str) -> dict[str, str]:
    return {
        "mcp-server-card": (
            "# HODLXXI MCP Server Card\n\n"
            "HODLXXI publishes a discovery-only MCP Server Card for agent readiness.\n\n"
            "Discovery:\n"
            f"- `{base}/.well-known/mcp/server-card.json`\n"
            f"- `{base}/.well-known/mcp.json`\n"
            f"- `{base}/.well-known/mcp/server-cards.json`\n\n"
            "Transport endpoint:\n"
            f"- `{base}/agent/mcp`\n\n"
            "Safety:\n"
            "- The MCP transport endpoint is a disabled-by-default stub.\n"
            "- No tool execution is enabled.\n"
            "- No NIP-17/NIP-59 send, intake, or relay publishing is enabled.\n"
        ),
        "agent-skills": (
            "# HODLXXI Agent Skills Discovery\n\n"
            "HODLXXI publishes an Agent Skills index for machine-readable discovery.\n\n"
            "Index:\n"
            f"- `{base}/.well-known/agent-skills/index.json`\n\n"
            "This index advertises public discovery, Auth.md registration metadata, and MCP server-card discovery.\n"
        ),
        "auth-md-agent-registration": (
            "# HODLXXI Auth.md Agent Registration\n\n"
            "HODLXXI exposes Auth.md-compatible agent registration metadata.\n\n"
            "Discovery:\n"
            f"- `{base}/auth.md`\n"
            f"- `{base}/.well-known/oauth-authorization-server`\n"
            f"- `{base}/.well-known/oauth-protected-resource`\n\n"
            "Safety:\n"
            "- Agent registration endpoints are advertised for discovery.\n"
            "- Registration remains disabled until explicitly enabled by the operator.\n"
        ),
        "agent-discovery": (
            "# HODLXXI Agent Discovery\n\n"
            "HODLXXI exposes public agent discovery surfaces.\n\n"
            "Discovery:\n"
            f"- `{base}/.well-known/agent.json`\n"
            f"- `{base}/agent/capabilities`\n"
            f"- `{base}/agent/capabilities/schema`\n"
            f"- `{base}/agent/skills`\n"
            f"- `{base}/agent/reputation`\n"
            f"- `{base}/agent/attestations`\n"
            f"- `{base}/agent/chain/health`\n"
        ),
    }


@oidc_bp.get("/.well-known/mcp/server-card.json")
@oidc_bp.get("/.well-known/mcp/server-cards.json")
@oidc_bp.get("/.well-known/mcp.json")
def mcp_server_card_metadata():
    base = _public_base_url()
    response = {
        "$schema": "https://modelcontextprotocol.io/schemas/server-card.v1.json",
        "serverInfo": {"name": "HODLXXI", "version": "2.2"},
        "name": "HODLXXI",
        "version": "2.2",
        "description": (
            "Bitcoin-native identity and agent runtime discovery surface. "
            "MCP transport is advertised for discovery only and remains disabled."
        ),
        "protocolVersion": "2025-06-18",
        "endpoint": f"{base}/agent/mcp",
        "transport": {
            "type": "streamable_http",
            "url": f"{base}/agent/mcp",
            "endpoint": f"{base}/agent/mcp",
        },
        "transports": [
            {
                "type": "streamable_http",
                "url": f"{base}/agent/mcp",
                "endpoint": f"{base}/agent/mcp",
            }
        ],
        "capabilities": {
            "tools": {"listChanged": False},
            "resources": {},
            "prompts": {},
        },
        "authentication": {
            "type": "oauth2",
            "authorization_server": f"{base}/.well-known/oauth-authorization-server",
            "protected_resource": f"{base}/.well-known/oauth-protected-resource",
        },
        "documentation": f"{base}/docs",
        "status": f"{base}/api/public/status",
    }
    return jsonify(response)


@oidc_bp.post("/agent/mcp")
def agent_mcp_transport_stub():
    response = {
        "error": "not_implemented",
        "error_description": (
            "MCP transport is advertised for discovery but disabled until " "the operator enables MCP tool execution."
        ),
        "enabled": False,
    }
    return jsonify(response), 501


@oidc_bp.get("/.well-known/agent-skills/index.json")
def agent_skills_discovery_index():
    import hashlib

    base = _public_base_url()
    docs = _agent_skill_docs(base)
    skills = []

    for slug, body in docs.items():
        lines = body.splitlines()
        description = lines[2] if len(lines) > 2 else slug
        skills.append(
            {
                "name": slug,
                "type": "documentation",
                "description": description,
                "url": f"{base}/.well-known/agent-skills/{slug}/SKILL.md",
                "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
            }
        )

    response = {
        "$schema": "https://agentskills.io/schemas/agent-skills-v0.2.0.json",
        "version": "0.2.0",
        "issuer": base,
        "skills": skills,
    }
    return jsonify(response)


@oidc_bp.get("/.well-known/agent-skills/<skill_slug>/SKILL.md")
def agent_skill_document(skill_slug: str):
    from flask import Response

    base = _public_base_url()
    docs = _agent_skill_docs(base)

    if skill_slug not in docs:
        return jsonify({"error": "not_found"}), 404

    return Response(docs[skill_slug], mimetype="text/markdown")


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
    body = f"""# Auth.md

## HODLXXI Agent Authentication

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

## agent_auth metadata

The OAuth Authorization Server Metadata at `/.well-known/oauth-authorization-server` includes an `agent_auth` block with:

- `skill`
- `register_uri`
- `identity_endpoint`
- `claim_endpoint`
- `events_endpoint`
- `identity_types_supported`
- `credential_types_supported`
- `identity_assertion`
- `identity_assertion.credential_types_supported`
- `events_supported`

## Standalone agent registration flow

1. Discover protected resource metadata at `/.well-known/oauth-protected-resource`.
2. Discover authorization server metadata at `/.well-known/oauth-authorization-server`.
3. Read the `agent_auth` block.
4. Register or review agent registration instructions at `/oauthx/docs`.
5. Use `identity_endpoint` for agent identity registration instructions.
6. Use `claim_endpoint` for agent identity claim instructions.
7. Exchange a service-issued identity assertion at `/oauth/token` using `urn:ietf:params:oauth:grant-type:jwt-bearer`.
8. Exchange a claim token at `/oauth/token` using `urn:workos:agent-auth:grant-type:claim`.
9. Use `events_endpoint` for revocation and identity assertion event instructions.

## Required agent_auth fields

- `register_uri`: `/oauthx/docs`
- `identity_endpoint`: `/agent/identity`
- `claim_endpoint`: `/agent/identity/claim`
- `events_endpoint`: `/agent/event/notify`
- `identity_types_supported`: `anonymous`, `identity_assertion`, `public_key`, `operator_key`, `oauth_client`
- `credential_types_supported`: `access_token`, `client_secret_basic`, `client_secret_post`, `pkce_authorization_code`
- `claim_uri`: `/agent/identity/claim`
- `anonymous.claim_uri`: `/agent/identity/claim`
- `anonymous.credential_types_supported`: `access_token`, `client_secret_basic`, `client_secret_post`, `pkce_authorization_code`
- `identity_assertion.claim_uri`: `/agent/identity/claim`
- `identity_assertion.credential_types_supported`: `access_token`, `client_secret_basic`, `client_secret_post`, `pkce_authorization_code`

## Disabled-by-default safety

The Auth.md registration endpoints are published for machine discovery, but currently return `501 not_implemented` until the operator explicitly enables agent registration.

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
