"""Auth/session gate helpers extracted from app.app.

Behavior must remain identical to the prior inline gate logic.
"""

from __future__ import annotations


ALLOWLIST_NO_SESSION_PATHS = {
    "/api/whoami",
    "/api/debug/session",
    "/api/challenge",
    "/api/verify",
    "/api/pof/verify_psbt",
}

PUBLIC_PATHS = {
    "/",
    "/oidc",
    "/docs",
    "/docs/",
    "/docs.json",
    "/oicd",
    "/pof/",
    "/pof/leaderboard",
    "/explorer",
    "/verify_pubkey_and_list",
    "/.well-known/openid-configuration",
    "/.well-known/agent.json",
    "/oauth/jwks.json",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth/register",
    "/oauth/introspect",
    "/oauthx/status",
    "/oauthx/docs",
    "/login",
    "/logout",
    "/metrics",
    "/metrics/prometheus",
    "/pof/verify",
    "/pof/verify/",
    "/api/challenge",
    "/api/verify",
}

AGENT_PUBLIC_PATHS = {
    "/agent/capabilities",
    "/agent/capabilities/schema",
    "/agent/skills",
    "/agent/request",
    "/agent/attestations",
    "/agent/reputation",
    "/agent/chain/health",
    "/agent/marketplace/listing",
    "/agent/trust/hodlxxi-herald-01",
    "/agent/binding/hodlxxi-herald-01",
    "/agent/trust-summary/hodlxxi-herald-01.json",
    "/agent/covenants/hodlxxi-herald-covenant-v1.json",
}

PUBLIC_ENDPOINTS = {
    "login",
    "logout",
    "verify_signature",
    "guest_login",
    "static",
    "convert_wif",
    "decode_raw_script",
    "turn_credentials",
    "api_challenge",
    "api_verify",
    "api_demo_free_v2",
    "userinfo",
    "set_labels_from_zpub",
    "universal_login",
    "lnurl_create",
    "lnurl_params",
    "lnurl_callback",
    "lnurl_check",
    "oauth_register",
    "oauth_authorize",
    "oauth_token",
    "oauthx_status",
    "oauthx_docs",
    "docs_json_alias",
    "api_docs",
    "landing_page",
    "root_redirect",
    "oidc_alias",
    "explorer_page",
    "verify_pubkey_and_list",
    "api_public_status",
}


def is_always_exempt_path(path: str) -> bool:
    return path.startswith("/api/internal/agent/invoice")


def is_allowlist_no_session_path(path: str) -> bool:
    return path in ALLOWLIST_NO_SESSION_PATHS


def is_public_browser_path(path: str) -> bool:
    return path in PUBLIC_PATHS or path.startswith("/docs/")


def is_public_agent_path(path: str, method: str) -> bool:
    if method in {"GET", "HEAD"}:
        return (
            path in AGENT_PUBLIC_PATHS
            or path.startswith("/agent/verify/")
            or path.startswith("/agent/jobs/")
            or path.startswith("/reports/")
            or path.startswith("/verify/report/")
            or path.startswith("/verify/nostr/")
            or path.startswith("/agent/trust/")
            or path.startswith("/agent/binding/")
            or path.startswith("/agent/trust-summary/")
            or path.startswith("/agent/covenants/")
        )
    return method == "POST" and path in {"/agent/request", "/agent/message"}


def should_skip_session_gate(path: str, method: str, auth_header: str) -> bool:
    if path.startswith("/api/billing/agent/"):
        return True
    if auth_header.startswith("Bearer ") and path.startswith("/api/"):
        return True
    if method == "OPTIONS" or path in (
        "/favicon.ico",
        "/robots.txt",
        "/health",
        "/metrics",
        "/metrics/prometheus",
    ):
        return True
    return (
        path.startswith("/oauth/")
        or path.startswith("/oauthx/")
        or path.startswith("/oauthdemo/")
        or path.startswith("/socket.io/")
        or path.startswith("/static/")
        or path == "/dashboard"
        or path == "/playground"
        or path.startswith("/p/")
        or path.startswith("/api/playground")
        or path in ("/api/pof/stats", "/api/pof/stats/")
        or path.startswith("/play")
    )


def is_public_endpoint(endpoint_base: str) -> bool:
    return endpoint_base in PUBLIC_ENDPOINTS


def should_allow_bearer_api_without_session(path: str, auth_header: str) -> bool:
    return auth_header.startswith("Bearer ") and path.startswith("/api/")


def should_return_401_for_unauthenticated(path: str, auth_header: str) -> bool:
    return (
        (
            path.startswith("/api/")
            and not path.startswith("/api/playground")
            and not path.startswith("/api/public/")
            and not (path == "/api/demo/protected" and auth_header.startswith("Bearer "))
        )
        or path.endswith("/set_labels_from_zpub")
    )
