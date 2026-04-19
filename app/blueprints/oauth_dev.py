"""OAuth developer-surface blueprint.

This blueprint restores human/developer-facing OAuth helper routes that are
intentionally separate from the core OAuth runtime endpoints.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, render_template_string, request, session

from app.config import get_config
from app.database import session_scope
from app.models import OAuthClient


oauth_dev_bp = Blueprint("oauth_dev", __name__)


@oauth_dev_bp.get("/oauthx/status")
def oauthx_status():
    """Lightweight status payload for developer discovery.

    This is intentionally conservative: it reports configured endpoint paths and
    an availability indicator, but does not claim downstream dependency health.
    """

    cfg = get_config()
    issuer = str(cfg.get("JWT_ISSUER") or request.url_root.rstrip("/")).rstrip("/")

    return jsonify(
        {
            "status": "available",
            "issuer": issuer,
            "endpoints": {
                "discovery": "/.well-known/openid-configuration",
                "register": "/oauth/register",
                "authorize": "/oauth/authorize",
                "token": "/oauth/token",
                "jwks": "/oauth/jwks.json",
                "clients": "/oauth/clients",
            },
        }
    )


@oauth_dev_bp.get("/oauthx/docs")
def oauthx_docs():
    """Minimal human-readable OAuth docs."""

    html = """
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <title>HODLXXI OAuth Developer Docs</title>
        <style>
          body { font-family: system-ui, sans-serif; margin: 2rem; line-height: 1.45; }
          code { background: #f3f4f6; padding: 0.1rem 0.35rem; border-radius: 4px; }
          h1, h2 { margin-bottom: 0.5rem; }
          ul { margin-top: 0.3rem; }
        </style>
      </head>
      <body>
        <h1>OAuth2 / OIDC Developer Docs</h1>
        <p>Use HODLXXI as an OAuth2 authorization server with OIDC discovery metadata.</p>

        <h2>Core flow (Authorization Code)</h2>
        <ol>
          <li><code>POST /oauth/register</code> to register a client and redirect URI(s).</li>
          <li>Send the user to <code>GET /oauth/authorize</code> with <code>response_type=code</code>,
              <code>client_id</code>, <code>redirect_uri</code>, <code>scope</code>, and <code>state</code>.</li>
          <li>Exchange the returned code at <code>POST /oauth/token</code> for access (and refresh) tokens.</li>
        </ol>

        <h2>Discovery metadata</h2>
        <p>Read OIDC metadata at <code>/.well-known/openid-configuration</code>.
           Resolve signing keys at <code>/oauth/jwks.json</code>.</p>

        <h2>Supported core endpoints</h2>
        <ul>
          <li><code>POST /oauth/register</code></li>
          <li><code>GET /oauth/authorize</code></li>
          <li><code>POST /oauth/token</code></li>
          <li><code>GET /.well-known/openid-configuration</code></li>
          <li><code>GET /oauth/jwks.json</code></li>
          <li><code>GET /oauth/clients</code> (developer listing; access controlled)</li>
        </ul>
      </body>
    </html>
    """
    return render_template_string(html)


@oauth_dev_bp.get("/oauth/clients")
def oauth_clients():
    """Developer-facing client listing.

    Access model (conservative):
      - requires a logged-in session
      - requires full access level for listing registered clients
      - never returns client_secret
    """

    pubkey = session.get("logged_in_pubkey")
    if not pubkey:
        return jsonify({"ok": False, "error": "not_logged_in", "clients": []}), 401

    access_level = (session.get("access_level") or "").lower()
    if access_level != "full":
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "forbidden",
                    "message": "oauth client listing requires full access level",
                    "clients": [],
                }
            ),
            403,
        )

    with session_scope() as db_session:
        rows = db_session.query(OAuthClient).order_by(OAuthClient.created_at.desc()).limit(200).all()

    clients = [
        {
            "client_id": row.client_id,
            "client_name": row.client_name,
            "redirect_uris": row.redirect_uris or [],
            "grant_types": row.grant_types or [],
            "response_types": row.response_types or [],
            "scope": row.scope,
            "token_endpoint_auth_method": row.token_endpoint_auth_method,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "is_active": bool(row.is_active),
        }
        for row in rows
    ]

    return jsonify({"ok": True, "count": len(clients), "clients": clients})
