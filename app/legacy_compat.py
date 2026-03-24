"""Factory-safe registration of legacy compatibility routes still used in production."""

from __future__ import annotations

import json
import os
from pathlib import Path

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session, url_for

from app.blueprints.account_api_compat import bp as account_api_compat_bp
from app.blueprints.accounts_page import bp as accounts_page_bp
from app.blueprints.billing_api_compat import bp as billing_api_compat_bp
from app.docs_routes import STATIC_DOCS_DIR, register_docs_routes

legacy_compat_bp = Blueprint("legacy_compat", __name__)


@legacy_compat_bp.route("/oauthx/status")
def oauthx_status():
    issuer = str((current_app.config.get("APP_CONFIG") or {}).get("JWT_ISSUER") or request.url_root.rstrip("/"))
    try:
        from app.database import session_scope
        from app.models import LNURLChallenge, OAuthClient, OAuthCode

        with session_scope() as db_session:
            registered_clients = db_session.query(OAuthClient).count()
            active_codes = db_session.query(OAuthCode).count()
            lnurl_sessions = db_session.query(LNURLChallenge).count()
    except Exception:
        registered_clients = 0
        active_codes = 0
        lnurl_sessions = 0

    return jsonify(
        {
            "ok": True,
            "service": "HODLXXI OAuth2/OIDC",
            "registered_clients": registered_clients,
            "active_codes": active_codes,
            "lnurl_sessions": lnurl_sessions,
            "issuer": issuer,
            "endpoints": {
                "discovery": "/.well-known/openid-configuration",
                "authorize": "/oauth/authorize",
                "token": "/oauth/token",
                "register": "/oauth/register",
                "jwks": "/oauth/jwks.json",
            },
        }
    )


@legacy_compat_bp.route("/oauthx/docs")
def oauthx_docs():
    issuer = str((current_app.config.get("APP_CONFIG") or {}).get("JWT_ISSUER") or request.url_root.rstrip("/"))
    return jsonify(
        {
            "version": "1.0",
            "authentication": {
                "type": "OAuth 2.0 + OIDC",
                "flows": {
                    "authorization_code": {
                        "authorization_url": f"{issuer.rstrip('/')}/oauth/authorize",
                        "token_url": f"{issuer.rstrip('/')}/oauth/token",
                        "scopes": {
                            "read": "Read-only access",
                            "write": "Write access",
                            "covenant_read": "Read covenants",
                            "covenant_create": "Create covenants",
                            "read_limited": "Limited read access (free tier)",
                        },
                    },
                    "refresh_token": {"token_url": f"{issuer.rstrip('/')}/oauth/token"},
                },
            },
            "endpoints": {
                "POST /oauth/register": {"description": "Register new OAuth client"},
                "GET /oauth/authorize": {"description": "Authorization endpoint"},
                "POST /oauth/token": {"description": "Token endpoint"},
                "GET /api/demo/protected": {
                    "description": "Demo protected endpoint",
                    "headers": {"Authorization": "Bearer <access_token>"},
                    "required_scope": "read_limited",
                },
            },
            "lnurl_auth": {
                "POST /api/lnurl-auth/create": "Create LNURL session",
                "GET /api/lnurl-auth/params": "Get LNURL params",
                "GET /api/lnurl-auth/callback/<session_id>": "LNURL callback",
                "GET /api/lnurl-auth/check/<session_id>": "Check auth status",
            },
        }
    )


@legacy_compat_bp.route("/playground", methods=["GET"])
@legacy_compat_bp.route("/playground/", methods=["GET"])
def playground():
    return render_template("playground.html")


@legacy_compat_bp.route("/account", methods=["GET"])
def account():
    if not session.get("logged_in_pubkey"):
        return redirect(f"/login?next={request.path}")

    pk = session.get("logged_in_pubkey") or ""
    short_pk = (pk[:12] + "…") if isinstance(pk, str) and len(pk) > 12 else pk
    return render_template(
        "account.html",
        pubkey=pk,
        short_pk=short_pk,
        access_level=session.get("access_level", "limited"),
        guest_label=session.get("guest_label"),
    )


@legacy_compat_bp.route("/api/public/status")
def api_public_status():
    return jsonify(
        {
            "online_users": 0,
            "active_sockets": 0,
            "server_time_epoch": int(__import__("time").time()),
            "btc": {"rpc_ok": False},
            "lnd": {"active": False},
        }
    )


@legacy_compat_bp.route("/docs")
@legacy_compat_bp.route("/docs/")
def docs_alias():
    md_items = []
    pdf_items = []
    if STATIC_DOCS_DIR.exists():
        for path in sorted(STATIC_DOCS_DIR.iterdir()):
            if path.suffix.lower() == ".md":
                title = path.stem.replace("_", " ").replace("-", " ").title()
                try:
                    raw = path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    raw = ""
                desc = next((line.strip() for line in raw.splitlines() if line.strip() and not line.startswith("#")), "")[:220]
                md_items.append({"slug": path.stem, "display": title, "desc": desc, "size_kb": (path.stat().st_size + 1023) // 1024})
            elif path.suffix.lower() == ".pdf":
                pdf_items.append({"name": path.name, "size_kb": (path.stat().st_size + 1023) // 1024})
    return render_template("docs_index.html", title="HODLXXI Docs", md_items=md_items, pdf_items=pdf_items)


@legacy_compat_bp.route("/docs.json")
def docs_json_alias():
    return redirect(url_for("legacy_compat.oauthx_docs"), code=302)


@legacy_compat_bp.route("/docs2")
def docs_viewer_v2():
    items = []
    if STATIC_DOCS_DIR.exists():
        items = sorted([path.name for path in STATIC_DOCS_DIR.iterdir() if path.suffix.lower() in {".md", ".pdf"}])
    return render_template("docs_viewer.html", items=items)


def _register_blueprint_once(app, blueprint):
    if blueprint.name in app.blueprints:
        return
    app.register_blueprint(blueprint)


def register_legacy_compat(app):
    register_docs_routes(app)
    _register_blueprint_once(app, accounts_page_bp)
    _register_blueprint_once(app, billing_api_compat_bp)
    _register_blueprint_once(app, account_api_compat_bp)
    _register_blueprint_once(app, legacy_compat_bp)
