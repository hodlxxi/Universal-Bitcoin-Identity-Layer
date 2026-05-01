"""
UI Blueprint - Frontend Routes (Dashboard, Playground, Chat)

Serves frontend HTML pages and handles user interface routes.
"""

import logging

from flask import Blueprint, redirect, render_template, render_template_string, request, session, url_for
from app.browser_routes import call_browser_route_handler, render_browser_playground
from app.browser_compat import (
    redirect_explorer,
    redirect_oneword,
    redirect_onboard,
    render_account_page,
    render_upgrade_page,
)
from app.browser_shell_routes import render_browser_home_page

logger = logging.getLogger(__name__)

ui_bp = Blueprint("ui", __name__)


@ui_bp.route("/")
def index():
    """
    Public front door:
    - logged-in users -> /home
    - everyone else   -> agent-first homepage
    """
    try:
        if session.get("logged_in_pubkey"):
            return redirect(url_for("ui.home"))
    except Exception:
        pass

    return render_template(
        "home_agent.html",
        agent_name="HODLXXI / UBID",
        tagline="Cryptographic identity, payment, and trust infrastructure for agents.",
        endpoints=[
            ("/agent/capabilities", "Supported jobs and pricing"),
            ("/agent/request", "Submit paid agent jobs"),
            ("/agent/reputation", "Public reputation surface"),
            ("/agent/attestations", "Public attestation chain"),
            ("/agent/chain/health", "Chain health surface"),
            ("/agent/trust/hodlxxi-herald-01", "Public trust surface for HODLXXI Herald"),
            ("/agent/marketplace/listing", "Marketplace-facing listing"),
            ("/screensaver", "Human / narrative interface"),
            ("/.well-known/openid-configuration", "OpenID discovery surface"),
        ],
        capabilities=[
            ("ping", "Lightweight liveness / protocol test"),
            ("verify_signature", "Verify secp256k1 signed payloads"),
            ("covenant_decode", "Decode covenant and script-related requests"),
        ],
        trust_features=[
            "Payment required before work",
            "Signed receipts",
            "Public attestations",
            "Public reputation surface",
            "Chain health visibility",
            "Bitcoin-native identity orientation",
        ],
    )


@ui_bp.route("/oidc")
def oidc_landing():
    return render_template_string(
        """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HODLXXI OIDC Direction</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; margin: 0; background: #0a0f14; color: #e7f7ef; }
    .wrap { max-width: 900px; margin: 0 auto; padding: 2rem 1.2rem; }
    h1 { color: #4dffb8; }
    a { color: #79caff; }
    .card { background: #111a22; border: 1px solid #1f394a; border-radius: 10px; padding: 1rem 1.1rem; margin: 1rem 0; }
    .muted { color: #a7bac8; }
  </style>
</head>
<body>
  <main class="wrap">
    <h1>HODLXXI / UBID — OIDC Direction</h1>
    <p>HODLXXI is an experimental Bitcoin-native identity and trust runtime.</p>
    <div class="card">
      <p>OIDC support is a direction for interoperability and is not finalized.</p>
      <p><strong>KeyAuth is a reference implementation, not an authority.</strong></p>
      <p class="muted">No production authority, warranty, or governance guarantees are implied by this page.</p>
    </div>
    <h2>Live Surfaces</h2>
    <ul>
      <li><a href="/.well-known/openid-configuration">/.well-known/openid-configuration</a></li>
      <li><a href="/.well-known/agent.json">/.well-known/agent.json</a></li>
      <li><a href="/agent/capabilities">/agent/capabilities</a></li>
      <li><a href="/agent/reputation">/agent/reputation</a></li>
      <li><a href="/api/public/status">/api/public/status</a></li>
      <li><a href="/docs">/docs</a></li>
      <li><a href="https://github.com/hodlxxi/Universal-Bitcoin-Identity-Layer">GitHub repository</a></li>
    </ul>
  </main>
</body>
</html>
"""
    )


@ui_bp.route("/screensaver")
def screensaver():
    return render_template("screensaver.html")


@ui_bp.route("/app")
def legacy_chat_route():
    if not session.get("logged_in_pubkey"):
        return redirect(f"/login?next={request.path}")

    return call_browser_route_handler("chat", default_handler=lambda: ("chat handler missing", 500))


@ui_bp.route("/home", methods=["GET"], endpoint="home")
def legacy_home_route():
    return render_browser_home_page(logger=logger)


@ui_bp.route("/account", methods=["GET"])
def legacy_account_route():
    return render_account_page()


@ui_bp.route("/dashboard")
def dashboard():
    """
    User dashboard (requires authentication).

    Returns:
        HTML dashboard
    """
    pubkey = session.get("logged_in_pubkey")
    access_level = session.get("access_level", "guest")

    if not pubkey:
        return (
            """
        <html>
        <body>
            <h1>Not Authenticated</h1>
            <p>Please <a href="/login">login</a> first.</p>
        </body>
        </html>
        """,
            401,
        )

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard</title>
    <style>
        body {{ margin: 0; padding: 2rem; font-family: system-ui; background: #0b0f10; color: #e6f1ef; }}
        .card {{ background: #11171a; border: 1px solid #00ff88; border-radius: 12px; padding: 1.5rem; margin-bottom: 1rem; }}
        h1 {{ color: #00ff88; }}
        .pubkey {{ font-family: monospace; word-break: break-all; }}
    </style>
</head>
<body>
    <h1>Dashboard</h1>
    <div class="card">
        <h3>Authentication Status</h3>
        <p><strong>Public Key:</strong> <span class="pubkey">{pubkey}</span></p>
        <p><strong>Access Level:</strong> {access_level}</p>
    </div>
    <div class="card">
        <h3>Quick Links</h3>
        <p>
            <a href="/playground">API Playground</a> |
            <a href="/oauth/clients">OAuth Clients</a> |
            <a href="/logout">Logout</a>
        </p>
    </div>
</body>
</html>
    """
    return render_template_string(html)


@ui_bp.route("/playground")
def playground():
    return render_browser_playground()


@ui_bp.route("/explorer", methods=["GET"])
def legacy_explorer_route():
    return redirect_explorer()


@ui_bp.route("/onboard", methods=["GET"])
def legacy_onboard_route():
    return redirect_onboard()


@ui_bp.route("/oneword", methods=["GET"])
def legacy_oneword_route():
    return redirect_oneword()


@ui_bp.route("/upgrade", methods=["GET", "POST"])
def legacy_upgrade_route():
    return render_upgrade_page()
