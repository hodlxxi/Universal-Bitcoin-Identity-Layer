"""
UI Blueprint - Frontend Routes (Dashboard, Playground, Chat)

Serves frontend HTML pages and handles user interface routes.
"""

import logging

from flask import Blueprint, current_app, redirect, render_template, render_template_string, session, url_for

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
            return redirect(url_for("home"))
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


@ui_bp.route("/screensaver")
def screensaver():
    return render_template("screensaver.html")


@ui_bp.route("/app")
def legacy_chat_route():
    from app.app import chat as legacy_chat

    return legacy_chat()


@ui_bp.route("/home", methods=["GET"], endpoint="home")
def legacy_home_route():
    from app.app import home_page as legacy_home_page

    return legacy_home_page()


@ui_bp.route("/account", methods=["GET"])
def legacy_account_route():
    from app.app import account as legacy_account

    return legacy_account()


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
    """
    API testing playground.

    Returns:
        HTML API playground
    """
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>API Playground</title>
    <style>
        body { margin: 0; padding: 2rem; font-family: system-ui; background: #0b0f10; color: #e6f1ef; }
        .endpoint { background: #11171a; border: 1px solid #00ff88; border-radius: 12px; padding: 1.5rem; margin-bottom: 1rem; }
        h1 { color: #00ff88; }
        button { background: #00ff88; color: #0b0f10; border: none; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; }
        button:hover { opacity: 0.8; }
        pre { background: #000; padding: 1rem; border-radius: 6px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>API Playground</h1>

    <div class="endpoint">
        <h3>Health Check</h3>
        <button onclick="fetchEndpoint('/health', 'health-result')">GET /health</button>
        <pre id="health-result">Click to fetch</pre>
    </div>

    <div class="endpoint">
        <h3>Metrics</h3>
        <button onclick="fetchEndpoint('/metrics', 'metrics-result')">GET /metrics</button>
        <pre id="metrics-result">Click to fetch</pre>
    </div>

    <div class="endpoint">
        <h3>OIDC Discovery</h3>
        <button onclick="fetchEndpoint('/.well-known/openid-configuration', 'oidc-result')">GET /.well-known/openid-configuration</button>
        <pre id="oidc-result">Click to fetch</pre>
    </div>

    <div class="endpoint">
        <h3>JWKS</h3>
        <button onclick="fetchEndpoint('/oauth/jwks.json', 'jwks-result')">GET /oauth/jwks.json</button>
        <pre id="jwks-result">Click to fetch</pre>
    </div>

    <script>
        async function fetchEndpoint(url, resultId) {
            const resultEl = document.getElementById(resultId);
            resultEl.textContent = 'Loading...';
            try {
                const response = await fetch(url);
                const data = await response.json();
                resultEl.textContent = JSON.stringify(data, null, 2);
            } catch (error) {
                resultEl.textContent = 'Error: ' + error.message;
            }
        }
    </script>
</body>
</html>
    """
    return render_template_string(html)
