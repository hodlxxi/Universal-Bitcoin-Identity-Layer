"""
UI Blueprint - Frontend Routes (Dashboard, Playground, Chat)

Serves frontend HTML pages and handles user interface routes.
"""

import logging

from flask import Blueprint, current_app, render_template_string, session

logger = logging.getLogger(__name__)

ui_bp = Blueprint("ui", __name__)


@ui_bp.route("/")
def index():
    """
    Application home page.

    Returns:
        HTML homepage
    """
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Universal Bitcoin Identity Layer</title>
    <style>
        :root {
            --bg: #0b0f10;
            --panel: #11171a;
            --fg: #e6f1ef;
            --accent: #00ff88;
        }
        body {
            margin: 0;
            padding: 0;
            font-family: -apple-system, system-ui, sans-serif;
            background: var(--bg);
            color: var(--fg);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            max-width: 800px;
            padding: 2rem;
            text-align: center;
        }
        h1 {
            color: var(--accent);
            font-size: 2.5rem;
            margin-bottom: 1rem;
        }
        p {
            font-size: 1.1rem;
            line-height: 1.6;
            margin-bottom: 2rem;
        }
        .links {
            display: flex;
            gap: 1rem;
            justify-content: center;
            flex-wrap: wrap;
        }
        a {
            background: var(--panel);
            color: var(--accent);
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            text-decoration: none;
            border: 1px solid var(--accent);
            transition: all 0.3s;
        }
        a:hover {
            background: var(--accent);
            color: var(--bg);
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Universal Bitcoin Identity Layer</h1>
        <p>
            Decentralized identity powered by Bitcoin signatures, Lightning Network,
            and OpenID Connect. Authenticate with proof of Bitcoin ownership.
        </p>
        <div class="links">
            <a href="/login">Login</a>
            <a href="/dashboard">Dashboard</a>
            <a href="/playground">API Playground</a>
            <a href="/.well-known/openid-configuration">OIDC Discovery</a>
            <a href="/health">Health Check</a>
        </div>
    </div>
</body>
</html>
    """
    return render_template_string(html)


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
        return """
        <html>
        <body>
            <h1>Not Authenticated</h1>
            <p>Please <a href="/login">login</a> first.</p>
        </body>
        </html>
        """, 401

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
