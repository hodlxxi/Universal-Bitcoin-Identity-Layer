"""
UI Blueprint - Frontend Routes (Dashboard, Playground, Chat)

Serves frontend HTML pages and handles user interface routes.
"""

import logging

import json

from flask import Blueprint, Response, redirect, render_template, render_template_string, request, session, url_for
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


@ui_bp.get("/robots.txt")
def robots_txt():
    body = "\n".join(
        [
            "User-agent: *",
            "Allow: /",
            "Content-Signal: ai-train=no, search=yes, ai-input=no",
            "Sitemap: https://hodlxxi.com/sitemap.xml",
        ]
    )
    return Response(body + "\n", mimetype="text/plain")


@ui_bp.get("/sitemap.xml")
def sitemap_xml():
    base_url = "https://hodlxxi.com"
    paths = [
        "/",
        "/chat-landing",
        "/.well-known/agent.json",
        "/.well-known/openid-configuration",
        "/.well-known/nostr-dm-policy.json",
        "/agent/capabilities",
        "/agent/capabilities/schema",
        "/agent/skills",
        "/agent/reputation",
        "/agent/attestations",
        "/agent/chain/health",
        "/api/public/status",
    ]
    urls = "".join(f"<url><loc>{base_url}{path}</loc></url>" for path in paths)
    xml = (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>'
    )
    return Response(xml, mimetype="application/xml")


def _wants_markdown_response():
    markdown_quality = request.accept_mimetypes["text/markdown"]
    html_quality = request.accept_mimetypes["text/html"]
    return markdown_quality > 0 and markdown_quality >= html_quality


@ui_bp.before_request
def serve_markdown_for_agents():
    if request.path != "/":
        return None

    if not _wants_markdown_response():
        return None

    body = """# HODLXXI

Bitcoin-native identity, agent discovery, Lightning-paid jobs, signed receipts, attestations, reputation, and staged private messaging.

## Agent discovery

- Agent descriptor: `/.well-known/agent.json`
- API catalog: `/.well-known/api-catalog`
- Capabilities: `/agent/capabilities`
- Capability schema: `/agent/capabilities/schema`
- Skills: `/agent/skills`
- Reputation: `/agent/reputation`
- Attestations: `/agent/attestations`
- Chain health: `/agent/chain/health`
- Public status: `/api/public/status`

## Authentication and identity

- OIDC metadata: `/.well-known/openid-configuration`
- Nostr DM policy: `/.well-known/nostr-dm-policy.json`

## Messaging status

NIP-17 / NIP-59 messaging is visible for discovery and UI readiness, but sending, intake, and relay publishing remain disabled.

## Documentation

- Human docs: `/docs`
- Robots: `/robots.txt`
- Sitemap: `/sitemap.xml`
"""

    response = Response(body, mimetype="text/markdown")
    response.headers["X-Markdown-Tokens"] = str(len(body.split()))
    response.headers["Link"] = ", ".join(
        [
            '</.well-known/api-catalog>; rel="api-catalog"; type="application/linkset+json"',
            '</.well-known/agent.json>; rel="service-desc"; type="application/json"',
            '</agent/capabilities>; rel="service-desc"; type="application/json"',
            '</docs>; rel="service-doc"; type="text/html"',
            '</api/public/status>; rel="status"; type="application/json"',
        ]
    )
    return response


@ui_bp.after_request
def add_agent_discovery_link_headers(response):
    if request.path == "/":
        links = [
            '</.well-known/api-catalog>; rel="api-catalog"; type="application/linkset+json"',
            '</.well-known/agent.json>; rel="service-desc"; type="application/json"',
            '</agent/capabilities>; rel="service-desc"; type="application/json"',
            '</docs>; rel="service-doc"; type="text/html"',
            '</api/public/status>; rel="status"; type="application/json"',
        ]
        response.headers["Link"] = ", ".join(links)
    return response


@ui_bp.get("/.well-known/api-catalog")
def api_catalog():
    base_url = "https://hodlxxi.com"
    catalog = {
        "linkset": [
            {
                "anchor": base_url,
                "api-catalog": [
                    {
                        "href": f"{base_url}/.well-known/api-catalog",
                        "type": "application/linkset+json",
                    }
                ],
                "service-doc": [
                    {
                        "href": f"{base_url}/docs",
                        "type": "text/html",
                    }
                ],
                "status": [
                    {
                        "href": f"{base_url}/api/public/status",
                        "type": "application/json",
                    }
                ],
            },
            {
                "anchor": f"{base_url}/agent",
                "service-desc": [
                    {
                        "href": f"{base_url}/agent/capabilities",
                        "type": "application/json",
                    },
                    {
                        "href": f"{base_url}/agent/capabilities/schema",
                        "type": "application/schema+json",
                    },
                    {
                        "href": f"{base_url}/.well-known/agent.json",
                        "type": "application/json",
                    },
                ],
                "service-doc": [
                    {
                        "href": f"{base_url}/docs",
                        "type": "text/html",
                    }
                ],
                "status": [
                    {
                        "href": f"{base_url}/agent/chain/health",
                        "type": "application/json",
                    },
                    {
                        "href": f"{base_url}/api/public/status",
                        "type": "application/json",
                    },
                ],
            },
        ]
    }
    body = json.dumps(catalog, sort_keys=True, separators=(",", ":")) + "\n"
    return Response(body, mimetype="application/linkset+json")


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
    return render_template("oidc.html")


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


@ui_bp.get("/my-kyc-id")
def my_kyc_id_landing():
    """Public KYK / Know Your Key identity landing page."""
    return render_template("my_kyc_id_landing.html")


@ui_bp.get("/chat-landing")
def chat_landing():
    """Public chat landing page.

    CTA intentionally points to /login?next=/app so successful login returns
    to the existing chat runtime.
    """
    return render_template("chat_landing.html")
