"""
Application Factory for Universal Bitcoin Identity Layer

Implements the Flask application factory pattern with:
- Blueprint registration
- Security configuration (TLS, JWKS, secrets)
- Database and cache initialization
- Comprehensive error handling
"""

import logging
import os
import time
from typing import Optional

from flask import Flask, g, jsonify, redirect, render_template_string, request
from flask_socketio import SocketIO
from werkzeug.exceptions import HTTPException

from app.audit_logger import init_audit_logger
from app.config import AppConfig, get_config
from app.database import close_all, init_all
from app.jwks import ensure_rsa_keypair
from app.request_context import get_or_create_request_id
from app.security import init_security
from app.structured_logging import log_event
from app.browser_routes import register_browser_route_handlers
from app.socket_handlers import register_socket_handlers
from app.socket_state import CHAT_HISTORY, ONLINE_USERS
from app.utils import generate_challenge, get_rpc_connection

logger = logging.getLogger(__name__)

EXPIRY_SECONDS = int(os.getenv("CHAT_EXPIRY_SECONDS", "45"))


def purge_old_messages() -> None:
    """Keep only messages newer than EXPIRY_SECONDS."""
    now = time.time()

    def is_fresh(msg):
        ts = msg.get("ts") if isinstance(msg, dict) else None
        return ts is not None and (now - ts) <= EXPIRY_SECONDS

    CHAT_HISTORY[:] = [msg for msg in CHAT_HISTORY if is_fresh(msg)]


def create_app(config_override: Optional[AppConfig] = None) -> Flask:
    """
    Create and configure the Flask application using the factory pattern.

    Args:
        config_override: Optional configuration override for testing

    Returns:
        Configured Flask application instance

    Security features:
    - RS256 JWT with managed JWKS endpoint
    - TLS enforcement in production
    - Security headers via Talisman
    - Rate limiting
    - Secret management via environment variables
    """

    app = Flask(__name__)

    # TESTING/CI: isolate Flask-Limiter counters between tests (memory storage persists otherwise)
    try:
        import os
        import uuid

        if (
            os.environ.get("TESTING") == "1"
            or "PYTEST_CURRENT_TEST" in os.environ
            or app.config.get("TESTING")
            or getattr(app, "testing", False)
        ):
            # REMOVED: do not force memory rate limit storage
            app.config.setdefault("RATELIMIT_KEY_PREFIX", f"test-{uuid.uuid4()}")
    except Exception:
        pass

    # Initialize rate limiter BEFORE importing blueprints (decorators bind at import time)
    try:
        from app.security import init_rate_limiter

        init_rate_limiter(app)
    except Exception:
        pass

    # Semantic version used by /health and tests
    app.config.setdefault("APP_VERSION", "1.0.0-beta")

    # Load configuration
    cfg = config_override or get_config()
    app.config["APP_CONFIG"] = cfg

    # Set Flask secret key (required for sessions)
    app.secret_key = cfg["FLASK_SECRET_KEY"]

    # Initialize RSA keypair for RS256 JWT signing with key rotation
    try:
        rotation_days = cfg.get("JWKS_ROTATION_DAYS", 90)
        max_retired = cfg.get("JWKS_MAX_RETIRED_KEYS", 3)

        jwks_doc, jwt_kid = ensure_rsa_keypair(
            cfg["JWKS_DIR"], rotation_days=rotation_days, max_retired_keys=max_retired
        )
        app.config["JWKS_DOCUMENT"] = jwks_doc
        app.config["JWT_KID"] = jwt_kid
        logger.info(
            f"✅ JWKS initialized: kid={jwt_kid}, keys={len(jwks_doc.get('keys', []))}, rotation={rotation_days}d"
        )
    except Exception as e:
        logger.error(f"❌ JWKS initialization failed: {e}")
        raise

    # Initialize security middleware (Talisman, rate limiting, CORS)
    init_security(app, cfg)

    # Initialize database and cache connections
    try:
        init_all()
        init_audit_logger()
        logger.info("✅ Database, cache, and audit logging initialized")
    except Exception as e:
        logger.error(f"❌ Infrastructure initialization failed: {e}")
        raise

    # Register blueprints
    # Rate limiter must be initialized BEFORE importing blueprints (blueprints use @limiter.limit at import time)
    try:
        from app.security import init_rate_limiter

        init_rate_limiter(app)
    except Exception:
        # Tests/minimal setups may intentionally disable the limiter
        pass

    register_blueprints(app)
    register_runtime_handlers()

    # Register error handlers
    register_error_handlers(app)

    # Register before/after request handlers
    register_request_handlers(app)

    socketio = create_socketio(app)
    register_socket_handlers(socketio)

    logger.info("🚀 Application factory completed successfully")

    return app


def register_blueprints(app: Flask) -> None:
    """Register all application blueprints."""

    # OIDC discovery and JWKS endpoints (already exists)
    from app.oidc import oidc_bp

    app.register_blueprint(oidc_bp)

    # Authentication blueprint (login, logout, signature verification)
    from app.blueprints.auth import auth_bp

    app.register_blueprint(auth_bp)

    # Bitcoin operations blueprint (RPC, descriptors, wallets)
    from app.blueprints.bitcoin import bitcoin_bp

    app.register_blueprint(bitcoin_bp, url_prefix="/api")

    # LEGACY_CHALLENGE_BRIDGE_V1
    # expose login challenge endpoint from legacy app.app
    if "api_challenge" not in app.view_functions:
        from app.app import api_challenge as legacy_api_challenge

        app.add_url_rule("/api/challenge", endpoint="api_challenge", view_func=legacy_api_challenge, methods=["POST"])
    # /LEGACY_CHALLENGE_BRIDGE_V1

    # LEGACY_VERIFY_BRIDGE_V1
    # Factory runtime uses wsgi:app=create_app(), but /api/verify still lives in app.app.
    # Register a thin bridge so production runtime exposes the login verify endpoint.
    if "api_verify" not in app.view_functions:
        from app.app import api_verify as legacy_api_verify

        app.add_url_rule("/api/verify", endpoint="api_verify", view_func=legacy_api_verify, methods=["POST"])
    # /LEGACY_VERIFY_BRIDGE_V1

    # Demo blueprint (public test endpoints)
    from app.blueprints.demo import demo_bp

    app.register_blueprint(demo_bp, url_prefix="/api/demo")
    # LNURL-Auth blueprint (challenges, callbacks)
    from app.blueprints.lnurl import lnurl_bp

    app.register_blueprint(lnurl_bp, url_prefix="/api/lnurl-auth")

    # OAuth2/OIDC blueprint (token, authorize, introspect, revoke)
    from app.blueprints.oauth import oauth_bp

    app.register_blueprint(oauth_bp, url_prefix="/oauth")

    # OAuth developer-facing surface (status/docs/client listing)
    from app.blueprints.oauth_dev import oauth_dev_bp

    app.register_blueprint(oauth_dev_bp)

    # Admin/operations blueprint (health, metrics, TURN)
    from app.blueprints.admin import admin_bp

    app.register_blueprint(admin_bp)

    # Proof-of-Funds blueprints (legacy public frontend + API)
    from app.pof_routes import pof_bp, pof_api_bp

    app.register_blueprint(pof_bp)
    app.register_blueprint(pof_api_bp)

    # UI/frontend blueprint (dashboard, playground, chat)
    from app.blueprints.ui import ui_bp
    from app.dev_routes import dev_bp

    app.register_blueprint(ui_bp)
    # Developer Platform
    app.register_blueprint(dev_bp)
    logger.info("✓ Developer platform registered")

    # OAuth client billing endpoints
    from app.blueprints.billing_agent import billing_agent_bp
    from app.blueprints.agent import agent_bp

    app.register_blueprint(billing_agent_bp)
    app.register_blueprint(agent_bp)

    # Public documentation routes
    from app.docs_routes import register_docs_routes

    register_docs_routes(app)

    # Legacy endpoint aliases for old templates/helpers that still call bare endpoint names
    try:
        if "ui.home" in app.view_functions and "home" not in app.view_functions:
            app.add_url_rule("/home", endpoint="home", view_func=app.view_functions["ui.home"])
        if "auth.login" in app.view_functions and "login" not in app.view_functions:
            app.add_url_rule("/login", endpoint="login", view_func=app.view_functions["auth.login"])
        if "auth.logout" in app.view_functions and "logout" not in app.view_functions:
            app.add_url_rule("/logout", endpoint="logout", view_func=app.view_functions["auth.logout"])
        if "ui.playground" in app.view_functions and "playground" not in app.view_functions:
            app.add_url_rule("/playground", endpoint="playground", view_func=app.view_functions["ui.playground"])
        if "ui.legacy_chat_route" in app.view_functions and "app" not in app.view_functions:
            app.add_url_rule("/app", endpoint="app", view_func=app.view_functions["ui.legacy_chat_route"])
    except Exception as e:
        logger.warning(f"Legacy endpoint alias registration failed: {e}")

    from app.blueprints.legacy_bridge import register_legacy_routes

    register_legacy_routes(app)
    logger.info("✅ All blueprints registered")


def register_runtime_handlers() -> None:
    """Initialize browser runtime handlers without registering Flask routes."""
    register_browser_route_handlers(
        generate_challenge=generate_challenge,
        get_rpc_connection=get_rpc_connection,
        logger=logger,
        render_template_string_func=render_template_string,
        special_names={},
        force_relay=False,
        chat_history=CHAT_HISTORY,
        online_users=ONLINE_USERS,
        purge_old_messages=purge_old_messages,
    )


def register_error_handlers(app: Flask) -> None:
    """Register global error handlers."""

    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "bad_request"}), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({"error": "unauthorized", "message": "Authentication required"}), 401

    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({"error": "forbidden", "message": "Access denied"}), 403

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "not_found", "message": "Resource not found"}), 404

    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return jsonify({"error": "rate_limit_exceeded"}), 429

    @app.errorhandler(500)
    def internal_error(e):
        request_id = getattr(g, "request_id", None)
        log_event(logger, "http.internal_error", outcome="error", status=500)
        logger.error(
            "internal_server_error request_id=%s path=%s method=%s",
            request_id,
            request.path,
            request.method,
            exc_info=True,
        )
        payload = {"error": "internal_error", "message": "An unexpected error occurred"}
        if request_id:
            payload["request_id"] = request_id
        return jsonify(payload), 500

    @app.errorhandler(Exception)
    def unhandled_exception(e):
        if isinstance(e, HTTPException):
            return e
        request_id = getattr(g, "request_id", None)
        log_event(logger, "http.unhandled_exception", outcome="error", status=500)
        logger.error(
            "unhandled_exception request_id=%s path=%s method=%s",
            request_id,
            request.path,
            request.method,
            exc_info=True,
        )
        payload = {"error": "internal_error", "message": "An unexpected error occurred"}
        if request_id:
            payload["request_id"] = request_id
        return jsonify(payload), 500


def register_request_handlers(app: Flask) -> None:
    """Register before/after request handlers."""

    OAUTH_PATH_PREFIXES = ("/oauth/", "/oauthx/")
    OAUTH_PUBLIC_PATHS = (
        "/oauth/register",
        "/oauth/authorize",
        "/oauth/token",
        "/oauthx/status",
        "/oauthx/docs",
        "/.well-known/openid-configuration",
    )

    @app.before_request
    def normalize_browser_alias_typos():
        """Canonicalize common legacy browser URL typos."""
        if request.path == "/accaunt":
            return redirect("/account", code=301)
        if request.path == "/accaunts":
            return redirect("/accounts", code=301)

    @app.before_request
    def mark_oauth_public_paths():
        """Mark OAuth public paths to bypass authentication checks."""
        get_or_create_request_id()
        log_event(logger, "http.request_received", outcome="started")
        p = request.path or "/"
        if any(p.startswith(pref) for pref in OAUTH_PATH_PREFIXES) or p in OAUTH_PUBLIC_PATHS:
            setattr(request, "_oauth_public", True)

    @app.after_request
    def add_security_headers(response):
        """Add additional security headers to all responses."""
        # Talisman already handles most headers, but we can add custom ones here

        # Only add HSTS in production with HTTPS
        cfg = app.config.get("APP_CONFIG", {})
        if cfg.get("FORCE_HTTPS") and request.is_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        response.headers["X-Request-ID"] = getattr(g, "request_id", "") or response.headers.get("X-Request-ID", "")
        log_event(logger, "http.response_sent", outcome="completed", status=response.status_code)

        return response

    @app.teardown_appcontext
    def cleanup(error=None):
        """Cleanup resources after request."""
        if error:
            logger.error(f"Request cleanup with error: {error}")
        # Database connections are handled by connection pooling


def create_socketio(app: Flask) -> SocketIO:
    """
    Create and configure SocketIO instance.

    Args:
        app: Flask application instance

    Returns:
        Configured SocketIO instance
    """
    cfg = app.config["APP_CONFIG"]
    socketio_cors = cfg.get("SOCKETIO_CORS", "*")

    socketio = SocketIO(app, cors_allowed_origins=socketio_cors)

    @socketio.on_error_default
    def default_error_handler(e):
        """Handle SocketIO errors."""
        logger.error(f"SocketIO error: {e}", exc_info=True)

    return socketio
