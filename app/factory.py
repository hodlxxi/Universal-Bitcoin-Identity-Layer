"""
Application Factory for Universal Bitcoin Identity Layer

Implements the Flask application factory pattern with:
- Blueprint registration
- Security configuration (TLS, JWKS, secrets)
- Database and cache initialization
- Comprehensive error handling
"""

import logging
from typing import Optional

from flask import Flask, jsonify
from flask_socketio import SocketIO

from app.audit_logger import init_audit_logger
from app.config import AppConfig, get_config
from app.database import close_all, init_all
from app.jwks import ensure_rsa_keypair
from app.security import init_security

logger = logging.getLogger(__name__)


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
            cfg["JWKS_DIR"],
            rotation_days=rotation_days,
            max_retired_keys=max_retired
        )
        app.config["JWKS_DOCUMENT"] = jwks_doc
        app.config["JWT_KID"] = jwt_kid
        logger.info(f"✅ JWKS initialized: kid={jwt_kid}, keys={len(jwks_doc.get('keys', []))}, rotation={rotation_days}d")
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
    register_blueprints(app)

    # Register error handlers
    register_error_handlers(app)

    # Register before/after request handlers
    register_request_handlers(app)

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

    # LNURL-Auth blueprint (challenges, callbacks)
    from app.blueprints.lnurl import lnurl_bp
    app.register_blueprint(lnurl_bp, url_prefix="/api/lnurl-auth")

    # OAuth2/OIDC blueprint (token, authorize, introspect, revoke)
    from app.blueprints.oauth import oauth_bp
    app.register_blueprint(oauth_bp, url_prefix="/oauth")

    # Admin/operations blueprint (health, metrics, TURN)
    from app.blueprints.admin import admin_bp
    app.register_blueprint(admin_bp)

    # UI/frontend blueprint (dashboard, playground, chat)
    from app.blueprints.ui import ui_bp
    from app.dev_routes import dev_bp
    app.register_blueprint(ui_bp)
    # Developer Platform
    app.register_blueprint(dev_bp)
    logger.info("✓ Developer platform registered")

    logger.info("✅ All blueprints registered")


def register_error_handlers(app: Flask) -> None:
    """Register global error handlers."""

    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "bad_request", "message": str(e)}), 400

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
        return jsonify({"error": "rate_limit_exceeded", "message": str(e)}), 429

    @app.errorhandler(500)
    def internal_error(e):
        logger.error(f"Internal server error: {e}", exc_info=True)
        return jsonify({"error": "internal_error", "message": "An unexpected error occurred"}), 500


def register_request_handlers(app: Flask) -> None:
    """Register before/after request handlers."""

    from flask import request

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
    def mark_oauth_public_paths():
        """Mark OAuth public paths to bypass authentication checks."""
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
