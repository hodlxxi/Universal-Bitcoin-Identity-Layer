"""Security helpers for configuring Flask in production."""
from __future__ import annotations

import logging
import os
from typing import Any, Mapping, Optional

from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

try:  # pragma: no cover - optional dependency
    from flask_talisman import Talisman  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - fallback for tests
    Talisman = None  # type: ignore


logger = logging.getLogger(__name__)

limiter: Optional[Limiter] = None


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "yes", "on"}


def _build_redis_uri(cfg: Mapping[str, Any]) -> str:
    if cfg.get("REDIS_URL"):
        return str(cfg["REDIS_URL"])

    host = cfg.get("REDIS_HOST", "127.0.0.1")
    port = cfg.get("REDIS_PORT", 6379)
    db = cfg.get("REDIS_DB", 0)
    password = cfg.get("REDIS_PASSWORD")
    if password:
        return f"redis://:{password}@{host}:{port}/{db}"
    return f"redis://{host}:{port}/{db}"


def init_security(app: Flask, cfg: Mapping[str, Any]) -> Optional[Limiter]:
    """Initialise standard security middleware and rate limiting."""
    global limiter

    # Respect reverse proxy headers for TLS detection and client IP extraction.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)  # type: ignore[assignment]

    default_force_https = (
        str(cfg.get("FLASK_ENV") or os.getenv("FLASK_ENV", "development"))
        .strip()
        .lower()
        == "production"
    )
    force_https = _as_bool(cfg.get("FORCE_HTTPS"), default_force_https)
    # Allow explicit override via environment for local debugging (DEV ONLY)
    # Set DISABLE_FORCE_HTTPS=1 in the service environment to disable HTTP->HTTPS redirects.
    if os.getenv("DISABLE_FORCE_HTTPS", "").lower() in {"1", "true", "yes", "on"}:
        force_https = False
        logger.warning("DISABLE_FORCE_HTTPS set: disabling HTTPS enforcement for local debugging.")


    if not force_https and default_force_https:
        logger.warning(
            "FORCE_HTTPS disabled while FLASK_ENV=production – ensure this is intentional before deploying."
        )
    elif force_https:
        logger.debug("HTTPS enforcement enabled")
    csp = {
        "default-src": "'self'",
        "img-src": "* data:",
        "style-src": "'self' 'unsafe-inline'",
        # CRITICAL: Added cdnjs.cloudflare.com and 'unsafe-eval' for Socket.IO
        "script-src": "'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tailwindcss.com",
        # CRITICAL: Added wss: and ws: for WebSocket connections
        "connect-src": "'self' wss: ws: https: http:",
        "font-src": "'self' https://fonts.googleapis.com https://fonts.gstatic.com",
    }
    if Talisman is not None:
        Talisman(
            app,
            force_https=force_https,
            force_file_save=False,
            content_security_policy=csp,
            session_cookie_secure=True,
            session_cookie_samesite="Lax",
            frame_options="DENY",
            referrer_policy="no-referrer",
        )
    else:
        logger.warning("flask-talisman not installed; skipping security headers setup")

    limit_default = cfg.get("RATELIMIT_DEFAULT") or cfg.get("RATE_LIMIT_DEFAULT") or "100/hour"
    if not limit_default:
        limit_default = "100/hour"

    if cfg.get("RATE_LIMIT_ENABLED") is False:
        limiter = None
    else:
        storage_uri = _build_redis_uri(cfg) if cfg.get("REDIS_URL") or cfg.get("REDIS_HOST") else "memory://"
        limiter = Limiter(
            key_func=get_remote_address,
            default_limits=[limit_default],
            storage_uri=storage_uri or "memory://",
            strategy="fixed-window",
        )
        limiter.init_app(app)

    log_level = str(cfg.get("LOG_LEVEL", "INFO")).upper()
    level = getattr(logging, log_level, logging.INFO)
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    if not any(isinstance(handler, logging.StreamHandler) for handler in root_logger.handlers):
        handler = logging.StreamHandler()
        fmt = (
            "{\"level\":\"%(levelname)s\",\"msg\":\"%(message)s\",\"name\":\"%(name)s\",\"path\":\"%(pathname)s\","
            "\"lineno\":%(lineno)d}"
        )
        handler.setFormatter(logging.Formatter(fmt))
        root_logger.addHandler(handler)

    return limiter
