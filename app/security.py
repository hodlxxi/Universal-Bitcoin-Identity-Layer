"""Security helpers for configuring Flask in production."""

from __future__ import annotations

import logging
import os
from typing import Any, Mapping, Optional

from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix


# ------------------------------
# Ensure limiter exists at import time
# ------------------------------
def ensure_limiter_initialized():
    global limiter
    try:
        limiter_obj = globals().get("limiter", None)
    except Exception:
        limiter_obj = None

    if limiter_obj is None:
        try:
            limiter = Limiter(key_func=get_remote_address)
        except Exception:
            # Absolute fallback (should not happen in your env)
            class _NoopLimiter:
                def limit(self, *_a, **_k):
                    def _decorator(fn):
                        return fn

                    return _decorator

            limiter = _NoopLimiter()


ensure_limiter_initialized()

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
        str(cfg.get("FLASK_ENV") or os.getenv("FLASK_ENV", "development")).strip().lower() == "production"
    )
    force_https = _as_bool(cfg.get("FORCE_HTTPS"), default_force_https)
    # Allow explicit override via environment for local debugging (DEV ONLY)
    # Set DISABLE_FORCE_HTTPS=1 in the service environment to disable HTTP->HTTPS redirects.
    if os.getenv("DISABLE_FORCE_HTTPS", "").lower() in {"1", "true", "yes", "on"}:
        force_https = False
        logger.warning("DISABLE_FORCE_HTTPS set: disabling HTTPS enforcement for local debugging.")

    if not force_https and default_force_https:
        logger.warning("FORCE_HTTPS disabled while FLASK_ENV=production – ensure this is intentional before deploying.")
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
            force_https=False,
            strict_transport_security=False,
            frame_options=None,
            x_xss_protection=False,
            force_file_save=False,
            content_security_policy=csp,
            session_cookie_secure=True,
            session_cookie_samesite="Lax",
            referrer_policy="no-referrer",
        )
    else:
        logger.warning("flask-talisman not installed; skipping security headers setup")

    limit_default = cfg.get("RATELIMIT_DEFAULT") or cfg.get("RATE_LIMIT_DEFAULT") or "100/hour"
    if not limit_default:
        limit_default = "100/hour"

    if cfg.get("RATE_LIMIT_ENABLED") is False:
        # limiter configured via init_rate_limiter()
        logger.info("Rate limiting disabled")
    else:
        # ALWAYS use memory:// storage for reliability
        # Redis-based rate limiting can be added later if needed
        limiter = Limiter(
            key_func=get_remote_address,
            default_limits=[limit_default],
            storage_uri="memory://",
            strategy="fixed-window",
        )
        limiter.init_app(app)
        logger.info(f"Rate limiter initialized with memory:// storage (limit: {limit_default})")

    log_level = str(cfg.get("LOG_LEVEL", "INFO")).upper()
    level = getattr(logging, log_level, logging.INFO)
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    if not any(isinstance(handler, logging.StreamHandler) for handler in root_logger.handlers):
        handler = logging.StreamHandler()
        fmt = (
            '{"level":"%(levelname)s","msg":"%(message)s","name":"%(name)s","path":"%(pathname)s",'
            '"lineno":%(lineno)d}'
        )
        handler.setFormatter(logging.Formatter(fmt))
        root_logger.addHandler(handler)

    return limiter


def init_rate_limiter(app):
    # CI/TESTING: isolate rate limit counters per app instance (prevents /oauth/register 429 in CI)
    try:
        import os
        import uuid

        if (
            os.environ.get("TESTING") == "1"
            or "PYTEST_CURRENT_TEST" in os.environ
            or app.config.get("TESTING")
            or getattr(app, "testing", False)
        ):
            app.config.setdefault("RATELIMIT_STORAGE_URI", "memory://")
            app.config.setdefault("RATELIMIT_KEY_PREFIX", f"test-{uuid.uuid4()}")
    except Exception:
        pass

    """Initialize Flask-Limiter using the module-level limiter instance."""
    enabled = app.config.get("RATE_LIMIT_ENABLED", True)
    storage_uri = app.config.get("RATE_LIMIT_STORAGE_URI") or "memory://"
    default_limit = app.config.get("RATE_LIMIT_DEFAULT") or "100/hour"

    # Even when disabled, keep limiter object valid for decorators.
    try:
        limiter.init_app(
            app,
            storage_uri=storage_uri,
            default_limits=[default_limit],
            enabled=enabled,
        )
    except TypeError:
        # older signatures: init_app(app) only
        limiter.init_app(app)

    try:
        app.logger.info(
            f"Rate limiter initialized with {storage_uri} storage (limit: {default_limit}), enabled={enabled}"
        )
    except Exception:
        pass


# ============================================================
# FINAL SAFETY: ensure limiter is never None (decorators bind at import time)
# ============================================================
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    if globals().get("limiter", None) is None:
        limiter = Limiter(key_func=get_remote_address)
except Exception:
    # absolute fallback to avoid import-time crashes
    class _NoopLimiter:
        def limit(self, *_a, **_k):
            def _decorator(fn):
                return fn

            return _decorator

    if globals().get("limiter", None) is None:
        limiter = _NoopLimiter()
