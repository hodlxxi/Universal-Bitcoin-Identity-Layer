"""Security helpers for configuring Flask in production."""

from __future__ import annotations

import logging
import os
from typing import Any, Mapping, Optional

import redis
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from app.redis_contract import log_memory_fallback_warning, redis_required

try:  # pragma: no cover - optional dependency
    from flask_talisman import Talisman  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - fallback for tests
    Talisman = None  # type: ignore


logger = logging.getLogger(__name__)

REDIS_BACKED_RATE_LIMIT_SCHEMES = ("redis://", "rediss://", "unix://")


def _is_redis_backed_storage_uri(storage_uri: object) -> bool:
    return isinstance(storage_uri, str) and storage_uri.startswith(REDIS_BACKED_RATE_LIMIT_SCHEMES)


def _redact_uri_for_log(uri: str | None) -> str:
    """Redact credentials from connection/storage URIs before logging."""
    if not uri:
        return ""
    raw = str(uri)
    try:
        from urllib.parse import urlsplit, urlunsplit

        parts = urlsplit(raw)
        if not parts.netloc:
            return raw

        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""

        if parts.username or "@" in parts.netloc:
            user = parts.username or "user"
            netloc = f"{user}:<redacted>@{host}{port}"
        else:
            netloc = parts.netloc

        return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    except Exception:
        if "://" in raw and "@" in raw:
            scheme, rest = raw.split("://", 1)
            return f"{scheme}://<redacted>@{rest.split('@', 1)[1]}"
        return raw


limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")


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


def _validate_rate_limit_storage(storage_uri: str, cfg: Mapping[str, Any]) -> str:
    """Return a safe rate-limit storage URI or fail closed in production."""

    if storage_uri == "memory://":
        if redis_required(cfg):
            raise RuntimeError("Redis-backed rate limiting is required in production")
        log_memory_fallback_warning("rate_limit", "missing_storage_uri")
        return storage_uri

    if storage_uri.startswith(("redis://", "rediss://", "unix://")):
        try:
            client = redis.from_url(storage_uri, socket_connect_timeout=5, socket_timeout=5)
            client.ping()
            client.close()
        except Exception as exc:
            if redis_required(cfg):
                raise RuntimeError(
                    "Redis-backed rate limiting is required in production but Redis ping failed"
                ) from exc
            log_memory_fallback_warning("rate_limit", exc.__class__.__name__)
            return "memory://"

    return storage_uri


def init_security(app: Flask, cfg: Mapping[str, Any]) -> Optional[Limiter]:
    """Initialise standard security middleware and rate limiting."""
    global limiter

    # Respect reverse proxy headers for TLS detection and client IP extraction.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)  # type: ignore[assignment]

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
        hsts_enabled = bool(force_https)
        Talisman(
            app,
            force_https=force_https,
            strict_transport_security=hsts_enabled,
            strict_transport_security_preload=hsts_enabled,
            strict_transport_security_include_subdomains=hsts_enabled,
            strict_transport_security_max_age=31536000 if hsts_enabled else 0,
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
        storage_uri = os.getenv("RATELIMIT_STORAGE_URL") or os.getenv("REDIS_URL") or "memory://"
        logger.info("Rate limiting disabled")
    else:
        # Validate storage before binding Flask-Limiter so production cannot
        # silently downgrade to in-memory rate-limit state.
        try:
            storage_uri = os.getenv("RATELIMIT_STORAGE_URL") or os.getenv("REDIS_URL") or "memory://"
            storage_uri = _validate_rate_limit_storage(storage_uri, cfg)
            app.config["RATELIMIT_STORAGE_URI"] = storage_uri
            app.config["RATE_LIMIT_STORAGE_URI"] = storage_uri
            app.config["RATELIMIT_DEFAULT"] = limit_default
            app.config["RATE_LIMIT_DEFAULT"] = limit_default
            limiter.init_app(
                app,
                default_limits=[limit_default],
                storage_uri=storage_uri,
                strategy="fixed-window",
            )
        except TypeError as exc:
            # Flask-Limiter 2.x accepted init_app(app) only.  The retry is
            # safe in production only after Redis-backed storage has been
            # validated and written into both legacy and current config keys.
            configured_storage = (
                app.config.get("RATELIMIT_STORAGE_URI") or app.config.get("RATE_LIMIT_STORAGE_URI") or ""
            )
            if redis_required(cfg) and not _is_redis_backed_storage_uri(configured_storage):
                raise RuntimeError("Rate limiter initialization failed in production") from exc
            limiter.init_app(app)
        # HODLXXI_EXEMPT_STATUS_V2
        # Screensaver polls /api/public/status; exempt it from Flask-Limiter defaults.
        try:
            vf = app.view_functions.get("api_public_status")
            if vf is not None and hasattr(limiter, "exempt"):
                limiter.exempt(vf)
                logger.info("✅ Exempted /api/public/status from Flask-Limiter defaults")
        except Exception:
            pass

    logger.info(f"Rate limiter initialized with {_redact_uri_for_log(storage_uri)} storage (limit: {limit_default})")

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
    storage_uri = (
        app.config.get("RATE_LIMIT_STORAGE_URI")
        or os.getenv("RATELIMIT_STORAGE_URL")
        or os.getenv("REDIS_URL")
        or "memory://"
    )
    storage_uri = _validate_rate_limit_storage(storage_uri, app.config)
    default_limit = app.config.get("RATE_LIMIT_DEFAULT") or "100/hour"

    app.config["RATELIMIT_STORAGE_URI"] = storage_uri
    app.config["RATE_LIMIT_STORAGE_URI"] = storage_uri
    app.config["RATELIMIT_DEFAULT"] = default_limit
    app.config["RATE_LIMIT_DEFAULT"] = default_limit

    # Even when disabled, keep limiter object valid for decorators.
    try:
        limiter.init_app(
            app,
            storage_uri=storage_uri,
            default_limits=[default_limit],
            enabled=enabled,
        )
    except TypeError as exc:
        # older signatures: init_app(app) only; production can use this only
        # after validated Redis storage has been committed to app.config.
        configured_storage = app.config.get("RATELIMIT_STORAGE_URI") or app.config.get("RATE_LIMIT_STORAGE_URI") or ""
        if redis_required(app.config) and not _is_redis_backed_storage_uri(configured_storage):
            raise RuntimeError("Rate limiter initialization failed in production") from exc
        limiter.init_app(app)

    try:
        app.logger.info(
            f"Rate limiter initialized with {_redact_uri_for_log(storage_uri)} storage (limit: {default_limit}), enabled={enabled}"
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
        limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")
except Exception:
    # absolute fallback to avoid import-time crashes
    class _NoopLimiter:
        def limit(self, *_a, **_k):
            def _decorator(fn):
                return fn

            return _decorator

    if globals().get("limiter", None) is None:
        limiter = _NoopLimiter()
