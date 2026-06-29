"""Redis runtime contract helpers.

Production must use explicit Redis-backed storage for cache/session/rate-limit
surfaces. Non-production may fall back to memory, but the fallback must be
visible in structured logs.
"""

from __future__ import annotations

import logging
import os
from typing import Mapping

from app.feature_flags import is_production

logger = logging.getLogger(__name__)


def redis_required(config: Mapping[str, object] | None = None) -> bool:
    """Return whether Redis is required for this runtime."""

    return is_production(config)


def has_explicit_redis_config(config: Mapping[str, object] | None = None) -> bool:
    """Return whether Redis was explicitly configured by URL/DSN or host.

    ``get_config()`` supplies localhost defaults for developer convenience, so
    production needs an explicit operator-provided Redis setting instead of an
    accidental default.
    """

    if os.environ.get("REDIS_URL") or os.environ.get("REDIS_DSN") or os.environ.get("REDIS_HOST"):
        return True
    if config is None:
        return False
    return bool(config.get("REDIS_URL") or config.get("REDIS_DSN") or config.get("REDIS_HOST_EXPLICIT"))


def memory_fallback_allowed(config: Mapping[str, object] | None = None) -> bool:
    """Return whether in-memory Redis/cache/rate-limit fallback is allowed."""

    return not redis_required(config)


def log_memory_fallback_warning(surface: str, reason: str) -> None:
    """Emit a structured warning when non-production falls back to memory."""

    logger.warning(
        "redis.memory_fallback",
        extra={
            "event": "redis.memory_fallback",
            "surface": surface,
            "reason": reason,
            "production": False,
        },
    )
