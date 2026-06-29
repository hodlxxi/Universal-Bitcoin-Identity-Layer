"""Small helpers for explicit runtime feature gates."""

from __future__ import annotations

import os
from typing import Mapping

_TRUE_VALUES = {"1", "true", "yes", "on"}


def config_flag(name: str, config: Mapping[str, object] | None = None, default: bool = False) -> bool:
    """Return True only for explicit boolean true values.

    Environment values take precedence over Flask config values. Accepted true
    values are intentionally narrow: "1", "true", "yes", and "on".
    Everything else, including unset, is false unless ``default`` is true.
    """

    value = os.environ.get(name)
    if value is None and config is not None:
        value = config.get(name)  # type: ignore[arg-type]
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in _TRUE_VALUES


def is_production(config: Mapping[str, object] | None = None) -> bool:
    """Return whether the current Flask/runtime environment is production."""

    value = os.environ.get("FLASK_ENV")
    if value is None and config is not None:
        value = config.get("ENV") or config.get("FLASK_ENV")  # type: ignore[arg-type]
    return str(value or "").strip().lower() == "production"


def production_closed_flag(name: str, config: Mapping[str, object] | None = None) -> bool:
    """Feature flag defaulting closed in production and open in non-production."""

    return config_flag(name, config, default=not is_production(config))
