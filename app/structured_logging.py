"""Lightweight structured logging helpers for request/job/invoice tracing."""

from __future__ import annotations

import json
import logging
from typing import Any

from flask import g, has_request_context, request, session


def _pubkey_tail(value: str | None) -> str | None:
    text = (value or "").strip()
    if len(text) < 6:
        return text or None
    return text[-6:]


def _request_fields() -> dict[str, Any]:
    if not has_request_context():
        return {}

    request_id = getattr(g, "request_id", None)
    actor_pubkey = session.get("logged_in_pubkey") if session else None
    actor_type = session.get("access_level") if session else None

    fields: dict[str, Any] = {
        "request_id": request_id,
        "path": getattr(request, "path", None),
        "method": getattr(request, "method", None),
        "user_pubkey_tail": _pubkey_tail(actor_pubkey),
        "actor_type": actor_type,
    }
    return {key: value for key, value in fields.items() if value not in (None, "")}


def _safe_fields(extra: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in extra.items():
        if value is None:
            continue
        if key in {"payment_request", "authorization", "auth", "macaroon", "headers"}:
            continue
        if isinstance(value, (dict, list, tuple)):
            safe[key] = value
        else:
            safe[key] = str(value) if not isinstance(value, (int, float, bool)) else value
    return safe


def log_event(logger: logging.Logger, event: str, level: int = logging.INFO, **fields: Any) -> None:
    """Emit a compact JSON log event without depending on an external stack."""
    payload = {"event": event}
    payload.update(_request_fields())
    payload.update(_safe_fields(fields))
    logger.log(level, json.dumps(payload, sort_keys=True, default=str))
