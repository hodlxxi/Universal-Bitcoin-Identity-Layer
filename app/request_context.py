"""Request-scoped context helpers."""

from __future__ import annotations

import re
import uuid

from flask import g, request

_SAFE_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")


def get_or_create_request_id() -> str:
    """
    Resolve a safe request ID for the current request.

    Reuses inbound X-Request-ID when it is structurally safe; otherwise
    generates a fresh UUID4 hex token.
    """
    incoming = (request.headers.get("X-Request-ID") or "").strip()
    if incoming and _SAFE_REQUEST_ID_RE.match(incoming):
        rid = incoming
    else:
        rid = uuid.uuid4().hex
    g.request_id = rid
    return rid
