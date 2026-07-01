"""Safe QR pointer landing pages.

The QR pointer surface is intentionally discovery-only. It renders a bounded,
non-redirecting landing page for static QR pointer fixtures and never mutates
jobs, issues receipts, or calls receipt verification automatically.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from html import escape
from importlib import resources
from typing import Any
from urllib.parse import urlsplit

from flask import Blueprint, abort, render_template_string

qr_pointer_bp = Blueprint("qr_pointer", __name__)

_ALLOWED_STATIC_TARGETS = {
    "/.well-known/agent.json",
    "/agent/capabilities",
    "/agent/discovery",
}
_ALLOWED_STATUSES = {"active", "revoked", "expired"}
_SECRET_LIKE_KEYS = {
    "api_key",
    "mnemonic",
    "password",
    "private_key",
    "privkey",
    "secret",
    "seed",
    "wif",
    "xprv",
}
_JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

_LANDING_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HODLXXI QR Pointer</title>
</head>
<body>
  <main>
    <h1>{{ label }}</h1>
    <p><strong>Status:</strong> {{ status }}</p>
    <p>
      This QR page is a discovery-only safety landing page. It does not redirect
      automatically, mutate jobs, issue receipts, or call verification endpoints.
    </p>
    {% if active %}
      <p>Review the target before opening it:</p>
      <p><code>{{ target }}</code></p>
      <p><a href="{{ target }}" rel="nofollow noopener">Open target manually</a></p>
    {% else %}
      <p>This QR pointer is no longer active. No target was opened.</p>
    {% endif %}
  </main>
</body>
</html>
"""


def _contains_secret_like_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            lowered = str(key).lower()
            if any(secret_key in lowered for secret_key in _SECRET_LIKE_KEYS):
                return True
            if _contains_secret_like_key(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_secret_like_key(item) for item in value)
    return False


def is_allowed_qr_target(target: object) -> bool:
    """Return whether a QR target is a bounded local discovery URL."""
    if not isinstance(target, str) or not target.startswith("/"):
        return False
    if target.startswith("//"):
        return False

    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        return False
    if ".." in parsed.path.split("/"):
        return False
    if target in _ALLOWED_STATIC_TARGETS:
        return True

    prefix = "/agent/verify/"
    if not target.startswith(prefix):
        return False
    job_id = target[len(prefix) :]
    return "/" not in job_id and bool(_JOB_ID_RE.fullmatch(job_id))


def _normalize_pointer(token: str, value: Any) -> dict[str, str] | None:
    if not isinstance(value, dict):
        return None
    if _contains_secret_like_key(value):
        return None
    if value.get("token") != token:
        return None
    status = value.get("status")
    target = value.get("target")
    if status not in _ALLOWED_STATUSES or not is_allowed_qr_target(target):
        return None
    label = value.get("label")
    if not isinstance(label, str) or not label.strip():
        label = "HODLXXI QR Pointer"
    return {"label": label.strip(), "status": status, "target": target}


@lru_cache(maxsize=1)
def load_qr_pointers() -> dict[str, dict[str, str]]:
    """Load static QR pointer fixtures, failing closed on malformed data."""
    try:
        raw = resources.files(__package__).joinpath("qr_pointers.json").read_text()
        decoded = json.loads(raw)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return {}

    if not isinstance(decoded, dict) or _contains_secret_like_key(decoded):
        return {}

    pointers: dict[str, dict[str, str]] = {}
    for token, value in decoded.items():
        if not isinstance(token, str) or not token:
            continue
        normalized = _normalize_pointer(token, value)
        if normalized is not None:
            pointers[token] = normalized
    return pointers


@qr_pointer_bp.get("/qr/<token>")
def qr_pointer_landing(token: str):
    pointer = load_qr_pointers().get(token)
    if pointer is None:
        abort(404)

    active = pointer["status"] == "active"
    status_code = 200 if active else 410
    html = render_template_string(
        _LANDING_TEMPLATE,
        active=active,
        label=escape(pointer["label"]),
        status=escape(pointer["status"]),
        target=escape(pointer["target"]),
    )
    return html, status_code
