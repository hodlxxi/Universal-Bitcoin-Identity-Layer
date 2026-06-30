"""Read-only QR Pointer v0 landing surface."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Blueprint, abort, render_template_string

qr_pointer_bp = Blueprint("qr_pointer", __name__)

POINTER_REGISTRY_DIR = Path(__file__).resolve().parents[2] / "data" / "qr_pointers"
_ALLOWED_EXACT_TARGETS = {
    "/.well-known/agent.json",
    "/.well-known/hodlxxi-operator.json",
    "/agent/discovery",
    "/agent/capabilities",
}
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_VERIFY_TARGET_RE = re.compile(r"^/agent/verify/[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SECRET_FIELD_RE = re.compile(
    r"(secret|access[_-]?token|refresh[_-]?token|password|passwd|private[_-]?key|macaroon|cookie|credential)",
    re.I,
)
_ALLOWED_STATUSES = {"active", "revoked", "expired"}
_TERMINAL_STATUSES = {"revoked", "expired"}


def is_allowed_qr_target(target: object) -> bool:
    """Return True only for bounded local QR Pointer targets."""
    if not isinstance(target, str) or not target:
        return False
    if "?" in target or "#" in target:
        return False
    if target.startswith(("http://", "https://", "//")):
        return False
    if target in _ALLOWED_EXACT_TARGETS:
        return True
    return bool(_VERIFY_TARGET_RE.fullmatch(target)) and "/../" not in target and "/./" not in target


def _has_secret_like_field(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or _SECRET_FIELD_RE.search(key):
                return True
            if _has_secret_like_field(child):
                return True
    elif isinstance(value, list):
        return any(_has_secret_like_field(item) for item in value)
    return False


def _parse_expires_at(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = f"{candidate[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def pointer_record_status(record: dict) -> str:
    """Return the effective static pointer status without mutating the record."""
    status = record.get("status")
    if status in _TERMINAL_STATUSES:
        return status
    expires_at = _parse_expires_at(record.get("expires_at"))
    if expires_at is not None and expires_at <= datetime.now(timezone.utc):
        return "expired"
    return "active"


def load_pointer_record(token: str) -> dict | None:
    """Load a static QR Pointer record, failing closed for invalid fixtures."""
    if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
        return None
    path = POINTER_REGISTRY_DIR / f"{token}.json"
    try:
        raw = path.read_text(encoding="utf-8")
        record = json.loads(raw)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(record, dict):
        return None
    if _has_secret_like_field(record):
        return None
    if record.get("token") != token:
        return None
    if record.get("status") not in _ALLOWED_STATUSES:
        return None
    if not is_allowed_qr_target(record.get("target")):
        return None
    return record


_LANDING_TEMPLATE = """
<!doctype html>
<title>HODLXXI QR Pointer</title>
<h1>HODLXXI QR Pointer</h1>
<p>This QR Pointer only links to a discovery or verification surface.</p>
<p><strong>Discovery-only warning:</strong> QR possession is not authority. This page is not a receipt, verification result, trust proof, payment proof, job authority, delegation, approval, reputation, or human approval.</p>
{% if target %}<p>Target: <a href="{{ target }}" rel="nofollow noopener">{{ target }}</a></p>{% endif %}
<p>The target endpoint, not this QR code, performs any receipt verification.</p>
"""


@qr_pointer_bp.get("/qr/<token>")
def qr_pointer_landing(token: str):
    record = load_pointer_record(token)
    if record is None:
        abort(404)
    status = pointer_record_status(record)
    if status in _TERMINAL_STATUSES:
        return render_template_string(_LANDING_TEMPLATE, target=None), 410
    return render_template_string(_LANDING_TEMPLATE, target=record["target"])
