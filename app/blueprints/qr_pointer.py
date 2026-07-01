"""Read-only QR Pointer landing surface backed by checked-in fixtures."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from flask import Blueprint, abort, current_app, render_template

qr_pointer_bp = Blueprint("qr_pointer", __name__)

TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{8,80}$")
DISCOVERY_ONLY_WARNING = (
    "This QR Pointer is discovery-only. It does not prove identity, consent, approval, "
    "delegation, authorization, payment, receipt validity, reputation, trust, or human presence."
)
ALLOWED_TARGETS = {
    "/.well-known/agent.json",
    "/.well-known/hodlxxi-operator.json",
    "/agent/discovery",
    "/agent/capabilities",
}
FORBIDDEN_TARGETS = {
    "/agent/request",
    "/.well-known/agent-delegation.json",
    "/agent/delegations",
    "/agent/policy",
}
SECRET_LIKE_KEYS = {
    "secret",
    "token_secret",
    "private_key",
    "privkey",
    "password",
    "cookie",
    "macaroon",
    "credential",
    "credentials",
    "invoice",
    "payment_request",
    "approval_token",
    "delegation_secret",
}
SAFE_ISSUER_KEYS = {"name", "url", "contact", "pubkey", "note"}


def _registry_dir() -> Path:
    return Path(current_app.root_path) / "data" / "qr_pointers"


def token_is_valid(token: str) -> bool:
    return bool(TOKEN_RE.fullmatch(token or ""))


def validate_target_path(target: str) -> bool:
    if not isinstance(target, str) or not target.startswith("/"):
        return False
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or target.startswith("//"):
        return False
    if ".." in parsed.path.split("/"):
        return False
    if parsed.path in FORBIDDEN_TARGETS:
        return False
    if parsed.path.startswith("/agent/request") or parsed.path.startswith("/agent/delegations"):
        return False
    return target in ALLOWED_TARGETS


def _contains_secret_like_field(value) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in SECRET_LIKE_KEYS or "secret" in normalized or "password" in normalized:
                return True
            if _contains_secret_like_field(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_secret_like_field(item) for item in value)
    return False


def _safe_issuer(record: dict) -> dict:
    issuer = record.get("issuer")
    if not isinstance(issuer, dict):
        return {}
    return {key: str(value) for key, value in issuer.items() if key in SAFE_ISSUER_KEYS and value is not None}


def load_pointer_record(token: str) -> dict | None:
    if not token_is_valid(token):
        return None
    path = _registry_dir() / f"{token}.json"
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError:
        return None
    if _registry_dir().resolve() not in resolved.parents:
        return None
    with resolved.open("r", encoding="utf-8") as handle:
        record = json.load(handle)
    if record.get("token") != token:
        return None
    if _contains_secret_like_field(record):
        return None
    target = record.get("target")
    if not validate_target_path(target):
        return None
    return record


def _effective_status(record: dict) -> str:
    status = str(record.get("status", "")).lower()
    expires_at = record.get("expires_at")
    if expires_at:
        try:
            expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            if expiry <= datetime.now(timezone.utc):
                return "expired"
        except ValueError:
            return "expired"
    if status in {"active", "revoked", "expired"}:
        return status
    return "revoked"


@qr_pointer_bp.get("/qr/<token>")
def qr_pointer_landing(token: str):
    record = load_pointer_record(token)
    if record is None:
        abort(404)
    status = _effective_status(record)
    http_status = 200 if status == "active" else 410
    return (
        render_template(
            "qr_pointer_landing.html",
            token=token,
            status=status,
            target=record["target"],
            issuer=_safe_issuer(record),
            warning=DISCOVERY_ONLY_WARNING,
        ),
        http_status,
        {"Cache-Control": "public, max-age=300"},
    )
