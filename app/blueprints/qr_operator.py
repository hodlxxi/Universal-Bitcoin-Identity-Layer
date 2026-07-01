"""Full-user QR Operator Console.

This surface is read-only and discovery-only. QR pointers are displayed for
operator inspection, but QR remains non-authoritative and never mutates runtime
state.
"""

from __future__ import annotations

from typing import Any

from flask import Blueprint, abort, jsonify, render_template, request, session

from app.blueprints.qr_pointer import is_allowed_qr_target, load_qr_pointers

qr_operator_bp = Blueprint("qr_operator", __name__)


def _current_pubkey() -> str:
    return str(session.get("logged_in_pubkey") or "").strip()


def _current_access_level() -> str:
    return str(session.get("access_level") or "").strip().lower()


def _pubkey_tail(pubkey: str) -> str:
    return pubkey[-4:] if pubkey else ""


def _require_full_user() -> tuple[str, str]:
    pubkey = _current_pubkey()
    access_level = _current_access_level()
    if not pubkey:
        abort(401)
    if access_level != "full":
        abort(403)
    return pubkey, access_level


def _origin() -> str:
    return request.host_url.rstrip("/")


def _normalize_pointer(token: str, pointer: dict[str, Any]) -> dict[str, Any]:
    status = str(pointer.get("status") or "")
    target = str(pointer.get("target") or "")
    return {
        "token": token,
        "status": status,
        "target": target,
        "qr_url": f"{_origin()}/qr/{token}",
        "is_active": status == "active",
        "is_revoked": status == "revoked",
        "is_expired": status == "expired",
        "safe_local_target": is_allowed_qr_target(target),
    }


def _normalized_pointers() -> list[dict[str, Any]]:
    return [_normalize_pointer(token, pointer) for token, pointer in sorted(load_qr_pointers().items())]


@qr_operator_bp.get("/operator/qr")
def qr_operator_console():
    pubkey, access_level = _require_full_user()
    return render_template(
        "qr_operator_console.html",
        access_level=access_level,
        user_pubkey_tail=_pubkey_tail(pubkey),
        pointers=_normalized_pointers(),
    )


@qr_operator_bp.get("/api/operator/qr/pointers")
def qr_operator_pointers_api():
    pubkey, access_level = _require_full_user()
    return jsonify(
        {
            "ok": True,
            "access_level": access_level,
            "user_pubkey_tail": _pubkey_tail(pubkey),
            "pointers": _normalized_pointers(),
        }
    )
