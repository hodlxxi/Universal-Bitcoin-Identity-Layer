from __future__ import annotations

from flask import Blueprint, jsonify, session

debug_session_bp = Blueprint("debug_session", __name__)


@debug_session_bp.route("/api/debug/session", methods=["GET"])
def api_debug_session():
    """
    Safe session-compat endpoint used by browser runtime.

    This returns only the current browser session's own public/session metadata.
    It does not expose secrets, cookies, tokens, macaroons, or server config.
    """
    pubkey = (session.get("logged_in_pubkey") or "").strip()
    access_level = (session.get("access_level") or "").strip()
    guest_label = (session.get("guest_label") or "").strip()
    login_method = (session.get("login_method") or "").strip()

    return jsonify(
        ok=True,
        authenticated=bool(pubkey),
        pubkey=pubkey,
        pubkey_tail=pubkey[-8:] if pubkey else "",
        access_level=access_level,
        guest_label=guest_label,
        login_method=login_method,
    )
