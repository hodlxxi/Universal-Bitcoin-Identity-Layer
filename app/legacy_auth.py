"""Legacy auth-compatible helpers extracted from the monolith for factory runtime use."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Optional

from flask import Blueprint, current_app, jsonify, request, session, url_for

from app.blueprints.bitcoin import verify_proof_of_funds
from app.ubid_membership import on_successful_login
from app.utils import derive_legacy_address_from_pubkey, get_rpc_connection, get_special_users, is_valid_pubkey

logger = logging.getLogger(__name__)

legacy_auth_bp = Blueprint("legacy_auth", __name__)

ACTIVE_CHALLENGES: dict[str, dict] = {}
NOSTR_LOGIN_MAX_AGE_SECONDS = int(os.getenv("NOSTR_LOGIN_MAX_AGE_SECONDS", "300"))
NOSTR_LOGIN_MAX_FUTURE_SKEW_SECONDS = int(os.getenv("NOSTR_LOGIN_MAX_FUTURE_SKEW_SECONDS", "60"))


def _as_bool(value: object, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def mint_access_token(sub: str, scope: str = "basic") -> str:
    token = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
    return f"{sub}.{token}"


def mint_refresh_token(sub: str) -> str:
    token = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    return f"{sub}.{token}"


def get_save_and_check_balances_for_pubkey(pubkey_hex: str) -> tuple[Decimal, Decimal]:
    """Compatibility stub for monolith auth logic.

    The real covenant/descriptor-heavy implementation still lives in the legacy monolith,
    but the auth boundary only needs a conservative fallback here. Tests monkeypatch this.
    """

    return Decimal(0), Decimal(0)


def _nostr_compact_json(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _nostr_event_id(event: dict) -> str:
    payload = [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]]
    return hashlib.sha256(_nostr_compact_json(payload).encode("utf-8")).hexdigest()


def _nostr_get_tag(event: dict, name: str) -> Optional[str]:
    tags = event.get("tags")
    if not isinstance(tags, list):
        return None

    for tag in tags:
        if (
            isinstance(tag, list)
            and len(tag) >= 2
            and isinstance(tag[0], str)
            and isinstance(tag[1], str)
            and tag[0] == name
        ):
            return tag[1]
    return None


def verify_nostr_login_event(
    event: dict,
    *,
    expected_pubkey: str,
    expected_challenge: str,
    expected_verify_url: Optional[str] = None,
    now_ts: Optional[int] = None,
) -> tuple[bool, Optional[str]]:
    if not isinstance(event, dict):
        return False, "Invalid nostr_event"

    required_fields = ("id", "pubkey", "created_at", "kind", "tags", "content", "sig")
    missing = [field for field in required_fields if field not in event]
    if missing:
        return False, f"Missing nostr_event field: {missing[0]}"

    event_pubkey = (event.get("pubkey") or "").strip().lower()
    event_id = (event.get("id") or "").strip().lower()
    event_sig = (event.get("sig") or "").strip().lower()
    expected_pubkey = (expected_pubkey or "").strip().lower()

    if not re.fullmatch(r"[0-9a-f]{64}", event_pubkey):
        return False, "Invalid nostr pubkey"
    if not re.fullmatch(r"[0-9a-f]{64}", event_id):
        return False, "Invalid nostr event id"
    if not re.fullmatch(r"[0-9a-f]{128}", event_sig):
        return False, "Invalid nostr signature"
    if event_pubkey != expected_pubkey:
        return False, "Pubkey mismatch"

    try:
        created_at = int(event.get("created_at"))
    except Exception:
        return False, "Invalid nostr created_at"

    try:
        kind = int(event.get("kind"))
    except Exception:
        return False, "Invalid nostr kind"

    if kind != 22242:
        return False, "Invalid nostr kind"
    if not isinstance(event.get("tags"), list):
        return False, "Invalid nostr tags"
    if not isinstance(event.get("content"), str):
        return False, "Invalid nostr content"

    now_ts = int(now_ts if now_ts is not None else time.time())
    if created_at < now_ts - NOSTR_LOGIN_MAX_AGE_SECONDS:
        return False, "Nostr event is too old"
    if created_at > now_ts + NOSTR_LOGIN_MAX_FUTURE_SKEW_SECONDS:
        return False, "Nostr event is too far in the future"

    challenge_tag = _nostr_get_tag(event, "challenge")
    if not challenge_tag or challenge_tag != expected_challenge:
        return False, "Challenge mismatch"

    url_tag = _nostr_get_tag(event, "u")
    if url_tag and expected_verify_url and url_tag != expected_verify_url:
        return False, "Nostr event URL mismatch"

    normalized_event = dict(event)
    normalized_event["pubkey"] = event_pubkey
    normalized_event["id"] = event_id
    normalized_event["sig"] = event_sig
    normalized_event["created_at"] = created_at
    normalized_event["kind"] = kind

    recomputed_id = _nostr_event_id(normalized_event)
    if recomputed_id != event_id:
        return False, "Nostr event id mismatch"

    try:
        from coincurve import PublicKeyXOnly

        verified = PublicKeyXOnly(bytes.fromhex(event_pubkey)).verify(
            bytes.fromhex(event_sig),
            bytes.fromhex(recomputed_id),
        )
    except Exception as exc:
        logger.error("Nostr login verification error: %s", exc)
        return False, "Nostr signature verification unavailable"

    if not verified:
        return False, "Invalid nostr signature"

    return True, None


def _finish_login(resp, pubkey: str, level: str = "limited"):
    on_successful_login(pubkey)
    session["logged_in_pubkey"] = pubkey
    session["access_level"] = level
    session.permanent = True

    env_name = os.getenv("FLASK_ENV", "development").strip().lower()
    secure_default = env_name == "production"
    secure_cookies = _as_bool(os.getenv("SECURE_COOKIES"), default=secure_default)
    access_cookie_httponly = _as_bool(os.getenv("ACCESS_COOKIE_HTTPONLY"), default=True)
    cookie_samesite = os.getenv("COOKIE_SAMESITE", "Lax")
    at_ttl = int(os.getenv("AT_TTL", "900"))
    rt_ttl = int(os.getenv("RT_TTL", str(30 * 24 * 3600)))

    try:
        at = mint_access_token(sub=pubkey)
        resp.set_cookie(
            "at",
            at,
            max_age=at_ttl,
            secure=secure_cookies,
            httponly=access_cookie_httponly,
            samesite=cookie_samesite,
        )
    except Exception:
        pass

    try:
        rt = mint_refresh_token(sub=pubkey)
        resp.set_cookie(
            "rt",
            rt,
            max_age=rt_ttl,
            secure=secure_cookies,
            httponly=True,
            samesite=cookie_samesite,
        )
    except Exception:
        pass

    return resp


@legacy_auth_bp.route("/api/whoami", methods=["GET"])
def api_whoami():
    pubkey = (session.get("logged_in_pubkey") or "").strip()
    if not pubkey:
        return jsonify(ok=False, error="Not logged in", logged_in=False), 401

    return jsonify(
        ok=True,
        logged_in=True,
        pubkey=pubkey,
        access_level=(session.get("access_level") or "limited").strip(),
        login_method=(session.get("login_method") or "").strip(),
        guest_label=(session.get("guest_label") or "").strip(),
    )


@legacy_auth_bp.route("/api/debug/session", methods=["GET"])
def api_debug_session_alias():
    return api_whoami()


@legacy_auth_bp.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.get_json() or {}

    # Preserve the PSBT proof-of-funds verification contract that also lives at /api/verify.
    if data.get("psbt") is not None:
        return verify_proof_of_funds()

    cid = (data.get("challenge_id") or "").strip()
    pubkey = (data.get("pubkey") or "").strip()
    signature = (data.get("signature") or "").strip()

    if not pubkey:
        session_pubkey = (session.get("logged_in_pubkey") or "").strip()
        if session_pubkey and is_valid_pubkey(session_pubkey):
            pubkey = session_pubkey

    if not cid:
        return jsonify(error="Missing required parameters"), 400

    rec = ACTIVE_CHALLENGES.get(cid)
    if not rec or rec["expires"] < datetime.now(timezone.utc):
        return jsonify(error="Invalid or expired challenge"), 400
    if rec["pubkey"] != pubkey:
        return jsonify(error="Pubkey mismatch"), 400

    method = rec.get("method", "api")
    if method == "nostr":
        nostr_event = data.get("nostr_event")
        if not nostr_event:
            return jsonify(error="Missing nostr_event"), 400

        ok, error = verify_nostr_login_event(
            nostr_event,
            expected_pubkey=pubkey,
            expected_challenge=rec["challenge"],
            expected_verify_url=request.url_root.rstrip("/") + url_for("legacy_auth.api_verify"),
        )
        if not ok:
            return jsonify(error=error or "Nostr verification failed"), 403
    elif method == "lightning":
        return jsonify(error=f"Verification method '{method}' not yet supported"), 501
    else:
        if not signature:
            return jsonify(error="Missing required parameters"), 400
        try:
            rpc = get_rpc_connection()
            addr = derive_legacy_address_from_pubkey(pubkey)
            ok = rpc.verifymessage(addr, signature, rec["challenge"])
        except Exception:
            return jsonify(error="Signature verification temporarily unavailable"), 500

        if not ok:
            return jsonify(error="Invalid signature"), 403

    try:
        in_total, out_total = get_save_and_check_balances_for_pubkey(pubkey)
        ratio = (out_total / in_total) if in_total > 0 else 0
        access = "full" if ratio >= 1 else "limited"
    except Exception:
        access = "limited"

    access_token = mint_access_token(sub=pubkey, scope="basic")
    ACTIVE_CHALLENGES.pop(cid, None)

    payload = {
        "ok": True,
        "verified": True,
        "token_type": "Bearer",
        "access_token": access_token,
        "refresh_token": None,
        "expires_in": 900,
        "pubkey": pubkey,
        "access_level": access,
    }
    resp = jsonify(payload)
    return _finish_login(resp, pubkey, access)


@legacy_auth_bp.route("/api/playground/pof/verify", methods=["POST", "OPTIONS"])
def api_playground_pof_verify():
    return api_verify()


@legacy_auth_bp.route("/api/playground/pof/challenge", methods=["POST", "OPTIONS"])
def api_playground_pof_challenge():
    view = current_app.view_functions.get("bitcoin.create_pof_challenge")
    if view is None:
        return jsonify(error="challenge endpoint unavailable"), 503
    return view()


@legacy_auth_bp.route("/special_login", methods=["POST"])
def special_login():
    data = request.get_json(silent=True) or {}
    signature = (data.get("signature") or "").strip()

    if not signature:
        return jsonify(error="Signature required", verified=False), 400

    rpc = get_rpc_connection()
    challenge = session.get("challenge")
    if not challenge:
        return jsonify(error="No active challenge", verified=False), 400

    for pubkey in get_special_users():
        try:
            addr = derive_legacy_address_from_pubkey(pubkey)
            if rpc.verifymessage(addr, signature, challenge):
                payload = {"verified": True, "pubkey": pubkey, "access_level": "special"}
                resp = jsonify(payload)
                return _finish_login(resp, pubkey, "special")
        except Exception:
            continue

    return jsonify(error="Invalid signature for all special users", verified=False), 403


__all__ = [
    "ACTIVE_CHALLENGES",
    "NOSTR_LOGIN_MAX_AGE_SECONDS",
    "NOSTR_LOGIN_MAX_FUTURE_SKEW_SECONDS",
    "_finish_login",
    "_nostr_event_id",
    "api_verify",
    "api_whoami",
    "get_rpc_connection",
    "get_save_and_check_balances_for_pubkey",
    "legacy_auth_bp",
    "mint_access_token",
    "special_login",
    "verify_nostr_login_event",
]
