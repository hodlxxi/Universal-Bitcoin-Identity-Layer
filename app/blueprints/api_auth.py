from __future__ import annotations

import base64
import os
import re
import time
import uuid
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request, session, url_for

api_auth_bp = Blueprint("api_auth", __name__)


@api_auth_bp.route("/api/challenge", methods=["POST"])
def api_challenge():
    """
    Factory-owned login challenge endpoint.

    Transitional extraction: this blueprint owns the route, while shared auth
    helpers/state still live in app.app until the next monolith-retirement step.
    """
    from app.auth_api_core import (
        ACTIVE_CHALLENGES,
        AGENT_REQUESTER_PROOF_PURPOSE,
        CHALLENGE_TTL_SECONDS,
        is_valid_pubkey,
        validate_agent_requester_proof_request,
    )

    data = request.get_json() or {}
    user_input = (data.get("pubkey") or "").strip()

    # Accept either:
    # - explicit pubkey in request
    # - OR (if logged in) any label, using session pubkey
    pubkey = user_input
    label = ""

    if not pubkey or not is_valid_pubkey(pubkey):
        spk = (session.get("logged_in_pubkey") or "").strip()
        if spk and is_valid_pubkey(spk):
            label = user_input
            pubkey = spk
        else:
            return jsonify(error="Missing or invalid pubkey"), 400

    purpose = (data.get("purpose") or "login").strip()
    now_utc = datetime.now(timezone.utc)
    cid = str(uuid.uuid4())

    if purpose == AGENT_REQUESTER_PROOF_PURPOSE:
        if data.get("method") != "nostr":
            return jsonify(error="unsupported_method"), 400
        ok, error, canonical_pubkey, request_hash = validate_agent_requester_proof_request(
            pubkey, data.get("request_body")
        )
        if not ok:
            return jsonify(error=error), 400
        challenge = f"HODLXXI:agent-request:{int(time.time())}:{uuid.uuid4().hex[:8]}:{request_hash}"
        ACTIVE_CHALLENGES[cid] = {
            "pubkey": pubkey,
            "canonical_pubkey": canonical_pubkey,
            "requester_pubkey": data["request_body"]["payload"]["requester_pubkey"].strip(),
            "request_hash": request_hash,
            "purpose": purpose,
            "label": label,
            "challenge": challenge,
            "created": now_utc,
            "expires": now_utc + timedelta(seconds=CHALLENGE_TTL_SECONDS),
            "method": "nostr",
        }
        return jsonify(
            ok=True,
            challenge_id=cid,
            challenge=challenge,
            request_hash=request_hash,
            expires_in=CHALLENGE_TTL_SECONDS,
        )

    challenge = f"HODLXXI:login:{int(time.time())}:{uuid.uuid4().hex[:8]}"

    ACTIVE_CHALLENGES[cid] = {
        "pubkey": pubkey,
        "label": label,
        "challenge": challenge,
        "created": now_utc,
        "expires": now_utc + timedelta(minutes=5),
        "method": data.get("method", "api"),
    }

    return jsonify(ok=True, challenge_id=cid, challenge=challenge, expires_in=300)


@api_auth_bp.route("/api/verify", methods=["POST"])
def api_verify():
    """
    Factory-owned login verify endpoint.

    Preserves existing behavior:
    - PSBT Proof-of-Funds compatibility when payload contains `psbt`
    - Nostr login verification
    - legacy Bitcoin message verification
    - session finalization through _finish_login()
    """
    import app.app as legacy_auth
    from app.auth_api_core import (
        ACTIVE_CHALLENGES,
        AGENT_REQUESTER_PROOF_PURPOSE,
        CHALLENGE_TTL_SECONDS,
        is_valid_pubkey,
        mint_access_token,
        verify_nostr_login_event,
    )

    REFRESH_STORE = getattr(legacy_auth, "REFRESH_STORE", None)
    _finish_login = legacy_auth._finish_login
    derive_legacy_address_from_pubkey = legacy_auth.derive_legacy_address_from_pubkey
    get_rpc_connection = legacy_auth.get_rpc_connection
    get_save_and_check_balances_for_pubkey = legacy_auth.get_save_and_check_balances_for_pubkey
    logger = legacy_auth.logger

    data = request.get_json() or {}

    # Transitional compatibility:
    # /api/verify historically also served PSBT Proof-of-Funds verification.
    # Keep that flow working while login/Nostr verification owns /api/verify.
    if data.get("psbt") is not None:
        from app.blueprints.bitcoin import verify_proof_of_funds

        return verify_proof_of_funds()

    cid = (data.get("challenge_id") or "").strip()
    pubkey = (data.get("pubkey") or "").strip()
    signature = (data.get("signature") or "").strip()

    if not pubkey:
        spk = (session.get("logged_in_pubkey") or "").strip()
        if spk and is_valid_pubkey(spk):
            pubkey = spk

    if not cid:
        return jsonify(error="Missing required parameters"), 400

    rec = ACTIVE_CHALLENGES.get(cid)
    if not rec or rec["expires"] < datetime.now(timezone.utc):
        return jsonify(error="Invalid or expired challenge"), 400

    method = rec.get("method", "api")

    # For nostr, pubkey is validated inside nostr event
    if method != "nostr":
        if rec["pubkey"] != pubkey:
            return jsonify(error="Pubkey mismatch"), 400

    # --- Verification depending on method ---
    if method == "nostr":
        nostr_event = data.get("nostr_event")
        if not nostr_event:
            return jsonify(error="Missing nostr_event"), 400

        nostr_expected_pubkey = rec["pubkey"]
        if re.fullmatch(r"[0-9a-fA-F]{66}", nostr_expected_pubkey) and nostr_expected_pubkey[:2].lower() in {
            "02",
            "03",
        }:
            nostr_expected_pubkey = nostr_expected_pubkey[2:]

        logger.warning("NOSTR_STEP=before_verify_nostr_login_event cid=%r", cid)
        ok, error = verify_nostr_login_event(
            nostr_event,
            expected_pubkey=nostr_expected_pubkey,
            expected_challenge=rec["challenge"],
            expected_verify_url=request.url_root.rstrip("/") + url_for("api_auth.api_verify"),
        )
        logger.warning("NOSTR_STEP=after_verify_nostr_login_event cid=%r ok=%r error=%r", cid, ok, error)

        if not ok:
            return jsonify(error=error or "Nostr verification failed"), 403

        if rec.get("purpose") == AGENT_REQUESTER_PROOF_PURPOSE:
            ACTIVE_CHALLENGES.pop(cid, None)
            now_ts = int(time.time())
            expires_at = min(now_ts + CHALLENGE_TTL_SECONDS, int(rec["expires"].timestamp()))
            session[AGENT_REQUESTER_PROOF_PURPOSE] = {
                "pubkey": rec["requester_pubkey"],
                "canonical_pubkey": rec["canonical_pubkey"],
                "request_hash": rec["request_hash"],
                "method": "nostr",
                "verified_at": now_ts,
                "expires_at": expires_at,
                "purpose": AGENT_REQUESTER_PROOF_PURPOSE,
            }
            return jsonify(
                ok=True,
                verified=True,
                purpose=AGENT_REQUESTER_PROOF_PURPOSE,
                pubkey=rec["requester_pubkey"],
                request_hash=rec["request_hash"],
                proof_expires_in=max(0, expires_at - now_ts),
            )

        try:
            in_total, out_total = get_save_and_check_balances_for_pubkey(rec["pubkey"])
            ratio = (out_total / in_total) if in_total > 0 else 0
            access = "full" if ratio >= 1 else "limited"
        except Exception:
            logger.exception("Nostr balance-based access check failed; defaulting to limited")
            access = "limited"

        logger.warning("NOSTR_STEP=before_session_set cid=%r access=%r", cid, access)
        session["logged_in_pubkey"] = rec["pubkey"]
        session["access_level"] = access
        session["login_method"] = "nostr"
        session.pop("guest_label", None)
        session.pop("guestLabel", None)

        logger.warning("NOSTR_STEP=before_pop cid=%r", cid)
        ACTIVE_CHALLENGES.pop(cid, None)

        logger.warning("NOSTR_STEP=before_success_return cid=%r", cid)
        return jsonify(ok=True, verified=True, method="nostr", pubkey=rec["pubkey"], access_level=access)

    elif method == "lightning":
        return jsonify(error=f"Verification method '{method}' not yet supported"), 501

    else:
        if not signature:
            return jsonify(error="Missing required parameters"), 400

        # Default: Bitcoin RPC verification
        try:
            rpc = get_rpc_connection()
            addr = derive_legacy_address_from_pubkey(pubkey)
            ok = rpc.verifymessage(addr, signature, rec["challenge"])
        except Exception:
            return jsonify(error="Signature verification temporarily unavailable"), 500

        if not ok:
            return jsonify(error="Invalid signature"), 403

    # --- Determine access level ---
    try:
        in_total, out_total = get_save_and_check_balances_for_pubkey(pubkey)
        ratio = (out_total / in_total) if in_total > 0 else 0
        access = "full" if ratio >= 1 else "limited"
    except Exception:
        access = "limited"

    access_token = mint_access_token(sub=pubkey, scope="basic")
    refresh_token = None

    if REFRESH_STORE is not None:
        token = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
        REFRESH_STORE[token] = {
            "sub": pubkey,
            "scope": "basic",
            "exp": int(time.time()) + 30 * 24 * 3600,
            "jti": str(uuid.uuid4()),
        }
        refresh_token = token

    ACTIVE_CHALLENGES.pop(cid, None)

    payload = {
        "ok": True,
        "verified": True,
        "token_type": "Bearer",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": 900,
        "pubkey": pubkey,
        "access_level": access,
    }

    resp = jsonify(payload)
    resp = _finish_login(resp, pubkey, access)
    return resp
