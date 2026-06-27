"""
LNURL-Auth Blueprint - Lightning Network Authentication

Implements LNURL-auth challenge-response authentication.
"""

import logging
import secrets
import time
from typing import Optional

from coincurve import PublicKey

from flask import Blueprint, current_app, jsonify, request
import bech32

from app.audit_logger import get_audit_logger
from app.db_storage import get_lnurl_challenge, store_lnurl_challenge
from app.security import limiter as _limiter


class _NoopLimiter:
    """Fallback when the rate limiter isn't initialized (e.g., unit tests)."""

    def limit(self, *_args, **_kwargs):
        def _decorator(fn):
            return fn

        return _decorator


limiter = _limiter or _NoopLimiter()

logger = logging.getLogger(__name__)
audit_logger = get_audit_logger()

lnurl_bp = Blueprint("lnurl", __name__)

LNURL_RATE_LIMIT = "20 per minute"


def _audit_verify_failed(session_id: str, reason: str) -> None:
    audit_logger.log_event("lnurl.verify_failed", session_id=session_id, reason=reason, ip=request.remote_addr)


def _decode_k1(k1: str) -> bytes:
    if len(k1) != 64:
        raise ValueError("k1 must be 32 bytes hex")
    try:
        return bytes.fromhex(k1)
    except ValueError as exc:
        raise ValueError("k1 must be hex") from exc


def _decode_signature(sig: str) -> bytes:
    if not sig or len(sig) % 2 != 0:
        raise ValueError("signature must be hex")
    try:
        sig_bytes = bytes.fromhex(sig)
    except ValueError as exc:
        raise ValueError("signature must be hex") from exc
    # DER ECDSA signatures are ASN.1 SEQUENCE values and begin with 0x30.
    # coincurve performs the full DER validation during verify().
    if not sig_bytes or sig_bytes[0] != 0x30:
        raise ValueError("signature must be DER encoded")
    return sig_bytes


def _decode_pubkey(key: str) -> bytes:
    if not key or len(key) % 2 != 0:
        raise ValueError("public key must be hex")
    try:
        key_bytes = bytes.fromhex(key)
    except ValueError as exc:
        raise ValueError("public key must be hex") from exc
    if len(key_bytes) != 33 or key_bytes[0] not in (0x02, 0x03):
        raise ValueError("public key must be a compressed secp256k1 key")
    # Constructor validates that the bytes represent a real secp256k1 point.
    PublicKey(key_bytes)
    return key_bytes


def _verify_lnurl_auth_signature(k1: str, sig: str, key: str) -> tuple[bool, Optional[str]]:
    try:
        k1_bytes = _decode_k1(k1)
    except ValueError:
        return False, "malformed_k1"

    try:
        sig_bytes = _decode_signature(sig)
    except ValueError:
        return False, "malformed_signature"

    try:
        key_bytes = _decode_pubkey(key)
    except ValueError:
        return False, "malformed_pubkey"

    try:
        if not PublicKey(key_bytes).verify(sig_bytes, k1_bytes, hasher=None):
            return False, "signature_invalid"
    except ValueError:
        return False, "malformed_signature"
    except Exception:
        logger.warning("LNURL signature verification failed unexpectedly", exc_info=True)
        return False, "signature_invalid"

    return True, None


@lnurl_bp.route("/create", methods=["POST"])
@limiter.limit(LNURL_RATE_LIMIT)
def create_challenge():
    """
    Create LNURL-auth challenge.

    Returns:
        JSON with session_id, challenge, and lnurl
    """
    try:
        # Generate session ID and challenge
        session_id = secrets.token_urlsafe(32)
        challenge = secrets.token_hex(32)

        # Get base URL from config
        cfg = current_app.config.get("APP_CONFIG", {})
        base_url = cfg.get("LNURL_BASE_URL", "http://localhost:5000")

        # Create LNURL callback URL and params URL
        callback_url = f"{base_url}/api/lnurl-auth/callback/{session_id}"
        params_url = f"{base_url}/api/lnurl-auth/params?session_id={session_id}"

        # Store challenge in database with TTL
        challenge_data = {
            "session_id": session_id,
            "challenge": challenge,
            "created_at": time.time(),
            "verified": False,
            "pubkey": None,
            "k1": challenge,  # LNURL-auth nonce
            "expires_at": (
                __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
                + __import__("datetime").timedelta(seconds=300)
            ).isoformat(),
        }

        store_lnurl_challenge(session_id, challenge_data, ttl=300)
        # 5 minute TTL

        audit_logger.log_event("lnurl.challenge_created", session_id=session_id, ip=request.remote_addr)

        # encode LNURL params endpoint (bech32)
        data = params_url.encode("utf-8")
        five_bit_r = bech32.convertbits(data, 8, 5)
        lnurl_bech32 = bech32.bech32_encode("lnurl", five_bit_r)

        # Return LNURL parameters
        return jsonify(
            {
                "session_id": session_id,
                "challenge": challenge,
                "lnurl": lnurl_bech32,
                "qr_code": lnurl_bech32,  # placeholder for tests
                "k1": challenge,  # k1 is the challenge in LNURL-auth
                "tag": "login",
                "callback_url": callback_url,
                "params_url": params_url,
            }
        )

    except Exception:
        logger.error("LNURL challenge creation failed", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@lnurl_bp.route("/callback/<session_id>", methods=["GET"])
@limiter.limit(LNURL_RATE_LIMIT)
def lnurl_callback(session_id: str):
    """
    LNURL-auth callback endpoint.

    Args:
        session_id: Session identifier

    Query parameters:
        - k1: Challenge (should match stored challenge)
        - sig: Signature over k1
        - key: Public key (hex)

    Returns:
        JSON LNURL response
    """
    k1 = request.args.get("k1")
    sig = request.args.get("sig")
    key = request.args.get("key")

    if not all([k1, sig, key]):
        _audit_verify_failed(session_id, "missing_parameters")
        return jsonify({"status": "ERROR", "reason": "Missing required parameters"}), 400

    try:
        # Retrieve challenge
        challenge_data = get_lnurl_challenge(session_id)

        if not challenge_data:
            _audit_verify_failed(session_id, "invalid_or_expired_session")
            return jsonify({"status": "ERROR", "reason": "Invalid or expired session"}), 404

        # Verify challenge format before comparing so malformed wallet input is explicit.
        try:
            _decode_k1(k1)
        except ValueError:
            _audit_verify_failed(session_id, "malformed_k1")
            return jsonify({"status": "ERROR", "reason": "Malformed k1"}), 400

        # Verify challenge matches
        stored_challenge = challenge_data.get("challenge") or challenge_data.get("k1")

        if not stored_challenge or stored_challenge != k1:
            _audit_verify_failed(session_id, "challenge_mismatch")
            return jsonify({"status": "ERROR", "reason": "Challenge mismatch"}), 403

        verified, failure_reason = _verify_lnurl_auth_signature(k1, sig, key)
        if not verified:
            _audit_verify_failed(session_id, failure_reason or "signature_invalid")
            response_reason = {
                "malformed_k1": "Malformed k1",
                "malformed_signature": "Malformed signature",
                "malformed_pubkey": "Malformed public key",
                "signature_invalid": "Invalid signature",
            }.get(failure_reason, "Invalid signature")
            status_code = 400 if failure_reason and failure_reason.startswith("malformed_") else 403
            return jsonify({"status": "ERROR", "reason": response_reason}), status_code

        # Update challenge as verified only after successful secp256k1 verification.
        challenge_data["verified"] = True
        challenge_data["pubkey"] = key
        challenge_data["verified_at"] = time.time()

        try:
            from app.db_storage import update_lnurl_challenge

            update_lnurl_challenge(session_id, key)
        except Exception as e:
            logger.error("LNURL update failed: %s", e, exc_info=True)
            _audit_verify_failed(session_id, "update_failed")
            return jsonify({"status": "ERROR", "reason": "Failed to update challenge"}), 500

        audit_logger.log_event("lnurl.verify_success", session_id=session_id, pubkey=key, ip=request.remote_addr)

        return jsonify({"status": "OK"})

    except Exception:
        logger.error("LNURL callback failed", exc_info=True)
        return jsonify({"status": "ERROR", "reason": "Internal server error"}), 500


@lnurl_bp.route("/check/<session_id>", methods=["GET"])
@limiter.limit("60 per minute")
def check_verification(session_id: str):
    """
    Check if LNURL-auth challenge has been verified.

    Args:
        session_id: Session identifier

    Returns:
        JSON with verification status
    """
    try:
        challenge_data = get_lnurl_challenge(session_id)

        if not challenge_data:
            return jsonify({"verified": False, "error": "Session not found or expired"}), 404

        return jsonify(
            {
                "verified": challenge_data.get("is_verified", False),
                "pubkey": challenge_data.get("pubkey") if challenge_data.get("is_verified") else None,
            }
        )

    except Exception:
        logger.error("Verification check failed", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@lnurl_bp.route("/params", methods=["GET"])
@limiter.limit(LNURL_RATE_LIMIT)
def lnurl_params():
    """
    Get LNURL-auth parameters for a session.

    Query parameters:
        - session_id: Session identifier

    Returns:
        JSON with LNURL parameters
    """
    session_id = request.args.get("session_id")

    if not session_id:
        return jsonify({"error": "Missing session_id parameter"}), 400

    try:
        challenge_data = get_lnurl_challenge(session_id)

        if not challenge_data:
            return jsonify({"error": "Invalid or expired session"}), 404

        cfg = current_app.config.get("APP_CONFIG", {})
        base_url = cfg.get("LNURL_BASE_URL", "http://localhost:5000")
        callback_url = f"{base_url}/api/lnurl-auth/callback/{session_id}"

        k1 = challenge_data.get("k1") or challenge_data.get("challenge")
        if not k1:
            return jsonify({"error": "Invalid challenge record"}), 500

        return jsonify({"tag": "login", "callback_url": callback_url, "k1": k1, "callback": callback_url})

    except Exception:
        logger.error("LNURL params failed", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@lnurl_bp.route("/status", methods=["GET"])
def lnurl_status_alias():
    session_id = request.args.get("session_id")
    if not session_id:
        return jsonify({"error": "missing session_id"}), 400
    return check_verification(session_id)
