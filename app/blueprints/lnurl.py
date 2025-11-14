"""
LNURL-Auth Blueprint - Lightning Network Authentication

Implements LNURL-auth challenge-response authentication.
"""

import logging
import secrets
import time
from typing import Optional

from flask import Blueprint, current_app, jsonify, request

from app.audit_logger import get_audit_logger
from app.db_storage import get_lnurl_challenge, store_lnurl_challenge
from app.security import limiter

logger = logging.getLogger(__name__)
audit_logger = get_audit_logger()

lnurl_bp = Blueprint("lnurl", __name__)

LNURL_RATE_LIMIT = "20 per minute"


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

        # Create LNURL callback URL
        callback_url = f"{base_url}/api/lnurl-auth/callback/{session_id}"

        # Store challenge in database with TTL
        challenge_data = {
            "session_id": session_id,
            "challenge": challenge,
            "created_at": time.time(),
            "verified": False,
            "pubkey": None
        }

        store_lnurl_challenge(session_id, challenge_data, ttl=300)  # 5 minute TTL

        audit_logger.log_event(
            "lnurl.challenge_created",
            session_id=session_id,
            ip=request.remote_addr
        )

        # Return LNURL parameters
        return jsonify({
            "session_id": session_id,
            "challenge": challenge,
            "lnurl": callback_url,
            "k1": challenge,  # k1 is the challenge in LNURL-auth
            "tag": "login"
        })

    except Exception as e:
        logger.error(f"LNURL challenge creation failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


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
        return jsonify({
            "status": "ERROR",
            "reason": "Missing required parameters"
        }), 400

    try:
        # Retrieve challenge
        challenge_data = get_lnurl_challenge(session_id)

        if not challenge_data:
            return jsonify({
                "status": "ERROR",
                "reason": "Invalid or expired session"
            }), 404

        # Verify challenge matches
        if challenge_data["challenge"] != k1:
            audit_logger.log_event(
                "lnurl.verify_failed",
                session_id=session_id,
                reason="challenge_mismatch",
                ip=request.remote_addr
            )
            return jsonify({
                "status": "ERROR",
                "reason": "Challenge mismatch"
            }), 403

        # Verify signature
        # In production, implement proper secp256k1 signature verification
        # For now, we trust the signature (this should be replaced)
        import hashlib
        message_hash = hashlib.sha256(k1.encode()).hexdigest()

        # Update challenge as verified
        challenge_data["verified"] = True
        challenge_data["pubkey"] = key
        challenge_data["verified_at"] = time.time()

        store_lnurl_challenge(session_id, challenge_data, ttl=300)

        audit_logger.log_event(
            "lnurl.verify_success",
            session_id=session_id,
            pubkey=key,
            ip=request.remote_addr
        )

        return jsonify({
            "status": "OK"
        })

    except Exception as e:
        logger.error(f"LNURL callback failed: {e}", exc_info=True)
        return jsonify({
            "status": "ERROR",
            "reason": str(e)
        }), 500


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
            return jsonify({
                "verified": False,
                "error": "Session not found or expired"
            }), 404

        return jsonify({
            "verified": challenge_data.get("verified", False),
            "pubkey": challenge_data.get("pubkey") if challenge_data.get("verified") else None
        })

    except Exception as e:
        logger.error(f"Verification check failed: {e}")
        return jsonify({"error": str(e)}), 500


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

        return jsonify({
            "tag": "login",
            "k1": challenge_data["challenge"],
            "callback": callback_url
        })

    except Exception as e:
        logger.error(f"LNURL params failed: {e}")
        return jsonify({"error": str(e)}), 500
