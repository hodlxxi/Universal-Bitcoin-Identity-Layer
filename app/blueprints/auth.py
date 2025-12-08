"""
Authentication Blueprint - Login, Logout, and Signature Verification

Handles Bitcoin signature-based authentication and session management.
"""

import logging
import re
import time
from typing import Optional

from flask import Blueprint, current_app, jsonify, redirect, request, session, url_for

from app import utils
from app.audit_logger import get_audit_logger
from app.security import limiter

logger = logging.getLogger(__name__)
audit_logger = get_audit_logger()

auth_bp = Blueprint("auth", __name__)

# Rate limiting decorators
VERIFY_RATE_LIMIT = "10 per minute"
LOGIN_RATE_LIMIT = "20 per minute"


@auth_bp.route("/logout")
def logout():
    """
    Clear user session and redirect to login.

    Returns:
        Redirect to login page
    """
    pubkey = session.get("logged_in_pubkey")
    if pubkey:
        audit_logger.log_event(
            "auth.logout",
            pubkey=pubkey,
            ip=request.remote_addr
        )

    session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/verify_signature", methods=["POST"])
@limiter.limit(VERIFY_RATE_LIMIT)
def verify_signature():
    """
    Verify Bitcoin signature for authentication.

    Expected JSON body:
        - pubkey: Hex-encoded public key (optional, will try SPECIAL_USERS if omitted)
        - signature: Bitcoin signature
        - challenge: Challenge string from session

    Returns:
        JSON with verification result and access level
    """
    data = request.get_json()
    pubkey_hex = (data.get("pubkey") or "").strip()
    signature = (data.get("signature") or "").strip()
    challenge = (data.get("challenge") or "").strip()

    # Validate challenge
    if "challenge" not in session or session["challenge"] != challenge:
        audit_logger.log_event(
            "auth.verify_failed",
            reason="invalid_challenge",
            ip=request.remote_addr
        )
        return jsonify({
            "verified": False,
            "error": "Invalid or expired challenge"
        }), 400

    # Check challenge timestamp (10 minute expiry)
    challenge_age = time.time() - session.get("challenge_timestamp", 0)
    if challenge_age > 600:
        audit_logger.log_event(
            "auth.verify_failed",
            reason="challenge_expired",
            ip=request.remote_addr
        )
        return jsonify({
            "verified": False,
            "error": "Challenge expired (10 minute limit)"
        }), 400

    # Validate signature presence
    if not signature:
        return jsonify({
            "verified": False,
            "error": "Signature is required"
        }), 400

    # Get RPC connection for signature verification
    try:
        rpc_conn = utils.get_rpc_connection()
    except Exception as e:
        logger.error(f"RPC connection failed: {e}")
        return jsonify({
            "verified": False,
            "error": "Authentication service temporarily unavailable"
        }), 503

    matched_pubkey: Optional[str] = None

    # Case 1: Specific pubkey provided
    if pubkey_hex:
        if not re.fullmatch(r"[0-9a-fA-F]{66}", pubkey_hex):
            return jsonify({
                "verified": False,
                "error": "Public key must be 66 hex characters"
            }), 400

        try:
            derived_addr = utils.derive_legacy_address_from_pubkey(pubkey_hex)
            if rpc_conn.verifymessage(derived_addr, signature, challenge):
                matched_pubkey = pubkey_hex
            else:
                audit_logger.log_event(
                    "auth.verify_failed",
                    reason="invalid_signature",
                    pubkey=pubkey_hex,
                    ip=request.remote_addr
                )
                return jsonify({
                    "verified": False,
                    "error": "Invalid signature"
                }), 403
        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            return jsonify({
                "verified": False,
                "error": str(e)
            }), 500

    # Case 2: No pubkey, try SPECIAL_USERS
    else:
        special_users = utils.get_special_users()
        for candidate in special_users:
            try:
                derived_addr = utils.derive_legacy_address_from_pubkey(candidate)
                if rpc_conn.verifymessage(derived_addr, signature, challenge):
                    matched_pubkey = candidate
                    break
            except Exception:
                continue

        if not matched_pubkey:
            audit_logger.log_event(
                "auth.verify_failed",
                reason="no_matching_special_user",
                ip=request.remote_addr
            )
            return jsonify({
                "verified": False,
                "error": "Invalid signature"
            }), 403

    # Determine access level
    if not pubkey_hex:  # Matched a special user
        access_level = "full"
    else:
        # Could implement balance-based access levels here
        # For now, grant limited access
        access_level = "limited"

    # Set session
    session["logged_in_pubkey"] = matched_pubkey
    session["access_level"] = access_level
    session.permanent = True

    # Audit log successful authentication
    audit_logger.log_event(
        "auth.verify_success",
        pubkey=matched_pubkey,
        access_level=access_level,
        ip=request.remote_addr
    )

    logger.info(
        f"Successful authentication: pubkey={matched_pubkey}, "
        f"access_level={access_level}"
    )

    return jsonify({
        "verified": True,
        "access_level": access_level,
        "pubkey": matched_pubkey
    })


@auth_bp.route("/guest_login", methods=["POST"])
@limiter.limit(LOGIN_RATE_LIMIT)
def guest_login():
    """
    Guest or PIN-based login.

    Expected JSON body:
        - pin: Optional PIN code

    Returns:
        JSON with login status
    """
    data = request.get_json(silent=True) or {}
    pin = (data.get("pin") or "").strip()

    # Check if already logged in
    if session.get("logged_in_pubkey"):
        label = session.get("guest_label", "Guest")
        return jsonify({"ok": True, "label": label})

    # PIN-based login
    if pin:
        guest_pins = utils.load_guest_pins()
        label = guest_pins.get(pin)

        if not label:
            audit_logger.log_event(
                "auth.guest_login_failed",
                reason="invalid_pin",
                ip=request.remote_addr
            )
            return jsonify({"error": "Invalid PIN"}), 403

        session["logged_in_pubkey"] = f"guest_{pin}"
        session["guest_label"] = label
        session["access_level"] = "guest"
        session.permanent = True

        audit_logger.log_event(
            "auth.guest_login_success",
            label=label,
            ip=request.remote_addr
        )

        return jsonify({"ok": True, "label": label})

    # Anonymous guest
    import uuid
    guest_id = str(uuid.uuid4())[:8]
    label = f"Guest_{guest_id}"

    session["logged_in_pubkey"] = f"anon_{guest_id}"
    session["guest_label"] = label
    session["access_level"] = "guest"
    session.permanent = False  # Session cookie only

    audit_logger.log_event(
        "auth.guest_login_success",
        label=label,
        ip=request.remote_addr
    )

    return jsonify({"ok": True, "label": label})


@auth_bp.route("/login")
def login():
    """Login page with authentication options."""
    from flask import render_template_string
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - HODLXXI</title>
    <style>
        body {
            font-family: -apple-system, system-ui, sans-serif;
            background: #0b0f10;
            color: #e6f1ef;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
        }
        .container {
            max-width: 400px;
            padding: 40px;
            background: #11171a;
            border-radius: 12px;
            border: 1px solid #00ff88;
        }
        h1 { color: #00ff88; margin-top: 0; }
        .btn {
            display: block;
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            background: #00ff88;
            color: #0b0f10;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
            text-decoration: none;
            text-align: center;
        }
        .btn:hover { background: #00dd77; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ Login to HODLXXI</h1>
        <p>Choose your authentication method:</p>
        <a href="/" class="btn">← Back to Home</a>
        <button class="btn" onclick="alert('OAuth login requires client_id and redirect_uri parameters. Use the OAuth flow from your application.')">OAuth Login</button>
        <p style="font-size: 14px; color: #888; margin-top: 20px;">
            For developers: See <a href="/.well-known/openid-configuration" style="color: #00ff88;">OpenID Configuration</a>
        </p>
    </div>
</body>
</html>
    """
    return render_template_string(html)
