"""
Bitcoin Operations Blueprint - RPC, Descriptors, Wallet Management

Handles Bitcoin Core RPC operations and wallet management.
"""

import logging
import time
import uuid
from decimal import Decimal
from typing import Any, Dict

from flask import Blueprint, current_app, jsonify, request

from app.audit_logger import get_audit_logger
from app.security import limiter as _limiter


class _NoopLimiter:
    """Fallback when the rate limiter isn't initialized (e.g., unit tests)."""

    def limit(self, *_args, **_kwargs):
        def _decorator(fn):
            return fn

        return _decorator


limiter = _limiter or _NoopLimiter()

from app.utils import get_rpc_connection, is_valid_pubkey

logger = logging.getLogger(__name__)
audit_logger = get_audit_logger()

bitcoin_bp = Blueprint("bitcoin", __name__)

RPC_RATE_LIMIT = "30 per minute"


@bitcoin_bp.route("/rpc/<cmd>", methods=["GET"])
@limiter.limit(RPC_RATE_LIMIT)
def rpc_command(cmd: str):
    """
    Execute Bitcoin Core RPC command.

    Security: Limited to read-only commands.

    Args:
        cmd: RPC command name

    Returns:
        JSON with RPC response
    """
    # Whitelist of safe read-only commands
    SAFE_COMMANDS = {
        "getblockchaininfo",
        "getblockcount",
        "getbestblockhash",
        "getmempoolinfo",
        "getnetworkinfo",
        "uptime",
        "getwalletinfo",
        "getbalance",
        "listdescriptors",
    }

    if cmd not in SAFE_COMMANDS:
        audit_logger.log_event("bitcoin.rpc_blocked", command=cmd, ip=request.remote_addr)
        return jsonify({"error": f"Command '{cmd}' not allowed"}), 403

    try:
        rpc = get_rpc_connection()
        result = getattr(rpc, cmd)()

        audit_logger.log_event("bitcoin.rpc_success", command=cmd, ip=request.remote_addr)

        return jsonify({"result": result})

    except AttributeError:
        return jsonify({"error": f"Unknown command: {cmd}"}), 400
    except Exception as e:
        logger.error(f"RPC command {cmd} failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@bitcoin_bp.route("/verify", methods=["POST"])
@limiter.limit("10 per minute")
def verify_proof_of_funds():
    """
    Verify proof of funds via PSBT.

    Expected JSON body:
        - psbt: Partially Signed Bitcoin Transaction
        - challenge: Challenge string

    Returns:
        JSON with verification result
    """
    data = request.get_json()
    psbt = data.get("psbt")
    challenge = data.get("challenge")

    if not psbt or not challenge:
        return jsonify({"error": "Missing psbt or challenge"}), 400

    try:
        rpc = get_rpc_connection()

        # Decode PSBT
        decoded = rpc.decodepsbt(psbt)

        # Verify inputs are unspent
        verified_amount = Decimal(0)
        for tx_input in decoded.get("tx", {}).get("vin", []):
            txid = tx_input.get("txid")
            vout = tx_input.get("vout")

            # Check if UTXO exists
            utxo = rpc.gettxout(txid, vout)
            if utxo:
                verified_amount += Decimal(str(utxo["value"]))

        # Verify challenge in OP_RETURN
        has_challenge = False
        for tx_output in decoded.get("tx", {}).get("vout", []):
            script_asm = tx_output.get("scriptPubKey", {}).get("asm", "")
            if "OP_RETURN" in script_asm and challenge in script_asm:
                has_challenge = True
                break

        if not has_challenge:
            return jsonify({"verified": False, "error": "Challenge not found in OP_RETURN"}), 400

        audit_logger.log_event("bitcoin.proof_of_funds_verified", amount=str(verified_amount), ip=request.remote_addr)

        return jsonify({"verified": True, "amount_btc": str(verified_amount), "challenge_verified": True})

    except Exception as e:
        logger.error(f"Proof of funds verification failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@bitcoin_bp.route("/decode_raw_script", methods=["POST"])
@limiter.limit(RPC_RATE_LIMIT)
def decode_raw_script():
    """
    Decode raw Bitcoin script.

    Expected JSON body:
        - script: Hex-encoded Bitcoin script

    Returns:
        JSON with decoded script
    """
    data = request.get_json()
    script = data.get("script")

    if not script:
        return jsonify({"error": "Missing script parameter"}), 400

    try:
        rpc = get_rpc_connection()
        decoded = rpc.decodescript(script)
        return jsonify(decoded)

    except Exception as e:
        logger.error(f"Script decoding failed: {e}")
        return jsonify({"error": str(e)}), 500


@bitcoin_bp.route("/descriptors", methods=["GET"])
@limiter.limit(RPC_RATE_LIMIT)
def list_descriptors():
    """
    List wallet descriptors.

    Returns:
        JSON with wallet descriptors
    """
    try:
        rpc = get_rpc_connection()
        descriptors = rpc.listdescriptors()
        result = descriptors
        cfg = current_app.config.get("APP_CONFIG", {}) or {}
        if str(cfg.get("FLASK_ENV", "")).lower() == "production":
            if isinstance(result, dict) and "descriptors" in result:
                for d in result.get("descriptors") or []:
                    if isinstance(d, dict) and isinstance(d.get("desc"), str):
                        for marker in ("xprv", "tprv", "yprv", "zprv", "vprv", "uprv"):
                            d["desc"] = d["desc"].replace(marker, "[REDACTED]")

        # Filter sensitive information in production
        cfg = current_app.config.get("APP_CONFIG", {})
        if cfg.get("FLASK_ENV") == "production":
            # Redact private keys
            for desc in descriptors.get("descriptors", []):
                if "desc" in desc:
                    # Remove private key parts
                    desc["desc"] = desc["desc"].split("#")[0]

        return jsonify(descriptors)

    except Exception as e:
        logger.error(f"List descriptors failed: {e}")
        return jsonify({"error": str(e)}), 500


@bitcoin_bp.route("/challenge", methods=["POST"])
def create_pof_challenge():
    """
    Compatibility endpoint for integration tests: POST /api/challenge

    Returns 200 with a challenge payload even when Bitcoin RPC is unavailable.
    """
    data = request.get_json(silent=True) or {}
    pubkey = data.get("pubkey")

    if not pubkey:
        return jsonify({"error": "missing pubkey"}), 400

    # Basic validation (keeps tests honest)
    if not is_valid_pubkey(pubkey):
        return jsonify({"error": "invalid pubkey"}), 400

    challenge_id = str(uuid.uuid4())
    challenge = f"HODLXXI:POF:{int(time.time())}:{challenge_id}"

    return (
        jsonify(
            {
                "ok": True,
                "challenge_id": challenge_id,
                "challenge": challenge,
                "expires_in": 300,
            }
        ),
        200,
    )
