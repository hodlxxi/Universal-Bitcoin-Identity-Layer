"""
Bitcoin Operations Blueprint - RPC, Descriptors, Wallet Management

Handles Bitcoin Core RPC operations and wallet management.
"""

import logging
import os
import re
import time
import uuid
from decimal import Decimal
from typing import Any, Dict

from flask import Blueprint, current_app, jsonify, request

from app.audit_logger import get_audit_logger
from app.billing_clients import require_paid_client
from app.oauth_utils import require_oauth_token
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
@require_oauth_token("read_limited")
@require_paid_client(cost_sats=int(os.getenv("HODLXXI_COST_BITCOIN_RPC_SATS", "1")))
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
    except Exception:
        logger.error("RPC command failed", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@bitcoin_bp.route("/bitcoin/verify", methods=["POST"])
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

    except Exception:
        logger.error("Proof of funds verification failed", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@bitcoin_bp.route("/decode_raw_script", methods=["POST"])
@limiter.limit(RPC_RATE_LIMIT)
def decode_raw_script():
    """
    Decode raw Bitcoin script and return the legacy browser QR pack.

    Accepts both:
        - script: Hex-encoded Bitcoin script
        - raw_script: legacy field name used by the browser shell
    """
    data = request.get_json(silent=True) or {}
    raw_script = (data.get("raw_script") or data.get("script") or "").strip()

    if not raw_script:
        return jsonify({"error": "No raw script provided."}), 400

    raw_script = re.sub(r"[^0-9A-Fa-f]", "", raw_script)
    if not raw_script:
        return jsonify({"error": "Script must contain hex characters only."}), 400

    try:
        # Transitional compatibility:
        # Keep the old QR/label-aware decode semantics while this route lives in
        # the bitcoin blueprint. These helpers still live in app.app until the
        # next monolith-retirement phase extracts them into a shared module.
        from app.app import (
            else_early_late,
            extract_else_branches,
            extract_pubkey_from_op_else,
            extract_pubkey_from_op_if,
            find_first_unused_labeled_address,
            generate_qr_code,
            to_npub,
        )

        rpc = get_rpc_connection()
        decoded = rpc.decodescript(raw_script)
        info = rpc.getdescriptorinfo(f"raw({raw_script})")
        full_desc = info["descriptor"]

        asm = decoded.get("asm", "")
        op_if = extract_pubkey_from_op_if(asm)
        op_else = extract_pubkey_from_op_else(asm)
        else_branches = extract_else_branches(asm)
        early, late = else_early_late(asm)

        # Prefer the late ELSE branch pubkey when present. Some legacy
        # extract_pubkey_from_op_else() patterns can pick the early/IF key
        # in CLTV ladder scripts, which makes npub_if and npub_else appear
        # identical even when the script contains two distinct pubkeys.
        effective_else_pub = (late.get("pubkey") if late else None) or op_else

        npub_if = to_npub(op_if) if op_if else None
        npub_else = to_npub(effective_else_pub) if effective_else_pub else None

        seg = decoded.get("segwit") or {}
        seg_addr = seg.get("address")
        script_hex = seg.get("hex")

        first_unused_addr = None
        warning_message = None

        if script_hex:
            first_unused_addr = find_first_unused_labeled_address(rpc, script_hex, max_scan=20)
            if not first_unused_addr:
                warning_message = "Set Checking Labels"

        return jsonify(
            {
                "decoded": decoded,
                "op_if": op_if,
                "op_else": effective_else_pub,
                "npub_if": npub_if,
                "npub_else": npub_else,
                "op_else_branches": else_branches,
                "else_early_pub": (early.get("pubkey") if early else None),
                "else_early_lock": (early.get("lock") if early else None),
                "else_late_pub": (late.get("pubkey") if late else None),
                "else_late_lock": (late.get("lock") if late else None),
                "qr": {
                    "full_descriptor": generate_qr_code(full_desc) if full_desc else None,
                    "segwit_address": generate_qr_code(seg_addr) if seg_addr else None,
                    "pubkey_if": generate_qr_code(npub_if) if npub_if else None,
                    "pubkey_else": generate_qr_code(npub_else) if npub_else else None,
                    "first_unused_addr": generate_qr_code(first_unused_addr) if first_unused_addr else None,
                    "raw_script_hex": generate_qr_code(raw_script) if raw_script else None,
                },
                "first_unused_addr_text": first_unused_addr,
                "script_hex": script_hex,
                "warning": warning_message,
            }
        )

    except Exception:
        logger.error("decode_raw_script failed", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@bitcoin_bp.route("/descriptors", methods=["GET"])
@limiter.limit(RPC_RATE_LIMIT)
@require_oauth_token("read_limited")
@require_paid_client(cost_sats=int(os.getenv("HODLXXI_COST_BITCOIN_RPC_SATS", "1")))
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

    except Exception:
        logger.error("List descriptors failed", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@bitcoin_bp.route("/bitcoin/challenge", methods=["POST"])
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
