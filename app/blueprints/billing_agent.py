"""
OAuth client_id billing endpoints for Lightning PAYG.
"""

import logging

from flask import Blueprint, jsonify, request

from app.billing_clients import check_client_invoice, create_client_invoice
from app.oauth_utils import require_oauth_token

logger = logging.getLogger(__name__)

billing_agent_bp = Blueprint("billing_agent", __name__)


@billing_agent_bp.route("/api/billing/agent/create-invoice", methods=["POST"])
@require_oauth_token("read_limited")
def create_agent_invoice():
    data = request.get_json(silent=True) or {}
    amount_raw = data.get("amount_sats") or request.form.get("amount_sats")
    if amount_raw is None:
        return jsonify({"ok": False, "error": "amount_sats required"}), 400
    try:
        amount_sats = int(amount_raw)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "amount_sats must be an integer"}), 400
    if amount_sats <= 0:
        return jsonify({"ok": False, "error": "amount_sats must be > 0"}), 400

    client_id = request.oauth_client_id
    memo = f"HODLXXI PAYG topup for client {client_id}"
    try:
        payload = create_client_invoice(client_id, amount_sats, memo)
    except Exception as exc:
        logger.error("Agent invoice create failed: %s", exc, exc_info=True)
        return jsonify({"ok": False, "error": "invoice_create_failed"}), 500
    return jsonify(payload)


@billing_agent_bp.route("/api/billing/agent/check-invoice", methods=["POST"])
@require_oauth_token("read_limited")
def check_agent_invoice():
    data = request.get_json(silent=True) or {}
    invoice_id = data.get("invoice_id") or request.args.get("invoice_id") or request.form.get("invoice_id")
    if not invoice_id:
        return jsonify({"ok": False, "error": "invoice_id required"}), 400

    client_id = request.oauth_client_id
    try:
        payload = check_client_invoice(client_id, invoice_id)
    except Exception as exc:
        logger.error("Agent invoice check failed: %s", exc, exc_info=True)
        return jsonify({"ok": False, "error": "invoice_check_failed"}), 500
    status_code = 404 if payload.get("error") == "invoice_not_found" else 200
    return jsonify(payload), status_code
