from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

bp = Blueprint("billing_api_compat", __name__)


def _proxy(endpoint_name: str):
    vf = current_app.view_functions.get(endpoint_name)
    if not vf:
        return jsonify({"error": f"Missing endpoint {endpoint_name}"}), 404
    return vf()


@bp.route("/api/billing/create-invoice", methods=["POST", "OPTIONS"])
def api_billing_create_invoice():
    # CORS preflight
    if request.method == "OPTIONS":
        return ("", 204)
    # Use the canonical implementation in dev_routes
    return _proxy("dev.create_invoice_route")


@bp.route("/api/billing/check-invoice", methods=["GET", "POST", "OPTIONS"])
def api_billing_check_invoice():
    # CORS preflight
    if request.method == "OPTIONS":
        return ("", 204)
    # Use the canonical implementation in dev_routes
    return _proxy("dev.check_invoice_route")
