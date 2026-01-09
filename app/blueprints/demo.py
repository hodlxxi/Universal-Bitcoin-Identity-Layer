"""
Demo endpoints blueprint.

These endpoints are intentionally simple and stable for integration tests and public demos.
"""
import time
from flask import Blueprint, jsonify, session

demo_bp = Blueprint("demo", __name__)

@demo_bp.get("/free")
def demo_free():
    # Public endpoint (no auth required)
    return jsonify({
        "ok": True,
        "tier": "free",
        "message": "demo free ok",
        "timestamp": time.time(),
    }), 200

@demo_bp.get("/pro")
def demo_pro():
    # Auth-gated example endpoint (may be used by future tests)
    if not session.get("logged_in_pubkey"):
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({
        "ok": True,
        "tier": "pro",
        "timestamp": time.time(),
    }), 200

@demo_bp.get("/protected")
def demo_protected():
    # Must require authentication (tests accept 401 or 403)
    if not session.get("logged_in_pubkey"):
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"ok": True, "message": "demo protected ok"}), 200

