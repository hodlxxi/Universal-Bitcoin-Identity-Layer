"""NIP-17 message envelope API surface.

This blueprint is intentionally conservative:
- feature flag default OFF
- validates relay-visible NIP-59 gift-wrap envelope shape only
- does not accept plaintext kind 14/15 as server transport
- does not store, publish, decrypt, sign, or log message content
"""

from __future__ import annotations

import os

from flask import Blueprint, current_app, jsonify, request

from app.services.nip17_storage import store_opaque_nip17_envelope

nip17_messages_bp = Blueprint("nip17_messages", __name__)


def _nip17_messages_enabled() -> bool:
    configured = current_app.config.get("NIP17_MESSAGES_ENABLED")
    if configured is not None:
        return bool(configured)
    return (os.getenv("NIP17_MESSAGES_ENABLED") or "").strip().lower() in {"1", "true", "yes", "on"}


@nip17_messages_bp.post("/api/messages/nip17/envelopes")
def post_nip17_envelope():
    if not _nip17_messages_enabled():
        return jsonify({"error": "not_found", "message": "NIP-17 message intake disabled"}), 404

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "invalid_json", "message": "JSON object required"}), 400

    envelope = payload.get("envelope")
    if not isinstance(envelope, dict):
        return jsonify({"error": "invalid_envelope", "message": "envelope object required"}), 400

    stored = store_opaque_nip17_envelope(
        envelope,
        source="api",
        metadata={"route": "/api/messages/nip17/envelopes"},
    )
    if not stored["ok"]:
        return (
            jsonify(
                {
                    "error": stored["error"],
                    "details": stored.get("details", []),
                }
            ),
            400,
        )

    return (
        jsonify(
            {
                "ok": True,
                "accepted": True,
                "kind": 1059,
                "stored": bool(stored["stored"]),
                "duplicate": bool(stored["duplicate"]),
                "event_id": stored["event_id"],
                "envelope_hash": stored["envelope_hash"],
                "receiver_pubkey": stored["receiver_pubkey"],
                "published": False,
                "plaintext_seen": False,
                "message": "opaque NIP-59 gift-wrap envelope stored; relay publishing is not enabled",
            }
        ),
        202,
    )
