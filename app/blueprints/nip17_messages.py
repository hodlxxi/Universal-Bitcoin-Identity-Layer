"""NIP-17 message envelope API surface.

This blueprint is intentionally conservative:
- feature flag default OFF
- validates relay-visible NIP-59 gift-wrap envelope shape only
- does not accept plaintext kind 14/15 as server transport
- does not store, publish, decrypt, sign, or log message content
"""

from __future__ import annotations

import os

from flask import Blueprint, current_app, jsonify, request, session

from app.services.nip17_storage import count_opaque_nip17_envelopes_for_receiver, store_opaque_nip17_envelope

nip17_messages_bp = Blueprint("nip17_messages", __name__)


def _nip17_messages_enabled() -> bool:
    configured = current_app.config.get("NIP17_MESSAGES_ENABLED")
    if configured is not None:
        return bool(configured)
    return (os.getenv("NIP17_MESSAGES_ENABLED") or "").strip().lower() in {"1", "true", "yes", "on"}


def _is_nostr_pubkey(value: str) -> bool:
    value = str(value or "").strip()
    return len(value) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in value)


@nip17_messages_bp.get("/api/messages/nip17/inbox/status")
def get_nip17_inbox_status():
    logged_in_pubkey = str(session.get("logged_in_pubkey") or "").strip()
    if not logged_in_pubkey:
        return jsonify({"error": "unauthorized", "message": "login required"}), 401

    receiver_pubkey_supported = _is_nostr_pubkey(logged_in_pubkey)
    stored_envelopes = 0

    if receiver_pubkey_supported:
        stored_envelopes = count_opaque_nip17_envelopes_for_receiver(logged_in_pubkey.lower())

    return jsonify(
        {
            "ok": True,
            "enabled": _nip17_messages_enabled(),
            "stored_envelopes": stored_envelopes,
            "receiver_pubkey_supported": receiver_pubkey_supported,
            "receiver_pubkey_tail": logged_in_pubkey[-8:] if receiver_pubkey_supported else None,
            "plaintext_storage": False,
            "key_custody": False,
            "ciphertext_echo": False,
            "relay_publish": False,
            "message": "read-only NIP-17 inbox status; envelope bodies are not returned",
        }
    )


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
