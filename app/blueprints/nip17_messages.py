"""NIP-17 message envelope API surface.

This blueprint is intentionally conservative:
- feature flag default OFF
- validates relay-visible NIP-59 gift-wrap envelope shape only
- does not accept plaintext kind 14/15 as server transport
- does not store, publish, decrypt, sign, or log message content
"""

from __future__ import annotations

import json
import os

from flask import Blueprint, current_app, jsonify, request, session

from app.services.nip17_storage import count_opaque_nip17_envelopes_for_receiver, store_opaque_nip17_envelope

nip17_messages_bp = Blueprint("nip17_messages", __name__)


def _nip17_messages_enabled() -> bool:
    configured = current_app.config.get("NIP17_MESSAGES_ENABLED")
    if configured is not None:
        return bool(configured)
    return (os.getenv("NIP17_MESSAGES_ENABLED") or "").strip().lower() in {"1", "true", "yes", "on"}


def _nip17_max_envelope_bytes() -> int:
    raw = current_app.config.get("NIP17_MAX_ENVELOPE_BYTES")
    if raw is None:
        raw = os.getenv("NIP17_MAX_ENVELOPE_BYTES", "65536")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = 65536
    return max(1024, min(value, 1024 * 1024))


def _json_size_bytes(value: object) -> int:
    return len(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def get_nip17_metadata() -> dict:
    """Return public NIP-17/NIP-59 runtime metadata.

    `enabled` means local HTTP intake accepts NIP-59 gift-wrap envelopes.
    It does not mean relay publishing, decryption, plaintext storage, or key custody.
    """

    intake_enabled = _nip17_messages_enabled()
    return {
        "enabled": intake_enabled,
        "intake_enabled": intake_enabled,
        "planned": True,
        "key_custody": False,
        "server_plaintext_storage": False,
        "nip44_encryption": "planned",
        "nip59_gift_wrap": "planned",
        "relay_list_kind": 10050,
        "supported_kinds": [14, 15],
        "accepted_transport_kind": 1059,
        "relay_publishing": False,
        "auth_required": True,
        "max_envelope_bytes": _nip17_max_envelope_bytes(),
    }


def _is_nostr_pubkey(value: str) -> bool:
    value = str(value or "").strip()
    return len(value) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def _receiver_pubkey_from_session() -> str | None:
    """Return x-only NIP-17 receiver pubkey for the current session.

    HODLXXI Legacy/Bitcoin login stores compressed secp256k1 pubkeys as
    66-hex values. Nostr/NIP-17 receiver keys are x-only 64-hex pubkeys.
    A compressed 02/03 key maps to its x-only tail for inbox lookup.

    Guest, anonymous, PIN, and non-hex identities are not supported receivers.
    """

    logged_in_pubkey = str(session.get("logged_in_pubkey") or "").strip().lower()

    if _is_nostr_pubkey(logged_in_pubkey):
        return logged_in_pubkey

    if (
        len(logged_in_pubkey) == 66
        and logged_in_pubkey[:2] in {"02", "03"}
        and all(ch in "0123456789abcdef" for ch in logged_in_pubkey)
    ):
        return logged_in_pubkey[2:]

    return None


@nip17_messages_bp.get("/api/messages/nip17/inbox/status")
def get_nip17_inbox_status():
    logged_in_pubkey = str(session.get("logged_in_pubkey") or "").strip()
    if not logged_in_pubkey:
        return jsonify({"error": "unauthorized", "message": "login required"}), 401

    receiver_pubkey = _receiver_pubkey_from_session()
    receiver_pubkey_supported = receiver_pubkey is not None
    stored_envelopes = 0

    if receiver_pubkey_supported:
        stored_envelopes = count_opaque_nip17_envelopes_for_receiver(receiver_pubkey)

    return jsonify(
        {
            "ok": True,
            "enabled": _nip17_messages_enabled(),
            "stored_envelopes": stored_envelopes,
            "receiver_pubkey_supported": receiver_pubkey_supported,
            "receiver_pubkey_tail": receiver_pubkey[-8:] if receiver_pubkey_supported else None,
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

    logged_in_pubkey = str(session.get("logged_in_pubkey") or "").strip()
    if not logged_in_pubkey:
        return jsonify({"error": "unauthorized", "message": "login required"}), 401

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "invalid_json", "message": "JSON object required"}), 400

    envelope = payload.get("envelope")
    if not isinstance(envelope, dict):
        return jsonify({"error": "invalid_envelope", "message": "envelope object required"}), 400

    envelope_size = _json_size_bytes(envelope)
    max_envelope_bytes = _nip17_max_envelope_bytes()
    if envelope_size > max_envelope_bytes:
        return (
            jsonify(
                {
                    "error": "envelope_too_large",
                    "message": "encrypted envelope exceeds configured size limit",
                    "max_envelope_bytes": max_envelope_bytes,
                }
            ),
            413,
        )

    stored = store_opaque_nip17_envelope(
        envelope,
        source="api",
        metadata={
            "route": "/api/messages/nip17/envelopes",
            "authenticated": True,
            "sender_session_pubkey_tail": logged_in_pubkey[-8:],
            "envelope_size_bytes": envelope_size,
        },
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


@nip17_messages_bp.get("/api/messages/nip17/inbox/envelopes")
def get_nip17_inbox_envelopes():
    """Return authenticated receiver inbox metadata only."""

    logged_in_pubkey = str(session.get("logged_in_pubkey") or "").strip()
    if not logged_in_pubkey:
        return jsonify({"error": "unauthorized", "message": "login required"}), 401

    receiver_pubkey = _receiver_pubkey_from_session()
    if not receiver_pubkey:
        return jsonify({"ok": True, "items": [], "count": 0, "limit": 0, "offset": 0}), 200

    try:
        limit = int(request.args.get("limit", "50"))
        offset = int(request.args.get("offset", "0"))
    except ValueError:
        return jsonify({"error": "bad_request", "message": "limit and offset must be integers"}), 400

    include_envelope = str(request.args.get("include_envelope") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    try:
        from app.services.nip17_storage import list_opaque_nip17_envelopes_for_receiver

        payload = list_opaque_nip17_envelopes_for_receiver(
            receiver_pubkey,
            limit=limit,
            offset=offset,
            include_envelope=include_envelope,
        )
    except ValueError as exc:
        return jsonify({"error": "bad_request", "message": str(exc)}), 400

    return jsonify(payload), 200
