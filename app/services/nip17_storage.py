"""Opaque NIP-17 envelope storage helpers.

This module stores encrypted NIP-59 gift-wrap envelopes only. It never
decrypts content, stores plaintext kind-14/kind-15 bodies, signs messages, or
requires custody of user private keys.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.database import session_scope
from app.models import NIP17Envelope
from app.services.nostr_dm import validate_nip59_gift_wrap_event


def canonical_envelope_bytes(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def opaque_envelope_hash(envelope: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_envelope_bytes(envelope)).hexdigest()


def _receiver_pubkey(envelope: dict[str, Any]) -> str:
    tags = envelope.get("tags") if isinstance(envelope.get("tags"), list) else []
    p_tags = [tag for tag in tags if isinstance(tag, list) and len(tag) >= 2 and tag[0] == "p"]
    if len(p_tags) != 1:
        raise ValueError("gift_wrap_must_have_exactly_one_receiver_p_tag")
    return str(p_tags[0][1]).lower()


def store_opaque_nip17_envelope(
    envelope: dict[str, Any],
    *,
    source: str = "api",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    validation = validate_nip59_gift_wrap_event(envelope)
    if not validation["ok"]:
        return {
            "ok": False,
            "error": "invalid_nip59_gift_wrap",
            "details": validation["errors"],
        }

    event_id = str(envelope["id"]).lower()
    envelope_hash = opaque_envelope_hash(envelope)
    wrapper_pubkey = str(envelope["pubkey"]).lower()
    receiver_pubkey = _receiver_pubkey(envelope)

    with session_scope() as session:
        existing = session.query(NIP17Envelope).filter_by(event_id=event_id).first()
        if existing:
            return {
                "ok": True,
                "stored": False,
                "duplicate": True,
                "id": existing.id,
                "event_id": existing.event_id,
                "envelope_hash": existing.envelope_hash,
                "receiver_pubkey": existing.receiver_pubkey,
            }

        row = NIP17Envelope(
            event_id=event_id,
            envelope_hash=envelope_hash,
            wrapper_pubkey=wrapper_pubkey,
            receiver_pubkey=receiver_pubkey,
            kind=1059,
            event_created_at=int(envelope["created_at"]),
            envelope_json=envelope,
            source=str(source or "api")[:64],
            status="received",
            metadata_json=metadata or {},
        )
        session.add(row)
        session.flush()

        return {
            "ok": True,
            "stored": True,
            "duplicate": False,
            "id": row.id,
            "event_id": row.event_id,
            "envelope_hash": row.envelope_hash,
            "receiver_pubkey": row.receiver_pubkey,
        }


def count_opaque_nip17_envelopes_for_receiver(receiver_pubkey: str) -> int:
    """Count stored opaque envelopes for one receiver without loading envelope_json."""

    receiver = str(receiver_pubkey or "").strip().lower()
    if not receiver:
        return 0

    with session_scope() as session:
        return int(
            session.query(NIP17Envelope.id)
            .filter(
                NIP17Envelope.receiver_pubkey == receiver,
                NIP17Envelope.status == "received",
            )
            .count()
        )


def get_opaque_nip17_envelope(event_id: str, *, include_envelope: bool = False) -> dict[str, Any] | None:
    with session_scope() as session:
        row = session.query(NIP17Envelope).filter_by(event_id=str(event_id).lower()).first()
        if not row:
            return None

        payload = {
            "id": row.id,
            "event_id": row.event_id,
            "envelope_hash": row.envelope_hash,
            "wrapper_pubkey": row.wrapper_pubkey,
            "receiver_pubkey": row.receiver_pubkey,
            "kind": row.kind,
            "event_created_at": row.event_created_at,
            "source": row.source,
            "status": row.status,
            "received_at": row.received_at.isoformat(),
            "metadata": row.metadata_json or {},
        }
        if include_envelope:
            payload["envelope"] = row.envelope_json
        return payload
