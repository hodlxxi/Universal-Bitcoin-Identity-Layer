"""Opaque NIP-17 envelope storage helpers.

This module stores encrypted NIP-59 gift-wrap envelopes only. It never
decrypts content, stores plaintext kind-14/kind-15 bodies, signs messages, or
requires custody of user private keys.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
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


def preview_nip17_envelope_retention(*, max_age_days: int = 90, max_rows: int = 10000) -> dict[str, Any]:
    """Preview NIP-17 envelope retention without deleting rows.

    Retention is intentionally conservative:
    - age cutoff applies to received_at
    - max_rows keeps newest rows by received_at/id and selects older overflow
    - no envelope_json/content is returned
    """

    if max_age_days < 1:
        raise ValueError("max_age_days must be >= 1")
    if max_rows < 1:
        raise ValueError("max_rows must be >= 1")

    with session_scope() as session:
        total = session.query(NIP17Envelope).count()

        age_cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
        age_ids = {
            row[0] for row in session.query(NIP17Envelope.id).filter(NIP17Envelope.received_at < age_cutoff).all()
        }

        ordered_ids = [
            row[0]
            for row in session.query(NIP17Envelope.id)
            .order_by(NIP17Envelope.received_at.desc(), NIP17Envelope.id.desc())
            .all()
        ]
        overflow_ids = set(ordered_ids[max_rows:])

        delete_ids = age_ids | overflow_ids

        return {
            "ok": True,
            "dry_run": True,
            "total": total,
            "max_age_days": max_age_days,
            "max_rows": max_rows,
            "age_cutoff": age_cutoff.isoformat(),
            "delete_count": len(delete_ids),
            "age_delete_count": len(age_ids),
            "overflow_delete_count": len(overflow_ids),
            "kept_count_after_delete": total - len(delete_ids),
        }


def apply_nip17_envelope_retention(*, max_age_days: int = 90, max_rows: int = 10000) -> dict[str, Any]:
    """Apply NIP-17 envelope retention and delete selected opaque rows."""

    preview = preview_nip17_envelope_retention(max_age_days=max_age_days, max_rows=max_rows)
    if preview["delete_count"] == 0:
        result = dict(preview)
        result["dry_run"] = False
        result["deleted_count"] = 0
        return result

    age_cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)

    with session_scope() as session:
        ordered_ids = [
            row[0]
            for row in session.query(NIP17Envelope.id)
            .order_by(NIP17Envelope.received_at.desc(), NIP17Envelope.id.desc())
            .all()
        ]
        overflow_ids = set(ordered_ids[max_rows:])

        age_ids = {
            row[0] for row in session.query(NIP17Envelope.id).filter(NIP17Envelope.received_at < age_cutoff).all()
        }

        delete_ids = age_ids | overflow_ids
        deleted_count = 0

        if delete_ids:
            deleted_count = (
                session.query(NIP17Envelope).filter(NIP17Envelope.id.in_(delete_ids)).delete(synchronize_session=False)
            )

    result = preview_nip17_envelope_retention(max_age_days=max_age_days, max_rows=max_rows)
    result["dry_run"] = False
    result["deleted_count"] = deleted_count
    return result
