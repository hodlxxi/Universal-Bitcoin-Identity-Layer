"""NIP-17 opaque envelope retention contract tests."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.database import session_scope
from app.models import NIP17Envelope
from app.services.nip17_storage import (
    apply_nip17_envelope_retention,
    preview_nip17_envelope_retention,
)


def _event_id(label: str) -> str:
    return f"{uuid4().hex}{uuid4().hex}"


def _insert_envelope(label: str, *, received_at: datetime) -> str:
    event_id = _event_id(label)
    with session_scope() as session:
        session.add(
            NIP17Envelope(
                event_id=event_id,
                envelope_hash=event_id,
                wrapper_pubkey="b" * 64,
                receiver_pubkey="c" * 64,
                kind=1059,
                event_created_at=1,
                envelope_json={"id": event_id, "kind": 1059, "content": "ciphertext"},
                source="test",
                status="received",
                received_at=received_at,
                metadata_json={"test": True, "label": label},
            )
        )
    return event_id


def test_preview_nip17_retention_does_not_delete_rows(app):
    now = datetime.now(timezone.utc)
    old_id = _insert_envelope("preview-old", received_at=now - timedelta(days=120))
    new_id = _insert_envelope("preview-new", received_at=now)

    preview = preview_nip17_envelope_retention(max_age_days=90, max_rows=10000)

    assert preview["ok"] is True
    assert preview["dry_run"] is True
    assert preview["delete_count"] >= 1
    assert preview["age_delete_count"] >= 1
    assert preview["overflow_delete_count"] >= 0

    with session_scope() as session:
        remaining = {row.event_id for row in session.query(NIP17Envelope).all()}

    assert old_id in remaining
    assert new_id in remaining


def test_apply_nip17_retention_deletes_old_rows(app):
    now = datetime.now(timezone.utc)
    old_id = _insert_envelope("apply-old", received_at=now - timedelta(days=120))
    new_id = _insert_envelope("apply-new", received_at=now)

    result = apply_nip17_envelope_retention(max_age_days=90, max_rows=10000)

    assert result["ok"] is True
    assert result["dry_run"] is False
    assert result["deleted_count"] >= 1

    with session_scope() as session:
        remaining = {row.event_id for row in session.query(NIP17Envelope).all()}

    assert old_id not in remaining
    assert new_id in remaining


def test_retention_max_rows_keeps_globally_newest_rows(app):
    # Use far-future timestamps so these rows are definitely the newest rows
    # even if the shared test DB contains records from earlier tests.
    base = datetime(2099, 1, 1, tzinfo=timezone.utc)
    oldest_id = _insert_envelope("overflow-oldest", received_at=base)
    middle_id = _insert_envelope("overflow-middle", received_at=base + timedelta(minutes=1))
    newest_id = _insert_envelope("overflow-newest", received_at=base + timedelta(minutes=2))

    preview = preview_nip17_envelope_retention(max_age_days=36500, max_rows=2)

    assert preview["delete_count"] >= 1
    assert preview["overflow_delete_count"] >= 1

    result = apply_nip17_envelope_retention(max_age_days=36500, max_rows=2)
    assert result["deleted_count"] >= 1

    with session_scope() as session:
        remaining = {row.event_id for row in session.query(NIP17Envelope).all()}

    assert oldest_id not in remaining
    assert middle_id in remaining
    assert newest_id in remaining


def test_retention_result_never_returns_envelope_json_or_content(app):
    now = datetime.now(timezone.utc)
    _insert_envelope("no-leak", received_at=now - timedelta(days=120))

    preview = preview_nip17_envelope_retention(max_age_days=90, max_rows=10000)

    text = repr(preview).lower()
    assert "envelope_json" not in text
    assert "ciphertext" not in text
    assert "content" not in text


def test_retention_rejects_unsafe_limits(app):
    try:
        preview_nip17_envelope_retention(max_age_days=0, max_rows=10000)
    except ValueError as exc:
        assert "max_age_days" in str(exc)
    else:
        raise AssertionError("max_age_days=0 should fail")

    try:
        preview_nip17_envelope_retention(max_age_days=90, max_rows=0)
    except ValueError as exc:
        assert "max_rows" in str(exc)
    else:
        raise AssertionError("max_rows=0 should fail")


def test_retention_script_memory_db_guard_helpers():
    from scripts.nip17_retention import _is_memory_database_url, _safe_database_target

    assert _is_memory_database_url("sqlite://")
    assert _is_memory_database_url("sqlite:///:memory:")
    assert _is_memory_database_url("sqlite:///:memory")
    assert not _is_memory_database_url("sqlite:////srv/ubid-staging/runtime/staging.db")

    target = _safe_database_target("sqlite:////srv/ubid-staging/runtime/staging.db")
    assert target["scheme"] == "sqlite"
    assert target["is_memory"] is False
    assert "password" not in repr(target).lower()
    assert "username" not in repr(target).lower()
