"""Opaque NIP-17 envelope storage contract tests."""

from app.services.nip17_storage import get_opaque_nip17_envelope, opaque_envelope_hash, store_opaque_nip17_envelope

HEX32_A = "a" * 64
HEX32_B = "b" * 64
HEX32_C = "c" * 64
SIG = "d" * 128


def _gift_wrap_event(event_id=HEX32_A):
    return {
        "id": event_id,
        "pubkey": HEX32_B,
        "created_at": 1779570000,
        "kind": 1059,
        "tags": [["p", HEX32_C]],
        "content": "encrypted-seal-ciphertext",
        "sig": SIG,
    }


def test_store_opaque_nip17_envelope_persists_ciphertext_only(app):
    envelope = _gift_wrap_event()

    result = store_opaque_nip17_envelope(envelope, source="unit_test")

    assert result["ok"] is True
    assert result["stored"] is True
    assert result["duplicate"] is False
    assert result["event_id"] == HEX32_A
    assert result["receiver_pubkey"] == HEX32_C

    fetched = get_opaque_nip17_envelope(HEX32_A)
    assert fetched is not None
    assert fetched["event_id"] == HEX32_A
    assert fetched["envelope_hash"] == opaque_envelope_hash(envelope)
    assert fetched["kind"] == 1059
    assert fetched["source"] == "unit_test"
    assert "envelope" not in fetched


def test_store_opaque_nip17_envelope_can_include_envelope_when_explicit(app):
    envelope = _gift_wrap_event("e" * 64)

    result = store_opaque_nip17_envelope(envelope, source="unit_test")
    assert result["ok"] is True

    fetched = get_opaque_nip17_envelope("e" * 64, include_envelope=True)
    assert fetched is not None
    assert fetched["envelope"]["kind"] == 1059
    assert fetched["envelope"]["content"] == "encrypted-seal-ciphertext"


def test_store_opaque_nip17_envelope_is_idempotent_by_event_id(app):
    event_id = "f" * 64
    envelope = _gift_wrap_event(event_id)

    first = store_opaque_nip17_envelope(envelope, source="unit_test")
    second = store_opaque_nip17_envelope(envelope, source="unit_test")

    assert first["ok"] is True
    assert first["stored"] is True
    assert second["ok"] is True
    assert second["stored"] is False
    assert second["duplicate"] is True
    assert second["event_id"] == first["event_id"]


def test_store_opaque_nip17_envelope_rejects_plaintext_kind14(app):
    event_id = "9" * 64
    plaintext = {
        "id": event_id,
        "pubkey": HEX32_B,
        "created_at": 1779570000,
        "kind": 14,
        "tags": [["p", HEX32_C]],
        "content": "plaintext message must never enter NIP17Envelope storage",
    }

    result = store_opaque_nip17_envelope(plaintext, source="unit_test")

    assert result["ok"] is False
    assert result["error"] == "invalid_nip59_gift_wrap"
    assert "kind_must_be_1059" in result["details"]

    assert get_opaque_nip17_envelope(event_id, include_envelope=True) is None


def test_migration_documents_ciphertext_only_boundary():
    text = open("migrations/2026-05-28_nip17_envelopes.sql", encoding="utf-8").read().lower()

    assert "encrypted relay-visible kind-1059" in text
    assert "must never contain plaintext kind-14/kind-15" in text
    assert "user private keys" in text
