from __future__ import annotations

from app.blueprints.qr_operator import _normalize_pointer, _pubkey_tail


def test_pubkey_tail_masks_full_pubkey():
    pubkey = "02" + ("a" * 60) + "abcd"

    assert _pubkey_tail(pubkey) == "abcd"
    assert _pubkey_tail(pubkey) != pubkey


def test_normalized_pointer_contract(app):
    with app.test_request_context(base_url="http://127.0.0.1:15056"):
        record = _normalize_pointer(
            "demo-active",
            {"status": "active", "target": "/agent/discovery"},
        )

    assert record == {
        "token": "demo-active",
        "status": "active",
        "target": "/agent/discovery",
        "qr_url": "http://127.0.0.1:15056/qr/demo-active",
        "is_active": True,
        "is_revoked": False,
        "is_expired": False,
        "manual_target_allowed": True,
    }


def test_revoked_and_expired_state_flags(app):
    with app.test_request_context(base_url="http://127.0.0.1:15056"):
        revoked = _normalize_pointer("demo-revoked", {"status": "revoked", "target": "/agent/discovery"})
        expired = _normalize_pointer("demo-expired", {"status": "expired", "target": "/agent/discovery"})

    assert revoked["is_active"] is False
    assert revoked["is_revoked"] is True
    assert revoked["is_expired"] is False
    assert revoked["manual_target_allowed"] is False
    assert expired["is_active"] is False
    assert expired["is_revoked"] is False
    assert expired["is_expired"] is True
    assert expired["manual_target_allowed"] is False
