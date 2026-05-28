"""NIP-17/NIP-59 envelope shape contracts."""

from app.services.nostr_dm import (
    validate_nip17_relay_list_event,
    validate_nip17_unsigned_event,
    validate_nip59_gift_wrap_event,
)

HEX32_A = "a" * 64
HEX32_B = "b" * 64
HEX32_C = "c" * 64
SIG = "d" * 128


def test_unsigned_kind14_requires_receiver_and_no_signature():
    event = {
        "id": HEX32_A,
        "pubkey": HEX32_B,
        "created_at": 1779570000,
        "kind": 14,
        "tags": [["p", HEX32_C, "wss://relay.example"]],
        "content": "hello",
    }

    result = validate_nip17_unsigned_event(event)

    assert result == {"ok": True, "errors": []}


def test_unsigned_kind14_rejects_server_transport_signature():
    event = {
        "id": HEX32_A,
        "pubkey": HEX32_B,
        "created_at": 1779570000,
        "kind": 14,
        "tags": [["p", HEX32_C]],
        "content": "hello",
        "sig": SIG,
    }

    result = validate_nip17_unsigned_event(event)

    assert result["ok"] is False
    assert "unsigned_nip17_event_must_not_have_sig" in result["errors"]


def test_unsigned_kind15_requires_file_metadata_tags():
    event = {
        "id": HEX32_A,
        "pubkey": HEX32_B,
        "created_at": 1779570000,
        "kind": 15,
        "tags": [["p", HEX32_C]],
        "content": "https://files.example/encrypted.bin",
    }

    result = validate_nip17_unsigned_event(event)

    assert result["ok"] is False
    assert "missing_file_tags:decryption-key,decryption-nonce,encryption-algorithm,file-type,x" in result["errors"]


def test_nip59_gift_wrap_shape_is_ciphertext_only_transport():
    event = {
        "id": HEX32_A,
        "pubkey": HEX32_B,
        "created_at": 1779570000,
        "kind": 1059,
        "tags": [["p", HEX32_C]],
        "content": "encrypted-seal-ciphertext",
        "sig": SIG,
    }

    result = validate_nip59_gift_wrap_event(event)

    assert result == {"ok": True, "errors": []}


def test_nip59_gift_wrap_requires_single_receiver():
    event = {
        "id": HEX32_A,
        "pubkey": HEX32_B,
        "created_at": 1779570000,
        "kind": 1059,
        "tags": [["p", HEX32_C], ["p", HEX32_A]],
        "content": "encrypted-seal-ciphertext",
        "sig": SIG,
    }

    result = validate_nip59_gift_wrap_event(event)

    assert result["ok"] is False
    assert "gift_wrap_must_have_exactly_one_receiver_p_tag" in result["errors"]


def test_kind10050_relay_list_contract():
    event = {
        "kind": 10050,
        "tags": [["relay", "wss://inbox.example"], ["relay", "wss://relay.example"]],
        "content": "",
    }

    result = validate_nip17_relay_list_event(event)

    assert result == {"ok": True, "errors": []}


def test_kind10050_rejects_non_relay_urls():
    event = {
        "kind": 10050,
        "tags": [["relay", "https://not-a-relay.example"]],
        "content": "",
    }

    result = validate_nip17_relay_list_event(event)

    assert result["ok"] is False
    assert "relay_tag_must_include_ws_or_wss_url" in result["errors"]
