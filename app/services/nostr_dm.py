"""Nostr DM / NIP-17 contract helpers.

This module validates public event *shapes* only. It does not encrypt,
decrypt, sign, publish, store plaintext, or require custody of user keys.
"""

from __future__ import annotations

from urllib.parse import urlparse
from typing import Any

NIP17_CHAT_KINDS = {14, 15}
NIP59_SEAL_KIND = 13
NIP59_GIFT_WRAP_KIND = 1059
NIP17_RELAY_LIST_KIND = 10050


def _is_hex(value: Any, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    return all(ch in "0123456789abcdefABCDEF" for ch in value)


def _tags(event: dict[str, Any]) -> list[list[Any]]:
    tags = event.get("tags")
    if not isinstance(tags, list):
        return []
    return [tag for tag in tags if isinstance(tag, list) and tag]


def _tag_values(event: dict[str, Any], tag_name: str) -> list[list[Any]]:
    return [tag for tag in _tags(event) if tag and tag[0] == tag_name]


def _is_valid_relay_url(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    parsed = urlparse(value)
    return parsed.scheme in {"ws", "wss"} and bool(parsed.netloc)


def validate_nip17_unsigned_event(event: Any) -> dict[str, Any]:
    """Validate the unsigned kind-14/kind-15 event shape before wrapping.

    NIP-17 plaintext message/file events are not the server transport format.
    They must be sealed and gift-wrapped before relay/server transport.
    """

    errors: list[str] = []

    if not isinstance(event, dict):
        return {"ok": False, "errors": ["event_must_be_object"]}

    kind = event.get("kind")
    if kind not in NIP17_CHAT_KINDS:
        errors.append("kind_must_be_14_or_15")

    if not _is_hex(event.get("id"), 64):
        errors.append("id_must_be_64_hex")

    if not _is_hex(event.get("pubkey"), 64):
        errors.append("pubkey_must_be_64_hex")

    if not isinstance(event.get("created_at"), int):
        errors.append("created_at_must_be_int")

    if not isinstance(event.get("content"), str):
        errors.append("content_must_be_string")

    if "sig" in event:
        errors.append("unsigned_nip17_event_must_not_have_sig")

    p_tags = _tag_values(event, "p")
    if not p_tags:
        errors.append("at_least_one_p_tag_required")

    for tag in p_tags:
        if len(tag) < 2 or not _is_hex(tag[1], 64):
            errors.append("p_tag_pubkey_must_be_64_hex")
            break
        if len(tag) >= 3 and tag[2] and not _is_valid_relay_url(tag[2]):
            errors.append("p_tag_relay_must_be_ws_or_wss")
            break

    if kind == 15:
        required_file_tags = {
            "file-type",
            "encryption-algorithm",
            "decryption-key",
            "decryption-nonce",
            "x",
        }
        present = {str(tag[0]) for tag in _tags(event)}
        missing = sorted(required_file_tags - present)
        if missing:
            errors.append(f"missing_file_tags:{','.join(missing)}")

    return {"ok": not errors, "errors": errors}


def validate_nip59_gift_wrap_event(event: Any) -> dict[str, Any]:
    """Validate the relay-visible NIP-59 gift-wrap event shape."""

    errors: list[str] = []

    if not isinstance(event, dict):
        return {"ok": False, "errors": ["event_must_be_object"]}

    if event.get("kind") != NIP59_GIFT_WRAP_KIND:
        errors.append("kind_must_be_1059")

    if not _is_hex(event.get("id"), 64):
        errors.append("id_must_be_64_hex")

    if not _is_hex(event.get("pubkey"), 64):
        errors.append("pubkey_must_be_64_hex")

    if not isinstance(event.get("created_at"), int):
        errors.append("created_at_must_be_int")

    if not isinstance(event.get("content"), str) or not event.get("content"):
        errors.append("content_ciphertext_required")

    if not _is_hex(event.get("sig"), 128):
        errors.append("sig_must_be_128_hex")

    p_tags = _tag_values(event, "p")
    if len(p_tags) != 1:
        errors.append("gift_wrap_must_have_exactly_one_receiver_p_tag")
    elif len(p_tags[0]) < 2 or not _is_hex(p_tags[0][1], 64):
        errors.append("receiver_p_tag_pubkey_must_be_64_hex")

    return {"ok": not errors, "errors": errors}


def validate_nip17_relay_list_event(event: Any) -> dict[str, Any]:
    """Validate kind-10050 DM relay-list event shape."""

    errors: list[str] = []

    if not isinstance(event, dict):
        return {"ok": False, "errors": ["event_must_be_object"]}

    if event.get("kind") != NIP17_RELAY_LIST_KIND:
        errors.append("kind_must_be_10050")

    relay_tags = _tag_values(event, "relay")
    if not relay_tags:
        errors.append("at_least_one_relay_tag_required")

    for tag in relay_tags:
        if len(tag) < 2 or not _is_valid_relay_url(tag[1]):
            errors.append("relay_tag_must_include_ws_or_wss_url")
            break

    if "content" in event and not isinstance(event.get("content"), str):
        errors.append("content_must_be_string")

    return {"ok": not errors, "errors": errors}
