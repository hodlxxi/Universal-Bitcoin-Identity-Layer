"""NIP-59 gift-wrap finalization contract.

P19 documents the boundary between the browser's local P18 skeleton and the
server's accepted opaque transport format.

The server accepts only finalized relay-visible kind-1059 gift wraps with
id/pubkey/sig/content and exactly one receiver p-tag. The P18 frontend skeleton
is intentionally not postable yet.
"""

from app.services.nostr_dm import validate_nip59_gift_wrap_event

RECEIVER = "a" * 64
WRAPPER = "b" * 64
EVENT_ID = "c" * 64
SIG = "d" * 128


def _final_gift_wrap(**overrides):
    event = {
        "id": EVENT_ID,
        "pubkey": WRAPPER,
        "created_at": 1780307952,
        "kind": 1059,
        "tags": [["p", RECEIVER]],
        "content": "opaque-gift-wrap-ciphertext",
        "sig": SIG,
    }
    event.update(overrides)
    return event


def test_nip59_validator_accepts_finalized_gift_wrap_shape():
    result = validate_nip59_gift_wrap_event(_final_gift_wrap())

    assert result == {"ok": True, "errors": []}


def test_nip59_validator_rejects_p18_skeleton_without_final_id_and_sig():
    skeleton_like = {
        "kind": 1059,
        "pubkey": WRAPPER,
        "created_at": 1780307952,
        "tags": [["p", RECEIVER]],
        "content": "opaque-gift-wrap-ciphertext",
    }

    result = validate_nip59_gift_wrap_event(skeleton_like)

    assert result["ok"] is False
    assert "id_must_be_64_hex" in result["errors"]
    assert "sig_must_be_128_hex" in result["errors"]


def test_nip59_validator_requires_exactly_one_receiver_p_tag():
    none = validate_nip59_gift_wrap_event(_final_gift_wrap(tags=[]))
    assert none["ok"] is False
    assert "gift_wrap_must_have_exactly_one_receiver_p_tag" in none["errors"]

    many = validate_nip59_gift_wrap_event(_final_gift_wrap(tags=[["p", RECEIVER], ["p", "e" * 64]]))
    assert many["ok"] is False
    assert "gift_wrap_must_have_exactly_one_receiver_p_tag" in many["errors"]


def test_nip59_validator_requires_opaque_content():
    result = validate_nip59_gift_wrap_event(_final_gift_wrap(content=""))

    assert result["ok"] is False
    assert "content_ciphertext_required" in result["errors"]


def test_frontend_p18_skeleton_is_explicitly_not_publishable():
    from pathlib import Path

    text = Path("app/browser_routes.py").read_text(encoding="utf-8")

    assert "Skeleton only: gift-wrap is not finalized/signed with ephemeral key in this PR. Do not publish." in text
    assert "gift_wrap_id_hint" in text
    assert "posted_to_server: false" in text
    assert "relay_publishing: false" in text
    assert (
        "fetch('/api/messages/nip17/envelopes'"
        not in text[
            text.index("async function buildNip17LocalEnvelopePreflight()") : text.index(
                "function initNip17ComposeCapabilityPanel()"
            )
        ]
    )
