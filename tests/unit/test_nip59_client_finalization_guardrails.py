"""NIP-59 client finalization guardrails.

P20 blocks unsafe hand-rolled browser crypto before real kind-1059 delivery.
"""

from pathlib import Path

DOC = Path("docs/ops/NIP59_CLIENT_FINALIZATION_GUARDRAILS.md")
BROWSER = Path("app/browser_routes.py")


def test_nip59_client_finalization_guardrail_doc_exists():
    text = DOC.read_text(encoding="utf-8")

    assert "ephemeral wrapper key generation" in text
    assert "Nostr event serialization" in text
    assert "SHA-256 event id calculation" in text
    assert "Schnorr signing" in text
    assert "Do not hand-roll" in text
    assert "Do not sign the final gift-wrap with the user's long-term Nostr signer key." in text


def test_current_browser_builder_remains_skeleton_not_finalized_delivery():
    text = BROWSER.read_text(encoding="utf-8")
    region = text[
        text.index("async function buildNip17LocalEnvelopePreflight()") : text.index(
            "function initNip17ComposeCapabilityPanel()"
        )
    ]

    assert "compatibility_warning" in region
    assert "Skeleton only" in region
    assert "Do not publish" in region
    assert "gift_wrap_id_hint" in region
    assert "gift_wrap_id_present" not in region
    assert "gift_wrap_sig_present" not in region


def test_browser_does_not_hand_roll_secp256k1_or_schnorr_finalization():
    text = BROWSER.read_text(encoding="utf-8")
    forbidden = [
        "secp256k1",
        "schnorr",
        "derivePrivateKey",
        "privateKey",
        "finalizeEvent",
        "getEventHash",
        "generateSecretKey",
        "generatePrivateKey",
    ]

    compose_region = text[
        text.index("async function buildNip17LocalEnvelopePreflight()") : text.index(
            "function initNip17ComposeCapabilityPanel()"
        )
    ]

    for token in forbidden:
        assert token not in compose_region


def test_delivery_still_disabled_until_finalization_dependency_is_chosen():
    text = BROWSER.read_text(encoding="utf-8")

    assert 'id="nip17SendPlaceholderBtn" class="nip17-compose-btn" type="button" disabled' in text
    assert "if (sendBtn) sendBtn.disabled = true;" in text

    compose_region = text[
        text.index("async function buildNip17LocalEnvelopePreflight()") : text.index(
            "function initNip17ComposeCapabilityPanel()"
        )
    ]

    assert "fetch('/api/messages/nip17/envelopes'" not in compose_region
    assert 'fetch("/api/messages/nip17/envelopes"' not in compose_region
    assert "NIP17_MESSAGES_ENABLED" not in compose_region
