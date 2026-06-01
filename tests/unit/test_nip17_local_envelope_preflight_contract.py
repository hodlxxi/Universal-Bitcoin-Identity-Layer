"""NIP-17 local envelope preflight contract.

P17 enables local-only recipient/message readiness checks. It must not POST to
the server or enable delivery.
"""

from pathlib import Path


def test_nip17_local_preflight_ui_is_rendered():
    text = Path("app/browser_routes.py").read_text(encoding="utf-8")

    assert 'id="nip17RecipientValid"' in text
    assert 'id="nip17MessagePresent"' in text
    assert 'id="nip17LocalBuildReady"' in text
    assert 'id="nip17BuildLocalBtn"' in text
    assert "Build local envelope" in text


def test_nip17_local_preflight_tracks_recipient_message_and_signer_state():
    text = Path("app/browser_routes.py").read_text(encoding="utf-8")

    assert "function getNip17LocalBuildState()" in text
    assert "function updateNip17LocalBuildState()" in text
    assert "function buildNip17LocalEnvelopePreflight()" in text
    assert "recipientValid = /^[0-9a-f]{64}$/.test(recipient)" in text
    assert "messagePresent = message.trim().length > 0" in text
    assert "signerReady = !!window.__nip17PreflightReady" in text
    assert "ready = signerReady && recipientValid && messagePresent" in text


def test_nip17_local_preflight_only_enables_local_builder_not_send():
    text = Path("app/browser_routes.py").read_text(encoding="utf-8")

    assert "if (recipientInput) recipientInput.disabled = !signerReady;" in text
    assert "if (messageInput) messageInput.disabled = !signerReady;" in text
    assert "if (buildBtn) buildBtn.disabled = !state.ready;" in text
    assert "if (sendBtn) sendBtn.disabled = true;" in text


def test_nip17_local_preflight_does_not_post_or_publish():
    text = Path("app/browser_routes.py").read_text(encoding="utf-8")
    region = text[
        text.index("function buildNip17LocalEnvelopePreflight()") : text.index(
            "function initNip17ComposeCapabilityPanel()"
        )
    ]

    assert "posted_to_server: false" in region
    assert "relay_publishing: false" in region
    assert "local_only: true" in region
    assert "fetch('/api/messages/nip17/envelopes'" not in region
    assert 'fetch("/api/messages/nip17/envelopes"' not in region
    assert "NIP17_MESSAGES_ENABLED" not in region
