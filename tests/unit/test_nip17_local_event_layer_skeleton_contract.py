"""NIP-17 local event-layer skeleton contract.

P18 builds local-only rumor/seal/gift-wrap candidates. It must not POST,
publish, enable delivery, or claim production-compatible finalization.
"""

from pathlib import Path


def test_nip17_local_event_layer_skeleton_functions_are_present():
    text = Path("app/browser_routes.py").read_text(encoding="utf-8")

    assert "async function buildNip17LocalEnvelopePreflight()" in text
    assert "function nip17NowSeconds()" in text
    assert "function nip17LocalEventIdHint(event)" in text


def test_nip17_local_event_layer_skeleton_builds_expected_candidate_kinds():
    text = Path("app/browser_routes.py").read_text(encoding="utf-8")

    assert "kind: 14" in text
    assert "kind: 13" in text
    assert "kind: 1059" in text
    assert "rumor_candidate: true" in text
    assert "seal_candidate: true" in text
    assert "gift_wrap_candidate: true" in text


def test_nip17_local_event_layer_skeleton_uses_signer_crypto_locally():
    text = Path("app/browser_routes.py").read_text(encoding="utf-8")

    assert "await signer.nip44.encrypt(state.recipient, rumorPlaintext)" in text
    assert "await signer.signEvent(seal)" in text
    assert "await signer.nip44.encrypt(state.recipient, JSON.stringify(signedSeal))" in text


def test_nip17_local_event_layer_skeleton_is_not_delivery():
    text = Path("app/browser_routes.py").read_text(encoding="utf-8")
    region = text[
        text.index("async function buildNip17LocalEnvelopePreflight()") : text.index(
            "function initNip17ComposeCapabilityPanel()"
        )
    ]

    assert "posted_to_server: false" in region
    assert "relay_publishing: false" in region
    assert "local_only: true" in region
    assert "Do not publish" in region
    assert "fetch('/api/messages/nip17/envelopes'" not in region
    assert 'fetch("/api/messages/nip17/envelopes"' not in region
    assert "NIP17_MESSAGES_ENABLED" not in region


def test_nip17_local_event_layer_skeleton_keeps_send_disabled():
    text = Path("app/browser_routes.py").read_text(encoding="utf-8")

    assert "if (sendBtn) sendBtn.disabled = true;" in text
    assert 'id="nip17SendPlaceholderBtn" class="nip17-compose-btn" type="button" disabled' in text
