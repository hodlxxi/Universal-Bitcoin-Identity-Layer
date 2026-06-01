"""NIP-17 compose capability panel contract.

P14 is UI-only capability detection. It must not imply server-side plaintext
handling, key custody, relay publishing, or enabled intake.
"""

from pathlib import Path


def test_nip17_compose_capability_panel_is_rendered():
    text = Path("app/browser_routes.py").read_text(encoding="utf-8")

    assert "Compose sealed message" in text
    assert 'id="nip17SignerStatus"' in text
    assert 'id="nip17SignerPubkey"' in text
    assert 'id="nip17RecipientInput"' in text
    assert 'id="nip17MessageInput"' in text
    assert 'id="nip17CheckSignerBtn"' in text
    assert 'id="nip17SendPlaceholderBtn"' in text


def test_nip17_compose_capability_panel_is_safe_by_default():
    text = Path("app/browser_routes.py").read_text(encoding="utf-8")

    assert "No plaintext is sent to the server" in text
    assert 'id="nip17SendPlaceholderBtn" class="nip17-compose-btn" type="button" disabled' in text
    assert (
        'class="nip17-compose-textarea" rows="3" placeholder="Client-side encryption required before sending" disabled'
        in text
    )
    assert (
        'class="nip17-compose-input" type="text" autocomplete="off" placeholder="64-hex recipient pubkey" disabled'
        in text
    )
    assert ".nip17-compose-btn:disabled" in text
    assert ".nip17-compose-actions" in text
    assert ".nip17-compose-field" in text


def test_nip17_compose_detects_nip07_without_auto_requesting_key():
    text = Path("app/browser_routes.py").read_text(encoding="utf-8")

    assert "function initNip17ComposeCapabilityPanel()" in text
    assert "window.nostr" in text
    assert "typeof window.nostr.getPublicKey === 'function'" in text
    assert "checkBtn.addEventListener('click'" in text
    assert "await signer.getPublicKey()" in text


def test_nip17_compose_does_not_post_plaintext_or_enable_intake():
    text = Path("app/browser_routes.py").read_text(encoding="utf-8")

    compose_region = text[
        text.index("function initNip17ComposeCapabilityPanel()") : text.index(
            "async function refreshNip17InboxStatus()"
        )
    ]

    assert "fetch('/api/messages/nip17/envelopes'" not in compose_region
    assert 'fetch("/api/messages/nip17/envelopes"' not in compose_region
    assert "NIP17_MESSAGES_ENABLED" not in compose_region
    assert "relay publishing" not in compose_region.lower()
    assert "private key" not in compose_region.lower()
