"""NIP-59 bundle capability display contract.

P25 wires the zero-dependency skeleton bundle into /app as read-only status only.
"""

from pathlib import Path

BROWSER = Path("app/browser_routes.py")


def test_app_loads_local_nip59_bundle_only():
    text = BROWSER.read_text(encoding="utf-8")

    assert '<script src="/static/js/nip59_client_bundle.js"></script>' in text
    assert "https://unpkg.com/nostr-tools" not in text
    assert "https://cdn.jsdelivr.net/npm/nostr-tools" not in text


def test_compose_panel_displays_nip59_bundle_capabilities():
    text = BROWSER.read_text(encoding="utf-8")

    assert 'id="nip59BundleStatus"' in text
    assert 'id="nip59CryptoReady"' in text
    assert 'id="nip59CanFinalizeGiftWrap"' in text
    assert 'id="nip59CanPostEnvelope"' in text


def test_bundle_display_reads_frozen_skeleton_capability_only():
    text = BROWSER.read_text(encoding="utf-8")

    assert "function updateNip59BundleCapabilityDisplay()" in text
    assert "window.HODLXXI_NIP59_CLIENT" in text
    assert "client.status || 'unavailable'" in text
    assert "client.cryptoReady === true" in text
    assert "client.canFinalizeGiftWrap === true" in text
    assert "client.canPostEnvelope === true" in text


def test_bundle_display_does_not_enable_send_or_post():
    text = BROWSER.read_text(encoding="utf-8")
    region = text[
        text.index("function updateNip59BundleCapabilityDisplay()") : text.index(
            "function nip17Timeout(promise, ms, label)"
        )
    ]

    assert "fetch(" not in region
    assert "XMLHttpRequest" not in region
    assert "nip17SendPlaceholderBtn" not in region
    assert "NIP17_MESSAGES_ENABLED" not in region

    assert 'id="nip17SendPlaceholderBtn" class="nip17-compose-btn" type="button" disabled' in text
    assert "if (sendBtn) sendBtn.disabled = true;" in text
