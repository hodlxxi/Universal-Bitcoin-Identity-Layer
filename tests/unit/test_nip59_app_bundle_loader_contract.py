"""NIP-59 app bundle loader contract.

P28 ensures /app loads the read-only skeleton bundle even if the static script
tag is not present in the exact app HTML path.
"""

from pathlib import Path

BROWSER = Path("app/browser_routes.py")


def test_app_has_dynamic_nip59_bundle_loader():
    text = BROWSER.read_text(encoding="utf-8")

    assert "function ensureNip59BundleLoaded()" in text
    assert "document.createElement('script')" in text
    assert "script.src = '/static/js/nip59_client_bundle.js';" in text
    assert "script.dataset.hodlxxiNip59Client = 'true';" in text
    assert "document.head.appendChild(script);" in text


def test_loader_updates_display_after_bundle_load():
    text = BROWSER.read_text(encoding="utf-8")

    assert "ensureNip59BundleLoaded().then(() => {" in text
    assert "updateNip59BundleCapabilityDisplay();" in text
    assert "window.addEventListener('load', () => {" in text


def test_loader_is_read_only_and_does_not_enable_delivery():
    text = BROWSER.read_text(encoding="utf-8")
    region = text[
        text.index("function ensureNip59BundleLoaded()") : text.index("function nip17Timeout(promise, ms, label)")
    ]

    assert "fetch(" not in region
    assert "XMLHttpRequest" not in region
    assert "/api/messages/nip17/envelopes" not in region
    assert "nip17SendPlaceholderBtn" not in region
    assert "NIP17_MESSAGES_ENABLED" not in region


def test_send_button_remains_disabled_in_app_markup():
    text = BROWSER.read_text(encoding="utf-8")

    assert 'id="nip17SendPlaceholderBtn" class="nip17-compose-btn" type="button" disabled' in text
    assert "if (sendBtn) sendBtn.disabled = true;" in text
