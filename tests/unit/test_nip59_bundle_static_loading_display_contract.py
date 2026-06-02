"""NIP-59 bundle static loading/display contract.

P26 makes the read-only skeleton bundle display deterministic without enabling
crypto, POST, send, intake, or relay publishing.
"""

from pathlib import Path

BROWSER = Path("app/browser_routes.py")
BUNDLE = Path("app/static/js/nip59_client_bundle.js")


def test_static_bundle_exists_and_exports_read_only_skeleton_global():
    text = BUNDLE.read_text(encoding="utf-8")

    assert "HODLXXI_NIP59_CLIENT" in text
    assert 'status: "skeleton"' in text
    assert "cryptoReady: false" in text
    assert "canFinalizeGiftWrap: false" in text
    assert "canPostEnvelope: false" in text
    assert "relayPublishing: false" in text
    assert "plaintextPost: false" in text
    assert "fetch(" not in text
    assert "XMLHttpRequest" not in text


def test_app_loads_local_bundle_before_inline_capability_reader():
    text = BROWSER.read_text(encoding="utf-8")

    bundle_idx = text.index('<script src="/static/js/nip59_client_bundle.js"></script>')
    reader_idx = text.index("function updateNip59BundleCapabilityDisplay()")

    assert bundle_idx < reader_idx


def test_bundle_display_is_rescheduled_after_load_to_avoid_race():
    text = BROWSER.read_text(encoding="utf-8")

    assert "function scheduleNip59BundleCapabilityDisplay()" in text
    assert "scheduleNip59BundleCapabilityDisplay();" in text
    assert "setTimeout(updateNip59BundleCapabilityDisplay, 0);" in text
    assert "setTimeout(updateNip59BundleCapabilityDisplay, 250);" in text
    assert "window.addEventListener('load', updateNip59BundleCapabilityDisplay, { once: true });" in text


def test_bundle_display_still_does_not_enable_send_or_post():
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
