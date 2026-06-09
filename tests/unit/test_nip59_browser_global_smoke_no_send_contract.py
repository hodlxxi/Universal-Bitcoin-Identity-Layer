"""Contract tests for P48 NIP-59 browser global no-send smoke."""

from pathlib import Path

import scripts.smoke_nip59_browser_global_no_send as smoke

SCRIPT = Path("scripts/smoke_nip59_browser_global_no_send.py")
DOC = Path("docs/ops/NIP59_BROWSER_GLOBAL_SMOKE_NO_SEND.md")
BUNDLE = Path("app/static/js/nip59_client_bundle.js")


def test_smoke_script_exists_and_is_no_install_no_send():
    text = SCRIPT.read_text(encoding="utf-8")

    assert "urllib.request" in text
    assert "npm" not in text.lower()
    assert "/api/messages/nip17/envelopes" in text
    assert "publish(" in text
    assert "SimplePool" in text


def test_live_bundle_passes_browser_global_no_send_smoke():
    text = BUNDLE.read_text(encoding="utf-8", errors="replace")
    assert smoke.inspect_bundle(text) == []


def test_live_bundle_exposes_expected_global_name():
    text = BUNDLE.read_text(encoding="utf-8", errors="replace")

    assert "HODLXXINip59Bundle" in text
    assert "generated-experiment-no-send" in text
    assert "sendEnabled: false" in text
    assert "canPostEnvelope: false" in text
    assert "relayPublishing: false" in text


def test_doc_records_browser_global_smoke_boundary():
    text = DOC.read_text(encoding="utf-8")

    assert "This is not a messaging enablement step." in text
    assert "HODLXXINip59Bundle" in text
    assert "sendEnabled=false" in text
    assert "intake_enabled=false" in text
    assert "relay_publishing=false" in text
