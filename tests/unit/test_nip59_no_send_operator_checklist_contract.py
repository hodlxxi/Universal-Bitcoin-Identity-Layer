"""P51 contract: NIP-59 no-send operator checklist is documented."""

from pathlib import Path

DOC = Path("docs/ops/NIP59_NO_SEND_OPERATOR_CHECKLIST.md")


def test_operator_checklist_documents_manual_no_send_ui_check():
    text = DOC.read_text(encoding="utf-8")

    assert "NIP-59 bundle" in text
    assert "NIP-59 send: disabled" in text
    assert "NIP-59 POST: disabled" in text
    assert "NIP-59 relay: disabled" in text
    assert "https://hodlxxi.com/login?next=/app" in text


def test_operator_checklist_preserves_disabled_policy_boundary():
    text = DOC.read_text(encoding="utf-8")

    assert "enabled=false" in text
    assert "intake_enabled=false" in text
    assert "relay_publishing=false" in text
    assert "sendEnabled=true" in text
    assert "canPostEnvelope=true" in text
    assert "relayPublishing=true" in text


def test_operator_checklist_references_existing_smoke_gates():
    text = DOC.read_text(encoding="utf-8")

    assert "smoke_nip59_browser_global_no_send.py" in text
    assert "test_nip59_app_rendered_no_send_smoke_contract.py" in text
    assert "/api/messages/nip17/envelopes" in text
    assert "node_modules" in text
