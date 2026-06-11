"""NIP-17 browser send boundary contract.

This adds validation/build boundaries for future browser-side encrypted send,
but it must remain no-send: no server POST, no relay publish, no plaintext
transport, no decryption, and no key custody.
"""

from pathlib import Path

BROWSER_SHELL = Path("app/browser_shell_routes.py")


def _source() -> str:
    return BROWSER_SHELL.read_text(encoding="utf-8")


def _boundary_source() -> str:
    text = _source()
    assert "function normalizeNip17Recipient" in text
    return text.split("function normalizeNip17Recipient", 1)[1]


def test_nip17_browser_send_boundary_functions_exist():
    text = _source()

    assert "function normalizeNip17Recipient" in text
    assert "function validateNip17MessageDraft" in text
    assert "function buildNip17SendDraft" in text
    assert "function renderNip17NoSendStatus" in text


def test_nip17_browser_send_boundary_validates_inputs():
    text = _boundary_source()

    assert "recipient_required" in text
    assert "recipient_must_be_npub_or_hex_pubkey" in text
    assert "message_required" in text
    assert "message_too_large" in text
    assert "4000" in text


def test_nip17_browser_send_boundary_is_no_send():
    text = _boundary_source()

    assert "window.HODLXXI_NIP17_SEND_ENABLED = false" in _source()
    assert "no_send: true" in text
    assert "send_enabled: false" in text
    assert "will_post_to_server: false" in text
    assert "relay_publishing: false" in text


def test_nip17_browser_send_boundary_preserves_security_claims():
    text = _boundary_source()

    assert "plaintext_local_only: true" in text
    assert "server_decrypts: false" in text
    assert "key_custody: false" in text
    assert "does not send plaintext" in text
    assert "does not decrypt" in text
    assert "does not take key custody" in text


def test_nip17_browser_send_boundary_does_not_perform_network_send():
    text = _boundary_source()

    assert "fetch('/api/messages/nip17/envelopes'" not in text
    assert 'fetch("/api/messages/nip17/envelopes"' not in text
    assert "method: 'POST'" not in text
    assert 'method: "POST"' not in text
