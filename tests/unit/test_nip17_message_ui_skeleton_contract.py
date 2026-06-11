"""NIP-17 message UI skeleton contract.

The browser page may expose a message form, but this release must remain
strictly no-send: no POST, no relay publish, no plaintext transport, no
decryption, and no key custody.
"""

from pathlib import Path

BROWSER_SHELL = Path("app/browser_shell_routes.py")


def _source() -> str:
    return BROWSER_SHELL.read_text(encoding="utf-8")


def test_nip17_message_ui_skeleton_is_present():
    text = _source()

    assert 'id="btnMessages"' in text
    assert 'id="messagesPanel"' in text
    assert 'id="nip17Recipient"' in text
    assert 'id="nip17Message"' in text
    assert 'id="nip17SendButton"' in text
    assert 'id="nip17MessageStatus"' in text


def test_nip17_message_ui_skeleton_is_no_send_by_default():
    text = _source()

    assert "NIP17_MESSAGES_UI_SKELETON_V1" in text
    assert "window.HODLXXI_NIP17_SEND_ENABLED = false" in text
    assert 'data-nip17-send-enabled="false"' in text
    assert "NO-SEND: encrypted message sending is not enabled" in text


def test_nip17_message_ui_skeleton_does_not_post_or_publish():
    text = _source()

    skeleton = text.split("NIP17_MESSAGES_UI_SKELETON_V1", 1)[1]

    assert "fetch('/api/messages/nip17/envelopes'" not in skeleton
    assert 'fetch("/api/messages/nip17/envelopes"' not in skeleton
    assert "method: 'POST'" not in skeleton
    assert 'method: "POST"' not in skeleton
    assert "relay" in skeleton.lower()
    assert "does not publish to relays" in skeleton


def test_nip17_message_ui_skeleton_does_not_claim_crypto_or_custody():
    text = _source()

    skeleton = text.split("NIP17_MESSAGES_UI_SKELETON_V1", 1)[1]

    assert "does not send plaintext" in skeleton
    assert "does not decrypt" in skeleton
    assert "does not take key custody" in skeleton
