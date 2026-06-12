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


def test_nip17_message_ui_skeleton_is_policy_gated_by_default():
    text = _source()

    assert "NIP17_MESSAGES_UI_SKELETON_V1" in text
    assert "window.HODLXXI_NIP17_SEND_ENABLED = false" in text
    assert 'data-nip17-send-enabled="false"' in text
    assert "encrypted site-local intake is disabled by server policy" in text


def test_nip17_message_ui_skeleton_posts_only_policy_gated_envelope():
    text = _source()

    skeleton = text.split("NIP17_MESSAGES_UI_SKELETON_V1", 1)[1]

    assert "function fetchNip17Policy" in skeleton
    assert "!policy.enabled || !policy.intake_enabled" in skeleton
    assert "fetch('/api/messages/nip17/envelopes'" in skeleton
    assert "body: JSON.stringify({envelope})" in skeleton
    assert "No POST was made." in skeleton
    assert "No relay publish was attempted." in skeleton


def test_nip17_message_ui_skeleton_preserves_no_plaintext_no_custody_claims():
    text = _source()

    skeleton = text.split("NIP17_MESSAGES_UI_SKELETON_V1", 1)[1]

    assert "plaintext_sent_to_server: false" in skeleton
    assert "server_decrypts: false" in skeleton
    assert "key_custody: false" in skeleton
    assert "No plaintext fallback is allowed." in skeleton
