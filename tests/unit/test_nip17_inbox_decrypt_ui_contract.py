"""NIP-17 inbox decrypt UI contract.

The authenticated browser shell must let a logged-in receiver load opaque
encrypted envelopes and decrypt them locally in the browser. The server must
not decrypt or receive plaintext.
"""

from pathlib import Path

BROWSER_SHELL = Path("app/browser_shell_routes.py")


def _source() -> str:
    return BROWSER_SHELL.read_text(encoding="utf-8")


def test_messages_panel_contains_inbox_ui():
    text = _source()

    assert 'id="nip17LoadInboxButton"' in text
    assert 'id="nip17InboxStatus"' in text
    assert 'id="nip17InboxList"' in text
    assert "Load encrypted inbox" in text
    assert "Encrypted Inbox" in text


def test_inbox_loader_fetches_envelopes_with_explicit_envelope_opt_in():
    text = _source()

    assert "async function loadNip17Inbox" in text
    assert "/api/messages/nip17/inbox/envelopes?limit=20&include_envelope=1" in text
    assert "credentials: 'same-origin'" in text
    assert "renderNip17InboxItems(payload)" in text


def test_inbox_items_are_kept_browser_local_for_decrypt():
    text = _source()

    assert "window.HODLXXI_NIP17_INBOX_ITEMS" in text
    assert "function renderNip17InboxItems" in text
    assert "decryptNip17InboxEnvelope" in text
    assert "nip17InboxPlaintext_" in text


def test_decrypt_uses_browser_nip44_only():
    text = _source()

    assert "async function decryptNip17InboxEnvelope" in text
    assert "window.nostr.nip44.decrypt" in text
    assert "nip44_decrypt_required" in text
    assert "const plaintext = await window.nostr.nip44.decrypt(senderPubkey, envelope.content)" in text


def test_decrypt_ui_preserves_no_plaintext_server_invariants():
    text = _source()

    assert "DECRYPTED LOCALLY" in text
    assert "plaintext_fetched_from_server: false" in text
    assert "plaintext_sent_to_server: false" in text
    assert "server_decrypts: false" in text
    assert "key_custody: false" in text
    assert "No plaintext fallback is allowed." in text


def test_decrypt_ui_does_not_post_plaintext():
    text = _source()

    assert "body: JSON.stringify({plaintext" not in text
    assert "body: JSON.stringify({ message" not in text
    assert "plaintext_fetched_from_server: true" not in text
    assert "server_decrypts: true" not in text
    assert "key_custody: true" not in text
