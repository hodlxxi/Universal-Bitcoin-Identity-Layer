"""NIP-17 Messages panel routing contract."""

from pathlib import Path

BROWSER_SHELL = Path("app/browser_shell_routes.py")


def _source() -> str:
    return BROWSER_SHELL.read_text(encoding="utf-8")


def test_messages_panel_has_button_form_and_send_button():
    text = _source()

    assert 'id="btnMessages"' in text
    assert 'id="messagesPanel"' in text
    assert 'id="nip17Recipient"' in text
    assert 'id="nip17Message"' in text
    assert 'id="nip17SendButton"' in text


def test_messages_button_targets_messages_hash_panel():
    text = _source()

    assert "btnMessages?.addEventListener('click', () => window.openPanel('messages'))" in text
    assert "messages" in text
    assert "messagesPanel" in text


def test_hash_router_includes_messages_panel_in_visibility_set():
    text = _source()

    assert "['homePanel','explorerPanel','onboardPanel','messagesPanel']" in text
    assert "hashchange" in text
    assert "switchPanelByHash" in text


def test_hash_router_can_select_messages_panel():
    text = _source()

    assert "messagesPanel" in text
    assert "messages" in text
    assert "target" in text
