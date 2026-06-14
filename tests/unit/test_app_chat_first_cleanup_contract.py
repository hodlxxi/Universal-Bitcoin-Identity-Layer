"""Chat-first /app cleanup contract.

The /app surface should prioritize Global Chat while preserving the existing
Socket.IO chat flow. Private encrypted messaging should be linked out to
/home#messages, with diagnostics hidden behind an advanced disclosure.
"""

from pathlib import Path

APP_BROWSER = Path("app/browser_routes.py")


def test_app_surface_is_chat_first_with_private_messages_shortcut():
    text = APP_BROWSER.read_text(encoding="utf-8")

    assert '<div class="panel-title">Global Chat</div>' in text
    assert "chat-first · live room" in text
    assert "Private messages" in text
    assert "Open Private Messages" in text
    assert "/home#messages" in text
    assert "Advanced messaging diagnostics" in text


def test_app_keeps_global_chat_frontend_contract():
    text = APP_BROWSER.read_text(encoding="utf-8")

    required = [
        'id="messages" class="message-list"',
        'id="chatInput"',
        'id="sendBtn"',
        "function sendMessage()",
        "socket.on('chat:history'",
        "socket.on('chat:message'",
        "socket.emit('chat:send'",
    ]

    for needle in required:
        assert needle in text


def test_app_diagnostics_are_not_the_primary_visible_title():
    text = APP_BROWSER.read_text(encoding="utf-8")

    section_start = text.index('<section id="hybridMessagingStatus"')
    layout_start = text.index('<section class="layout"', section_start)
    section = text[section_start:layout_start]

    assert '<div class="panel-title">Global Chat</div>' in section
    assert '<div class="panel-title">Hybrid Messaging</div>' not in section
    assert "<summary" in section
    assert "Advanced messaging diagnostics" in section


def test_app_preserves_hidden_nip17_nip59_diagnostic_ids_for_existing_js():
    text = APP_BROWSER.read_text(encoding="utf-8")

    for needle in [
        'id="nip17InboxCount"',
        'id="nip17ReceiverSupported"',
        'id="nip17InboxRows"',
        'id="nip17SignerStatus"',
        'id="nip59BundleStatus"',
        'id="nip59SendStatus"',
        "function initNip17ComposeCapabilityPanel",
        "async function refreshNip17InboxStatus",
    ]:
        assert needle in text
