"""Read-only NIP-17 inbox panel UI contract."""

import inspect

import app.browser_routes as browser_routes


def test_app_contains_readonly_nip17_inbox_panel():
    source = inspect.getsource(browser_routes)

    required = [
        "Hybrid Messaging",
        "Encrypted inbox",
        "nip17InboxSummary",
        "nip17InboxRows",
        "renderNip17InboxRows",
        "refreshNip17InboxRows",
        "/api/messages/nip17/inbox/status",
        "/api/messages/nip17/inbox/envelopes?limit=10",
        "metadata is read-only",
    ]

    for needle in required:
        assert needle in source


def test_inbox_panel_does_not_render_forbidden_envelope_material_fields():
    source = inspect.getsource(browser_routes)

    forbidden = [
        "envelope_json",
        "item.content",
        "item.sig",
        "nip44_decrypt",
        "decryptNip17",
    ]

    for needle in forbidden:
        assert needle not in source


def test_inbox_panel_preserves_existing_live_chat_and_call_markers():
    source = inspect.getsource(browser_routes)

    required = [
        "socket.on('chat:history'",
        "socket.on('chat:message'",
        "socket.emit('chat:send'",
        "rtc:join_room",
        "GroupCallManager",
        "function sendMessage()",
    ]

    for needle in required:
        assert needle in source
