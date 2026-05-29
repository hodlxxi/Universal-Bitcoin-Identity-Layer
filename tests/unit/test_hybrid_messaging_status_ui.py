"""Hybrid messaging status UI contract for /app."""

from pathlib import Path


def test_app_chat_surface_documents_hybrid_messaging_status():
    source = Path("app/browser_routes.py").read_text(encoding="utf-8")

    required = [
        "Hybrid Messaging",
        "Live chat / calls",
        "Encrypted inbox",
        "NIP-17 / NIP-59",
        "Socket.IO",
        "self-erase after 45 seconds",
        "Server plaintext storage: <code>false</code>",
        "Server key custody: <code>false</code>",
        "intake disabled",
    ]

    for needle in required:
        assert needle in source


def test_hybrid_status_preserves_existing_chat_frontend_contracts():
    source = Path("app/browser_routes.py").read_text(encoding="utf-8")

    existing_frontend_markers = [
        "socket.on('chat:history'",
        "socket.on('chat:message'",
        "socket.emit('chat:send'",
        "const GroupCallManager",
        "function sendMessage()",
        "message-list",
        "chatInput",
        "sendBtn",
    ]

    for needle in existing_frontend_markers:
        assert needle in source


def test_hybrid_status_does_not_remove_existing_socketio_webrtc_handlers():
    source = Path("app/socket_handlers.py").read_text(encoding="utf-8")

    existing_backend_markers = [
        '@socketio.on("rtc:offer")',
        '@socketio.on("rtc:answer")',
        '@socketio.on("rtc:ice")',
        '@socketio.on("rtc:hangup")',
        '@socketio.on("rtc:join_room")',
        '@socketio.on("chat:send")',
        '@socketio.on("connect")',
        '@socketio.on("disconnect")',
    ]

    for needle in existing_backend_markers:
        assert needle in source
