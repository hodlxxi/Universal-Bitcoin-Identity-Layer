"""Socket.IO chat broadcast fanout contracts."""

from flask import session

import app.socket_handlers as socket_handlers
from app.socket_state import ACTIVE_SOCKETS, CHAT_HISTORY


class FakeSocketIO:
    def __init__(self):
        self.emits = []

    def emit(self, event, payload, **kwargs):
        self.emits.append(
            {
                "event": event,
                "payload": payload,
                "to": kwargs.get("to"),
                "namespace": kwargs.get("namespace"),
            }
        )


def test_chat_broadcast_uses_context_broadcast_and_fans_out_to_each_active_sid(app, monkeypatch):
    fake_socketio = FakeSocketIO()
    context_emits = []
    original_sockets = dict(ACTIVE_SOCKETS)
    original_history = list(CHAT_HISTORY)

    def fake_context_emit(event, payload, **kwargs):
        context_emits.append(
            {
                "event": event,
                "payload": payload,
                "broadcast": kwargs.get("broadcast"),
            }
        )

    try:
        ACTIVE_SOCKETS.clear()
        CHAT_HISTORY.clear()
        ACTIVE_SOCKETS.update(
            {
                "sid-sender": "a" * 64,
                "sid-receiver": "b" * 64,
            }
        )

        monkeypatch.setattr(socket_handlers, "get_socketio", lambda: fake_socketio)
        monkeypatch.setattr(socket_handlers, "emit", fake_context_emit)

        with app.test_request_context("/socket.io/"):
            session["logged_in_pubkey"] = "a" * 64
            socket_handlers._broadcast_chat_message("hello live", client_id="client-1")

        assert len(CHAT_HISTORY) == 1
        assert CHAT_HISTORY[0]["text"] == "hello live"
        assert CHAT_HISTORY[0]["client_id"] == "client-1"

        context_events = {(call["event"], call["broadcast"]) for call in context_emits}
        assert ("message", True) in context_events
        assert ("chat:message", True) in context_events

        emitted = {(call["event"], call["to"]) for call in fake_socketio.emits}
        assert ("message", "sid-sender") in emitted
        assert ("chat:message", "sid-sender") in emitted
        assert ("message", "sid-receiver") in emitted
        assert ("chat:message", "sid-receiver") in emitted

        assert all(call["namespace"] == "/" for call in fake_socketio.emits)
        assert all(call["to"] for call in fake_socketio.emits)
    finally:
        ACTIVE_SOCKETS.clear()
        ACTIVE_SOCKETS.update(original_sockets)
        CHAT_HISTORY[:] = original_history
