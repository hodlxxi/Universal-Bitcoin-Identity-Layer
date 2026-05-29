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


def test_chat_broadcast_fans_out_to_each_active_socket_sid(app, monkeypatch):
    fake_socketio = FakeSocketIO()
    original_sockets = dict(ACTIVE_SOCKETS)
    original_history = list(CHAT_HISTORY)

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

        with app.test_request_context("/socket.io/"):
            session["logged_in_pubkey"] = "a" * 64
            socket_handlers._broadcast_chat_message("hello live", client_id="client-1")

        assert len(CHAT_HISTORY) == 1
        assert CHAT_HISTORY[0]["text"] == "hello live"
        assert CHAT_HISTORY[0]["client_id"] == "client-1"

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
