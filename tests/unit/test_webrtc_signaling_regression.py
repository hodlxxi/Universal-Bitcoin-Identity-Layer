import inspect

from app.factory import create_app


def test_socketio_registers_room_and_invite_events():
    app = create_app()
    socketio = app.extensions.get("socketio")
    handlers = socketio.server.handlers.get("/", {})

    assert "rtc:join_room" in handlers
    assert "rtc:leave_room" in handlers
    assert "rtc:signal" in handlers
    assert "rtc:invite" in handlers
    assert "rtc:call_invite" in handlers


def test_browser_group_call_handles_peer_join_and_queued_ice():
    import app.browser_routes as browser_routes

    source = inspect.getsource(browser_routes)

    assert 'socket.on("rtc:peer_joined", handlePeerJoined);' in source
    assert "pendingIceCandidates" in source
    assert "stream.addTrack(e.track)" in source
