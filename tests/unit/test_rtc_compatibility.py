import inspect
import pathlib
import time

from app.factory import create_app


def test_turn_credentials_returns_ice_servers_with_secret(monkeypatch):
    monkeypatch.setenv("TURN_HOST", "turn.test.example")
    monkeypatch.setenv("TURN_SECRET", "test-secret")
    monkeypatch.setenv("TURN_TTL", "60")
    app = create_app()
    app.config.update(TESTING=True)

    response = app.test_client().get("/turn_credentials")

    assert response.status_code == 200
    payload = response.get_json()
    assert isinstance(payload, dict)
    assert "iceServers" in payload
    assert isinstance(payload["iceServers"], list)
    assert payload["iceServers"][0]["urls"] == ["stun:turn.test.example:3478"]
    assert "test-secret" not in response.get_data(as_text=True)

    turn_server = payload["iceServers"][1]
    username = turn_server["username"]
    assert int(time.time()) <= int(username) <= int(time.time()) + 60
    assert turn_server["credential"]
    assert turn_server["credential"] != "test-secret"


def test_turn_credentials_missing_secret_returns_stun_fallback(monkeypatch):
    monkeypatch.delenv("TURN_SECRET", raising=False)
    app = create_app()
    app.config.update(TESTING=True)

    response = app.test_client().get("/turn_credentials")

    assert response.status_code == 200
    payload = response.get_json()
    assert isinstance(payload, dict)
    assert isinstance(payload["iceServers"], list)
    assert payload["iceServers"] == [{"urls": "stun:stun.l.google.com:19302"}]
    assert payload["warning"] == "TURN_SECRET not configured"


def test_debug_session_returns_only_safe_keys():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "a" * 64
        sess["guest_label"] = "Guest"
        sess["access_level"] = "guest"
        sess["login_method"] = "guest"
        sess["token"] = "secret-token"

    response = client.get("/api/debug/session")

    assert response.status_code == 200
    payload = response.get_json()
    assert set(payload) == {
        "ok",
        "authenticated",
        "pubkey",
        "pubkey_tail",
        "guest_label",
        "access_level",
        "login_method",
    }
    assert payload["authenticated"] is True
    assert payload["pubkey_tail"] == "a" * 8


def test_browser_webrtc_source_has_ice_ordering_guards():
    import app.browser_routes as browser_routes

    source = inspect.getsource(browser_routes)

    assert "function queueIceCandidate(remotePk, candidate)" in source
    assert "async function flushPendingIce(remotePk)" in source
    assert "!pc || !pc.remoteDescription" in source
    assert "await flushPendingIce(remotePk);" in source
    assert "await pc.addIceCandidate(new RTCIceCandidate(data.payload));" in source
    assert 'console.warn("Ignoring unexpected answer in state", pc.signalingState, remotePk)' not in source

    create_pc_block = source.split("async function createPC(remotePk){", 1)[1].split(
        "function queueIceCandidate(remotePk, candidate)", 1
    )[0]
    assert "pendingIceCandidates" not in create_pc_block


def test_rtc_compatibility_tests_do_not_reimplement_sha1_derivation():
    source = pathlib.Path(__file__).read_text(encoding="utf-8")

    assert "hashlib" + ".sha1" not in source
    assert "hmac" + ".new" not in source
