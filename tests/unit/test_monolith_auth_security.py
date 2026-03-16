import importlib
from datetime import datetime, timedelta, timezone


def _load_monolith():
    return importlib.import_module("app.app")


def test_api_verify_rejects_nostr_without_crypto_proof(monkeypatch):
    m = _load_monolith()

    challenge_id = "cid-nostr-1"
    pubkey = "02" + "a" * 64
    m.ACTIVE_CHALLENGES[challenge_id] = {
        "pubkey": pubkey,
        "label": "",
        "challenge": "HODLXXI:login:test",
        "created": datetime.now(timezone.utc),
        "expires": datetime.now(timezone.utc) + timedelta(minutes=5),
        "method": "nostr",
    }

    with m.app.test_request_context(
        "/api/verify",
        method="POST",
        json={"challenge_id": challenge_id, "pubkey": pubkey, "signature": "fake"},
    ):
        resp, status = m.api_verify()
        assert status == 501
        payload = resp.get_json()
        assert payload["error"].startswith("Verification method 'nostr'")


def test_api_verify_rejects_lightning_without_crypto_proof(monkeypatch):
    m = _load_monolith()

    challenge_id = "cid-ln-1"
    pubkey = "02" + "b" * 64
    m.ACTIVE_CHALLENGES[challenge_id] = {
        "pubkey": pubkey,
        "label": "",
        "challenge": "HODLXXI:login:test",
        "created": datetime.now(timezone.utc),
        "expires": datetime.now(timezone.utc) + timedelta(minutes=5),
        "method": "lightning",
    }

    with m.app.test_request_context(
        "/api/verify",
        method="POST",
        json={"challenge_id": challenge_id, "pubkey": pubkey, "signature": "fake"},
    ):
        resp, status = m.api_verify()
        assert status == 501
        payload = resp.get_json()
        assert payload["error"].startswith("Verification method 'lightning'")


def test_finish_login_sets_secure_and_httponly_cookies_in_production(monkeypatch):
    m = _load_monolith()

    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.delenv("SECURE_COOKIES", raising=False)
    monkeypatch.delenv("ACCESS_COOKIE_HTTPONLY", raising=False)
    monkeypatch.setattr(m, "on_successful_login", lambda pubkey: {"pubkey": pubkey})
    monkeypatch.setattr(m, "mint_access_token", lambda sub=None, scope=None: "at-test")
    monkeypatch.setattr(m, "AT_TTL", 900, raising=False)
    monkeypatch.setattr(m, "RT_TTL", 2592000, raising=False)

    with m.app.test_request_context("/", method="GET"):
        resp = m.jsonify({"ok": True})
        out = m._finish_login(resp, "02" + "c" * 64, "limited")
        cookies = out.headers.getlist("Set-Cookie")

    at_cookie = next(c for c in cookies if c.startswith("at="))
    assert "Secure" in at_cookie
    assert "HttpOnly" in at_cookie
