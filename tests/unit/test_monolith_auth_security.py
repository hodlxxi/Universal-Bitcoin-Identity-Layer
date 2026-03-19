import importlib
import json
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace


def _load_monolith():
    return importlib.import_module("app.app")


def _seed_challenge(m, challenge_id, pubkey, challenge="HODLXXI:login:test", method="nostr"):
    m.ACTIVE_CHALLENGES[challenge_id] = {
        "pubkey": pubkey,
        "label": "",
        "challenge": challenge,
        "created": datetime.now(timezone.utc),
        "expires": datetime.now(timezone.utc) + timedelta(minutes=5),
        "method": method,
    }


def _install_fake_coincurve(monkeypatch, verifier):
    class FakePublicKeyXOnly:
        def __init__(self, raw_pubkey):
            self.raw_pubkey = raw_pubkey

        def verify(self, signature, message):
            return verifier(self.raw_pubkey, signature, message)

    monkeypatch.setitem(sys.modules, "coincurve", SimpleNamespace(PublicKeyXOnly=FakePublicKeyXOnly))


def _build_nostr_event(m, *, pubkey, challenge, created_at=None, sig=None, tags=None, content=None):
    created_at = int(created_at or datetime.now(timezone.utc).timestamp())
    event = {
        "pubkey": pubkey.lower(),
        "created_at": created_at,
        "kind": 22242,
        "tags": tags if tags is not None else [["challenge", challenge], ["app", "HODLXXI"]],
        "content": content if content is not None else f"HODLXXI Login: {challenge}",
        "sig": sig or ("11" * 64),
    }
    event["id"] = m._nostr_event_id(event)
    return event


def test_verify_nostr_login_event_accepts_valid_event(monkeypatch):
    m = _load_monolith()
    pubkey = "a" * 64
    challenge = "HODLXXI:login:test"
    event = _build_nostr_event(m, pubkey=pubkey, challenge=challenge)

    _install_fake_coincurve(
        monkeypatch,
        lambda raw_pubkey, signature, message: (
            raw_pubkey == bytes.fromhex(pubkey)
            and signature == bytes.fromhex(event["sig"])
            and message == bytes.fromhex(event["id"])
        ),
    )

    ok, error = m.verify_nostr_login_event(
        event,
        expected_pubkey=pubkey,
        expected_challenge=challenge,
        expected_verify_url="http://localhost/api/verify",
        now_ts=event["created_at"],
    )

    assert ok is True
    assert error is None


def test_verify_nostr_login_event_rejects_malformed_event(monkeypatch):
    m = _load_monolith()
    _install_fake_coincurve(monkeypatch, lambda *_: True)

    ok, error = m.verify_nostr_login_event(
        {"pubkey": "a" * 64},
        expected_pubkey="a" * 64,
        expected_challenge="challenge",
    )

    assert ok is False
    assert error == "Missing nostr_event field: id"


def test_verify_nostr_login_event_rejects_wrong_pubkey(monkeypatch):
    m = _load_monolith()
    challenge = "HODLXXI:login:test"
    event = _build_nostr_event(m, pubkey="a" * 64, challenge=challenge)
    _install_fake_coincurve(monkeypatch, lambda *_: True)

    ok, error = m.verify_nostr_login_event(
        event,
        expected_pubkey="b" * 64,
        expected_challenge=challenge,
        now_ts=event["created_at"],
    )

    assert ok is False
    assert error == "Pubkey mismatch"


def test_verify_nostr_login_event_rejects_wrong_challenge(monkeypatch):
    m = _load_monolith()
    event = _build_nostr_event(m, pubkey="a" * 64, challenge="HODLXXI:login:test")
    _install_fake_coincurve(monkeypatch, lambda *_: True)

    ok, error = m.verify_nostr_login_event(
        event,
        expected_pubkey="a" * 64,
        expected_challenge="HODLXXI:login:other",
        now_ts=event["created_at"],
    )

    assert ok is False
    assert error == "Challenge mismatch"


def test_verify_nostr_login_event_rejects_stale_created_at(monkeypatch):
    m = _load_monolith()
    created_at = int(datetime.now(timezone.utc).timestamp()) - (m.NOSTR_LOGIN_MAX_AGE_SECONDS + 1)
    event = _build_nostr_event(m, pubkey="a" * 64, challenge="HODLXXI:login:test", created_at=created_at)
    _install_fake_coincurve(monkeypatch, lambda *_: True)

    ok, error = m.verify_nostr_login_event(
        event,
        expected_pubkey="a" * 64,
        expected_challenge="HODLXXI:login:test",
    )

    assert ok is False
    assert error == "Nostr event is too old"


def test_verify_nostr_login_event_rejects_tampered_id(monkeypatch):
    m = _load_monolith()
    event = _build_nostr_event(m, pubkey="a" * 64, challenge="HODLXXI:login:test")
    event["id"] = "f" * 64
    _install_fake_coincurve(monkeypatch, lambda *_: True)

    ok, error = m.verify_nostr_login_event(
        event,
        expected_pubkey="a" * 64,
        expected_challenge="HODLXXI:login:test",
        now_ts=event["created_at"],
    )

    assert ok is False
    assert error == "Nostr event id mismatch"


def test_verify_nostr_login_event_rejects_tampered_sig(monkeypatch):
    m = _load_monolith()
    event = _build_nostr_event(m, pubkey="a" * 64, challenge="HODLXXI:login:test")
    _install_fake_coincurve(monkeypatch, lambda *_: False)

    ok, error = m.verify_nostr_login_event(
        event,
        expected_pubkey="a" * 64,
        expected_challenge="HODLXXI:login:test",
        now_ts=event["created_at"],
    )

    assert ok is False
    assert error == "Invalid nostr signature"


def test_api_verify_accepts_valid_nostr_event_and_consumes_challenge(monkeypatch):
    m = _load_monolith()
    challenge_id = "cid-nostr-1"
    pubkey = "a" * 64
    challenge = "HODLXXI:login:test"
    _seed_challenge(m, challenge_id, pubkey, challenge=challenge)
    event = _build_nostr_event(m, pubkey=pubkey, challenge=challenge)

    _install_fake_coincurve(
        monkeypatch,
        lambda raw_pubkey, signature, message: (
            raw_pubkey == bytes.fromhex(pubkey)
            and signature == bytes.fromhex(event["sig"])
            and message == bytes.fromhex(event["id"])
        ),
    )
    monkeypatch.setattr(m, "get_save_and_check_balances_for_pubkey", lambda pubkey: (1, 1))
    monkeypatch.setattr(m, "mint_access_token", lambda sub=None, scope=None: "access-token")
    monkeypatch.setattr(m, "_finish_login", lambda resp, pubkey, access: resp)

    client = m.app.test_client()
    response = client.post(
        "/api/verify",
        data=json.dumps({"challenge_id": challenge_id, "pubkey": pubkey, "nostr_event": event}),
        content_type="application/json",
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["verified"] is True
    assert payload["pubkey"] == pubkey
    assert challenge_id not in m.ACTIVE_CHALLENGES

    replay = client.post(
        "/api/verify",
        data=json.dumps({"challenge_id": challenge_id, "pubkey": pubkey, "nostr_event": event}),
        content_type="application/json",
    )
    assert replay.status_code == 400
    assert replay.get_json()["error"] == "Invalid or expired challenge"


def test_api_verify_rejects_nostr_without_event(monkeypatch):
    m = _load_monolith()
    challenge_id = "cid-nostr-missing"
    pubkey = "a" * 64
    _seed_challenge(m, challenge_id, pubkey)

    with m.app.test_request_context(
        "/api/verify", method="POST", json={"challenge_id": challenge_id, "pubkey": pubkey}
    ):
        resp, status = m.api_verify()
        assert status == 400
        assert resp.get_json()["error"] == "Missing nostr_event"


def test_api_verify_rejects_lightning_without_crypto_proof(monkeypatch):
    m = _load_monolith()

    challenge_id = "cid-ln-1"
    pubkey = "b" * 64
    _seed_challenge(m, challenge_id, pubkey, method="lightning")

    with m.app.test_request_context(
        "/api/verify",
        method="POST",
        json={"challenge_id": challenge_id, "pubkey": pubkey, "signature": "fake"},
    ):
        resp, status = m.api_verify()
        assert status == 501
        payload = resp.get_json()
        assert payload["error"].startswith("Verification method 'lightning'")


def test_api_verify_keeps_legacy_bitcoin_message_flow(monkeypatch):
    m = _load_monolith()
    challenge_id = "cid-btc-1"
    pubkey = "02" + "c" * 64
    _seed_challenge(m, challenge_id, pubkey, method="api")

    calls = {}

    class FakeRPC:
        def verifymessage(self, addr, signature, challenge):
            calls["addr"] = addr
            calls["signature"] = signature
            calls["challenge"] = challenge
            return True

    monkeypatch.setattr(m, "get_rpc_connection", lambda: FakeRPC())
    monkeypatch.setattr(m, "derive_legacy_address_from_pubkey", lambda pubkey: "1LegacyAddr")
    monkeypatch.setattr(m, "get_save_and_check_balances_for_pubkey", lambda pubkey: (1, 1))
    monkeypatch.setattr(m, "mint_access_token", lambda sub=None, scope=None: "access-token")
    monkeypatch.setattr(m, "_finish_login", lambda resp, pubkey, access: resp)

    client = m.app.test_client()
    response = client.post(
        "/api/verify",
        data=json.dumps({"challenge_id": challenge_id, "pubkey": pubkey, "signature": "signed-message"}),
        content_type="application/json",
    )

    assert response.status_code == 200
    assert response.get_json()["verified"] is True
    assert calls == {
        "addr": "1LegacyAddr",
        "signature": "signed-message",
        "challenge": "HODLXXI:login:test",
    }


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
