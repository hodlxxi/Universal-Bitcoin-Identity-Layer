import base64
import hashlib
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

import pytest

from app.auth_api_core import ACTIVE_CHALLENGES, canonical_xonly_pubkey
from app.db_storage import create_user, get_oauth_code, get_user_by_id


COMPRESSED = "02" + "a" * 64
SUBJECT = "a" * 64
REDIRECT_URI = "https://social.example/callback"


def _register(client):
    response = client.post("/oauth/register", json={"client_name": "Social test", "redirect_uris": [REDIRECT_URI]})
    assert response.status_code == 201
    return response.get_json()


def _query(registration, **overrides):
    verifier = "v" * 43
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    query = {
        "response_type": "code",
        "client_id": registration["client_id"],
        "redirect_uri": REDIRECT_URI,
        "scope": "profile openid",
        "state": "bound-state",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    query.update(overrides)
    return query


def _session(client, pubkey=COMPRESSED, method="legacy", access="limited", persist=True):
    if persist:
        create_user(canonical_xonly_pubkey(pubkey))
    with client.session_transaction() as browser:
        browser["logged_in_pubkey"] = pubkey
        browser["login_method"] = method
        browser["access_level"] = access


@pytest.mark.parametrize("method", ["legacy", "nostr"])
def test_persisted_legacy_and_nostr_sessions_bind_canonical_code(client, method):
    registration = _register(client)
    _session(client, method=method, access="full")
    response = client.get("/oauth/authorize", query_string=_query(registration))
    assert response.status_code == 302
    parsed = urlparse(response.location)
    values = parse_qs(parsed.query)
    assert values["state"] == ["bound-state"]
    record = get_oauth_code(values["code"][0])
    assert get_user_by_id(record["user_id"])["pubkey"] == SUBJECT
    assert "access_level" not in record
    assert record["redirect_uri"] == REDIRECT_URI
    assert record["scope"] == "openid profile"
    assert record["code_challenge_method"] == "S256"


def test_actually_missing_login_redirects_to_login(client):
    registration = _register(client)
    response = client.get("/oauth/authorize", query_string=_query(registration))
    assert response.status_code == 302
    assert response.location.startswith("/login?")


@pytest.mark.parametrize(
    "pubkey,method,access,persist",
    [
        ("guest_123", "legacy", "limited", False),
        ("anon_123", "nostr", "limited", False),
        (COMPRESSED, None, "limited", True),
        (COMPRESSED, "guest", "limited", True),
        (COMPRESSED, "lightning", "limited", True),
        (COMPRESSED, "unknown", "limited", True),
        (COMPRESSED, "legacy", None, True),
        (COMPRESSED, "legacy", "guest", True),
        ("02" + "c" * 64, "legacy", "limited", False),
    ],
)
def test_inadmissible_sessions_are_denied_without_storing_codes(client, pubkey, method, access, persist):
    registration = _register(client)
    _session(client, pubkey, method, access, persist)
    with patch("app.blueprints.oauth.store_oauth_code") as store:
        response = client.get("/oauth/authorize", query_string=_query(registration))
    assert response.status_code == 403
    assert response.get_json() == {
        "error": "access_denied",
        "error_description": "Authenticated session is not eligible",
    }
    store.assert_not_called()


def test_nostr_persistence_precedes_authenticated_session_fields(client, monkeypatch):
    cid = "nostr-order"
    ACTIVE_CHALLENGES[cid] = {
        "pubkey": COMPRESSED,
        "challenge": "one-time",
        "method": "nostr",
        "expires": datetime.now(timezone.utc) + timedelta(minutes=1),
    }
    monkeypatch.setattr("app.auth_api_core.verify_nostr_login_event", lambda *args, **kwargs: (True, None))
    monkeypatch.setattr("app.app.get_save_and_check_balances_for_pubkey", lambda _: (1, 0))
    observed = []

    def persist(pubkey):
        from flask import session

        observed.append((pubkey, "logged_in_pubkey" in session, cid in ACTIVE_CHALLENGES))
        return SUBJECT

    monkeypatch.setattr("app.blueprints.api_auth.persist_verified_browser_subject", persist)
    response = client.post("/api/verify", json={"challenge_id": cid, "nostr_event": {"id": "test"}})
    assert response.status_code == 200
    assert observed == [(COMPRESSED, False, False)]
    with client.session_transaction() as browser:
        assert browser["logged_in_pubkey"] == COMPRESSED
        assert browser["login_method"] == "nostr"
        assert browser["access_level"] == "limited"


def test_nostr_persistence_failure_consumes_challenge_and_leaves_no_login(client, monkeypatch):
    cid = "nostr-failure"
    ACTIVE_CHALLENGES[cid] = {
        "pubkey": COMPRESSED,
        "challenge": "one-time",
        "method": "nostr",
        "expires": datetime.now(timezone.utc) + timedelta(minutes=1),
    }
    monkeypatch.setattr("app.auth_api_core.verify_nostr_login_event", lambda *args, **kwargs: (True, None))
    monkeypatch.setattr("app.app.get_save_and_check_balances_for_pubkey", lambda _: (1, 0))
    monkeypatch.setattr(
        "app.blueprints.api_auth.persist_verified_browser_subject",
        lambda _: (_ for _ in ()).throw(RuntimeError("private persistence detail")),
    )
    response = client.post("/api/verify", json={"challenge_id": cid, "nostr_event": {"id": "test"}})
    assert response.status_code == 503
    assert response.get_json() == {"error": "Authentication service temporarily unavailable"}
    assert cid not in ACTIVE_CHALLENGES
    with client.session_transaction() as browser:
        assert "logged_in_pubkey" not in browser
        assert "login_method" not in browser
        assert "access_level" not in browser
