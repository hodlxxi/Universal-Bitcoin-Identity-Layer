import sys
import types

import pytest

from app.auth_api_core import _nostr_event_id, verify_nostr_login_event

PUBKEY = "a" * 64
OTHER_PUBKEY = "b" * 64
SIG = "c" * 128
CHALLENGE = "HODLXXI:login:1778350000:abcdef12"
VERIFY_URL = "https://hodlxxi.com/api/verify"
NOW = 1_778_350_000


def make_event(**overrides):
    event = {
        "pubkey": PUBKEY,
        "created_at": NOW,
        "kind": 22242,
        "tags": [
            ["challenge", CHALLENGE],
            ["u", VERIFY_URL],
        ],
        "content": "HODLXXI Nostr auth",
        "sig": SIG,
    }
    event.update(overrides)

    if "id" not in overrides:
        event["id"] = _nostr_event_id(event)

    return event


class FakePublicKeyXOnly:
    verify_result = True

    def __init__(self, raw_pubkey):
        self.raw_pubkey = raw_pubkey

    def verify(self, raw_sig, raw_event_id):
        return self.verify_result


@pytest.fixture(autouse=True)
def fake_coincurve(monkeypatch):
    fake_module = types.SimpleNamespace(PublicKeyXOnly=FakePublicKeyXOnly)
    monkeypatch.setitem(sys.modules, "coincurve", fake_module)
    FakePublicKeyXOnly.verify_result = True


def test_verify_nostr_login_event_accepts_valid_event():
    event = make_event()

    ok, error = verify_nostr_login_event(
        event,
        expected_pubkey=PUBKEY,
        expected_challenge=CHALLENGE,
        expected_verify_url=VERIFY_URL,
        now_ts=NOW,
    )

    assert ok is True
    assert error is None


def test_verify_nostr_login_event_accepts_url_tag_alias():
    event = make_event(tags=[["challenge", CHALLENGE], ["url", VERIFY_URL]])
    event["id"] = _nostr_event_id(event)

    ok, error = verify_nostr_login_event(
        event,
        expected_pubkey=PUBKEY,
        expected_challenge=CHALLENGE,
        expected_verify_url=VERIFY_URL,
        now_ts=NOW,
    )

    assert ok is True
    assert error is None


def test_verify_nostr_login_event_rejects_missing_required_field():
    event = make_event()
    event.pop("sig")

    ok, error = verify_nostr_login_event(
        event,
        expected_pubkey=PUBKEY,
        expected_challenge=CHALLENGE,
        expected_verify_url=VERIFY_URL,
        now_ts=NOW,
    )

    assert ok is False
    assert error == "Missing nostr_event field: sig"


def test_verify_nostr_login_event_rejects_pubkey_mismatch():
    event = make_event(pubkey=OTHER_PUBKEY)
    event["id"] = _nostr_event_id(event)

    ok, error = verify_nostr_login_event(
        event,
        expected_pubkey=PUBKEY,
        expected_challenge=CHALLENGE,
        expected_verify_url=VERIFY_URL,
        now_ts=NOW,
    )

    assert ok is False
    assert error == "Pubkey mismatch"


def test_verify_nostr_login_event_rejects_wrong_kind():
    event = make_event(kind=1)
    event["id"] = _nostr_event_id(event)

    ok, error = verify_nostr_login_event(
        event,
        expected_pubkey=PUBKEY,
        expected_challenge=CHALLENGE,
        expected_verify_url=VERIFY_URL,
        now_ts=NOW,
    )

    assert ok is False
    assert error == "Invalid nostr kind"


def test_verify_nostr_login_event_rejects_old_event():
    event = make_event(created_at=NOW - 301)
    event["id"] = _nostr_event_id(event)

    ok, error = verify_nostr_login_event(
        event,
        expected_pubkey=PUBKEY,
        expected_challenge=CHALLENGE,
        expected_verify_url=VERIFY_URL,
        now_ts=NOW,
    )

    assert ok is False
    assert error == "Nostr event is too old"


def test_verify_nostr_login_event_rejects_future_event():
    event = make_event(created_at=NOW + 61)
    event["id"] = _nostr_event_id(event)

    ok, error = verify_nostr_login_event(
        event,
        expected_pubkey=PUBKEY,
        expected_challenge=CHALLENGE,
        expected_verify_url=VERIFY_URL,
        now_ts=NOW,
    )

    assert ok is False
    assert error == "Nostr event is too far in the future"


def test_verify_nostr_login_event_rejects_challenge_mismatch():
    event = make_event(tags=[["challenge", "wrong"], ["u", VERIFY_URL]])
    event["id"] = _nostr_event_id(event)

    ok, error = verify_nostr_login_event(
        event,
        expected_pubkey=PUBKEY,
        expected_challenge=CHALLENGE,
        expected_verify_url=VERIFY_URL,
        now_ts=NOW,
    )

    assert ok is False
    assert error == "Challenge mismatch"


def test_verify_nostr_login_event_rejects_url_mismatch():
    event = make_event(tags=[["challenge", CHALLENGE], ["u", "https://evil.example/api/verify"]])
    event["id"] = _nostr_event_id(event)

    ok, error = verify_nostr_login_event(
        event,
        expected_pubkey=PUBKEY,
        expected_challenge=CHALLENGE,
        expected_verify_url=VERIFY_URL,
        now_ts=NOW,
    )

    assert ok is False
    assert error == "Nostr event URL mismatch"


def test_verify_nostr_login_event_rejects_event_id_mismatch():
    event = make_event(id="d" * 64)

    ok, error = verify_nostr_login_event(
        event,
        expected_pubkey=PUBKEY,
        expected_challenge=CHALLENGE,
        expected_verify_url=VERIFY_URL,
        now_ts=NOW,
    )

    assert ok is False
    assert error == "Nostr event id mismatch"


def test_verify_nostr_login_event_rejects_invalid_signature():
    FakePublicKeyXOnly.verify_result = False
    event = make_event()

    ok, error = verify_nostr_login_event(
        event,
        expected_pubkey=PUBKEY,
        expected_challenge=CHALLENGE,
        expected_verify_url=VERIFY_URL,
        now_ts=NOW,
    )

    assert ok is False
    assert error == "Invalid nostr signature"


def test_verify_nostr_login_event_requires_url_when_requested():
    event = make_event(tags=[["challenge", CHALLENGE]])
    event["id"] = _nostr_event_id(event)

    ok, error = verify_nostr_login_event(
        event,
        expected_pubkey=PUBKEY,
        expected_challenge=CHALLENGE,
        expected_verify_url=VERIFY_URL,
        now_ts=NOW,
        require_verify_url=True,
    )

    assert ok is False
    assert error == "Missing nostr event URL"


def test_verify_nostr_login_event_wrong_required_url_fails():
    event = make_event(tags=[["challenge", CHALLENGE], ["url", "https://evil.example/api/verify"]])
    event["id"] = _nostr_event_id(event)

    ok, error = verify_nostr_login_event(
        event,
        expected_pubkey=PUBKEY,
        expected_challenge=CHALLENGE,
        expected_verify_url=VERIFY_URL,
        now_ts=NOW,
        require_verify_url=True,
    )

    assert ok is False
    assert error == "Nostr event URL mismatch"


def test_verify_nostr_login_event_missing_url_still_allowed_for_legacy_login():
    event = make_event(tags=[["challenge", CHALLENGE]])
    event["id"] = _nostr_event_id(event)

    ok, error = verify_nostr_login_event(
        event,
        expected_pubkey=PUBKEY,
        expected_challenge=CHALLENGE,
        expected_verify_url=VERIFY_URL,
        now_ts=NOW,
    )

    assert ok is True
    assert error is None
