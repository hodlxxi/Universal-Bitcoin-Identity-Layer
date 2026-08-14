import inspect

import pytest

import app.app as legacy_app

from app.services.canonical_oauth_browser_subject import (
    OAuthBrowserSubject,
    persist_verified_browser_subject,
    resolve_oauth_browser_subject,
)


SUBJECT = "a" * 64
COMPRESSED = "02" + SUBJECT
USER_ID = "canonical-user"


def _user(**overrides):
    value = {"id": USER_ID, "pubkey": SUBJECT, "is_active": True}
    value.update(overrides)
    return value


def test_persist_verified_subject_canonicalizes_and_rereads_exact_active_user():
    created = []
    result = persist_verified_browser_subject(
        COMPRESSED,
        create_user_fn=lambda subject: created.append(subject) or USER_ID,
        get_user_fn=lambda subject: _user(),
    )
    assert result == SUBJECT
    assert created == [SUBJECT]


@pytest.mark.parametrize("value", [None, False, 1, [], {}, "guest_123", "anon_123", "bad"])
def test_persistence_rejects_noncanonical_subjects(value):
    with pytest.raises((ValueError, RuntimeError)):
        persist_verified_browser_subject(value, create_user_fn=lambda _: USER_ID, get_user_fn=lambda _: _user())


def test_persistence_rejects_string_subclasses_and_preserves_interrupts():
    class StringLike(str):
        pass

    with pytest.raises(ValueError):
        persist_verified_browser_subject(StringLike(COMPRESSED))
    with pytest.raises(KeyboardInterrupt):
        persist_verified_browser_subject(COMPRESSED, create_user_fn=lambda _: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(SystemExit):
        persist_verified_browser_subject(COMPRESSED, create_user_fn=lambda _: (_ for _ in ()).throw(SystemExit()))


@pytest.mark.parametrize(
    "row",
    [None, [], _user(is_active=False), _user(pubkey="b" * 64), _user(id=""), {"id": USER_ID}],
)
def test_persistence_rejects_missing_inactive_inconsistent_or_malformed_rows(row):
    with pytest.raises(RuntimeError):
        persist_verified_browser_subject(
            COMPRESSED,
            create_user_fn=lambda _: USER_ID,
            get_user_fn=lambda _: row,
        )


@pytest.mark.parametrize("method", [None, "", "guest", "lightning", "unknown", 1, True])
def test_oauth_resolution_rejects_nonadmitted_methods(method):
    with pytest.raises(ValueError):
        resolve_oauth_browser_subject(SUBJECT, method, "limited", get_user_fn=lambda _: _user())


@pytest.mark.parametrize("access", [None, "", "guest", "special", 1, True])
def test_oauth_resolution_rejects_nonadmitted_access_levels(access):
    with pytest.raises(ValueError):
        resolve_oauth_browser_subject(SUBJECT, "legacy", access, get_user_fn=lambda _: _user())


@pytest.mark.parametrize("method", ["legacy", "nostr"])
@pytest.mark.parametrize("access", ["limited", "full"])
def test_oauth_resolution_returns_frozen_canonical_result(method, access):
    result = resolve_oauth_browser_subject(COMPRESSED, method, access, get_user_fn=lambda _: _user())
    assert type(result) is OAuthBrowserSubject
    assert result.subject == SUBJECT
    with pytest.raises(Exception):
        result.subject = "b" * 64


def test_oauth_resolution_rejects_malformed_adapter_and_preserves_interrupts():
    class DictLike(dict):
        pass

    with pytest.raises(RuntimeError):
        resolve_oauth_browser_subject(SUBJECT, "legacy", "limited", get_user_fn=lambda _: DictLike(_user()))
    with pytest.raises(KeyboardInterrupt):
        resolve_oauth_browser_subject(
            SUBJECT,
            "legacy",
            "limited",
            get_user_fn=lambda _: (_ for _ in ()).throw(KeyboardInterrupt()),
        )


def test_cookie_domain_default_is_host_only_with_explicit_override_support():
    source = inspect.getsource(legacy_app).replace(" ", "")
    assert 'os.getenv("SESSION_COOKIE_DOMAIN")' in source
    assert 'if_cookie_domain:' in source
    assert 'app.config.setdefault("SESSION_COOKIE_DOMAIN",None)' in source
    assert legacy_app.app.config["SESSION_COOKIE_SECURE"] is True
    assert legacy_app.app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert legacy_app.app.config["SESSION_COOKIE_HTTPONLY"] is True
