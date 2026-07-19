import pytest

from app.services.action_authorization import IdentityClass
from app.services.current_entitlement import EntitlementDenied, EntitlementUnavailable, resolve_current_entitlement

SUBJECT = "a" * 64


@pytest.mark.parametrize("subject", ["", "guest", "02" + "a" * 64, "A" * 64, None])
def test_malformed_or_noncanonical_subject_is_denied(subject):
    with pytest.raises(EntitlementDenied):
        resolve_current_entitlement(subject)


def test_unknown_and_inactive_users_are_denied(monkeypatch):
    monkeypatch.setattr("app.services.current_entitlement.get_user_by_pubkey", lambda _subject: None)
    with pytest.raises(EntitlementDenied):
        resolve_current_entitlement(SUBJECT)
    monkeypatch.setattr(
        "app.services.current_entitlement.get_user_by_pubkey",
        lambda subject: {"pubkey": subject, "is_active": False},
    )
    with pytest.raises(EntitlementDenied):
        resolve_current_entitlement(SUBJECT)


def test_active_user_is_limited_and_does_not_use_browser_state(app, monkeypatch):
    monkeypatch.setattr(
        "app.services.current_entitlement.get_user_by_pubkey",
        lambda subject: {"pubkey": subject, "is_active": True},
    )
    with app.test_request_context():
        from flask import g, session

        session["access_level"] = "full"
        session["logged_in_pubkey"] = "b" * 64
        before = vars(g).copy()
        decision = resolve_current_entitlement(SUBJECT)
        assert vars(g) == before
    assert decision.identity_class is IdentityClass.LIMITED
    assert decision.current_full_relation_satisfied is False
    assert decision.evidence_source == "active_persisted_user"


def test_database_failure_is_typed_unavailable(monkeypatch):
    def fail(_subject):
        raise RuntimeError("database down")

    monkeypatch.setattr("app.services.current_entitlement.get_user_by_pubkey", fail)
    with pytest.raises(EntitlementUnavailable):
        resolve_current_entitlement(SUBJECT)
