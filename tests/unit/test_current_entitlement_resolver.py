from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import uuid

import pytest

from app.services.action_authorization import IdentityClass
from app.services.current_entitlement import (
    EntitlementDenied,
    EntitlementUnavailable,
    EvidenceBackedCurrentEntitlementResolver,
    resolve_current_entitlement,
)
from app.services.current_entitlement_evidence import CONTRACT_VERSION, CurrentEntitlementEvidenceRecord

SUBJECT = "a" * 64
NOW = datetime(2026, 7, 22, 12, tzinfo=timezone.utc)


def evidence(identity=IdentityClass.FULL, **changes):
    values = dict(
        evidence_id=str(uuid.uuid4()),
        contract_version=CONTRACT_VERSION,
        subject_pubkey=SUBJECT,
        identity_class=identity,
        current_full_relation_satisfied=identity is IdentityClass.FULL,
        evidence_source="offline_verifier",
        evidence_version="v1",
        source_evidence_sha256="b" * 64,
        observed_at=NOW - timedelta(seconds=1),
        valid_until=NOW + timedelta(minutes=5),
        revoked_at=None,
        created_at=NOW,
    )
    values.update(changes)
    return CurrentEntitlementEvidenceRecord(**values)


class Repository:
    def __init__(self, latest=None, error=None):
        self.latest = latest
        self.error = error
        self.calls = []

    def get_latest(self, subject):
        self.calls.append(subject)
        if self.error:
            raise self.error
        return self.latest


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


def test_evidence_resolver_missing_full_and_limited(monkeypatch):
    monkeypatch.setattr(
        "app.services.current_entitlement.get_user_by_pubkey",
        lambda subject: {"pubkey": subject, "is_active": True},
    )
    missing = EvidenceBackedCurrentEntitlementResolver(Repository(), clock=lambda: NOW)(SUBJECT)
    full = EvidenceBackedCurrentEntitlementResolver(Repository(evidence()), clock=lambda: NOW)(SUBJECT)
    limited = EvidenceBackedCurrentEntitlementResolver(Repository(evidence(IdentityClass.LIMITED)), clock=lambda: NOW)(
        SUBJECT
    )
    assert (missing.identity_class, missing.evidence_source) == (IdentityClass.LIMITED, "active_persisted_user")
    assert (full.identity_class, full.current_full_relation_satisfied) == (IdentityClass.FULL, True)
    assert (limited.identity_class, limited.current_full_relation_satisfied) == (IdentityClass.LIMITED, False)
    assert (
        EvidenceBackedCurrentEntitlementResolver(Repository(evidence()), clock=lambda: NOW)
        .resolve(SUBJECT)
        .identity_class
        is IdentityClass.FULL
    )


@pytest.mark.parametrize(
    "latest",
    [
        evidence(revoked_at=NOW),
        evidence(valid_until=NOW),
        evidence(observed_at=NOW + timedelta(seconds=30), created_at=NOW + timedelta(seconds=30)),
    ],
)
def test_revoked_expired_and_future_latest_never_grant_full(monkeypatch, latest):
    monkeypatch.setattr(
        "app.services.current_entitlement.get_user_by_pubkey",
        lambda subject: {"pubkey": subject, "is_active": True},
    )
    decision = EvidenceBackedCurrentEntitlementResolver(Repository(latest), clock=lambda: NOW)(SUBJECT)
    assert decision.identity_class is IdentityClass.LIMITED
    assert decision.current_full_relation_satisfied is False


def test_malformed_repository_failure_and_excess_future_skew_are_unavailable(monkeypatch):
    monkeypatch.setattr(
        "app.services.current_entitlement.get_user_by_pubkey",
        lambda subject: {"pubkey": subject, "is_active": True},
    )
    malformed = SimpleNamespace(**{**vars(evidence()), "current_full_relation_satisfied": False})
    for repository in (
        Repository(malformed),
        Repository(error=RuntimeError("secret database detail")),
        Repository(evidence(observed_at=NOW + timedelta(seconds=61), created_at=NOW + timedelta(seconds=61))),
    ):
        with pytest.raises(EntitlementUnavailable):
            EvidenceBackedCurrentEntitlementResolver(repository, clock=lambda: NOW)(SUBJECT)


def test_active_user_check_precedes_evidence_and_exact_subject_is_enforced(monkeypatch):
    repository = Repository(evidence())
    monkeypatch.setattr("app.services.current_entitlement.get_user_by_pubkey", lambda _subject: None)
    with pytest.raises(EntitlementDenied):
        EvidenceBackedCurrentEntitlementResolver(repository, clock=lambda: NOW)(SUBJECT)
    assert repository.calls == []

    monkeypatch.setattr(
        "app.services.current_entitlement.get_user_by_pubkey",
        lambda subject: {"pubkey": subject, "is_active": True},
    )
    mismatched = evidence(subject_pubkey="c" * 64)
    with pytest.raises(EntitlementUnavailable):
        EvidenceBackedCurrentEntitlementResolver(Repository(mismatched), clock=lambda: NOW)(SUBJECT)


def test_evidence_resolver_does_not_mutate_browser_state_or_use_legacy_balance(app, monkeypatch):
    monkeypatch.setattr(
        "app.services.current_entitlement.get_user_by_pubkey",
        lambda subject: {"pubkey": subject, "is_active": True},
    )
    with app.test_request_context():
        from flask import g, session

        session["access_level"] = "full"
        before_session = dict(session)
        before_g = vars(g).copy()
        decision = EvidenceBackedCurrentEntitlementResolver(Repository(evidence()), clock=lambda: NOW)(SUBJECT)
        assert dict(session) == before_session
        assert vars(g) == before_g
    assert decision.identity_class is IdentityClass.FULL
