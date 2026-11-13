"""Real owner decisions with explicitly synthetic SQLite catalogs and triggers."""

import hashlib
from datetime import timedelta

import pytest
from sqlalchemy import event, select, update
from sqlalchemy.orm import Session

from app.models import OAuthToken
from app.services.social_session_issuance_v2_contract import V2IssuanceUnavailable
from app.services.social_session_issuance_v2_storage import V2Issuance, V2Offer, V2Parent, V2TokenBirth
from tests.unit.test_social_session_issuance_v2_storage import NOW, VECTOR, SessionDouble, graph


def test_exact_offer_retry_preserves_original_bytes_and_one_parent(graph):
    first = graph.create()
    assert graph.create() == first == VECTOR["authorizationWire"]
    with SessionDouble(graph) as db, db.begin():
        assert len(db.actual.execute(select(V2Offer)).scalars().all()) == 1
        assert len(db.actual.execute(select(V2Parent)).scalars().all()) == 1
    assert graph.issue()["currentActive"] is True


def test_offer_retry_does_not_renew_expired_original(graph):
    graph.create()
    graph.now = NOW + timedelta(minutes=5)
    with pytest.raises(V2IssuanceUnavailable):
        graph.create()


def test_offer_retry_authenticates_original_desktop(graph):
    graph.create()
    with pytest.raises(V2IssuanceUnavailable):
        graph.issuer.create_offer(VECTOR["authorizationWire"], desktop_bearer="wrong.exact.token")


def test_self_revoke_retains_exact_inactive_history_and_is_idempotent(graph):
    graph.create()
    first = graph.issue()
    args = dict(viewer_bearer=first["viewerAccessToken"])
    result = graph.issuer.revoke(first["receipt"]["issuanceId"], **args)
    assert result == dict(
        schema="hodlxxi.social_session_revocation.v2",
        version=2,
        issuanceId=first["receipt"]["issuanceId"],
        status="revoked",
    )
    assert graph.issuer.revoke(first["receipt"]["issuanceId"], **args) == result
    history = graph.issue(recover_only=True)
    assert history["receipt"] == first["receipt"]
    assert history["currentActive"] is False and history["viewerAccessToken"] is history["subject"] is None


@pytest.mark.parametrize(
    "wrong",
    ["other.exact.token", None, "", "a" * 8193, "bad\ncredential"],
    ids=("wrong", "missing", "empty", "oversize", "newline"),
)
def test_revoke_requires_exact_original_secret_not_selector_or_desktop(graph, wrong):
    graph.create()
    first = graph.issue()
    with pytest.raises(V2IssuanceUnavailable):
        graph.issuer.revoke(first["receipt"]["issuanceId"], viewer_bearer=wrong)
    assert graph.issue(recover_only=True)["currentActive"] is True


def test_desktop_bearer_cannot_cancel_phone_child(graph):
    graph.create()
    first = graph.issue()
    with pytest.raises(V2IssuanceUnavailable):
        graph.issuer.revoke(first["receipt"]["issuanceId"], viewer_bearer=graph.desktop)


def test_expired_self_cancellation_needs_no_signer_or_current_parent_authority(graph, monkeypatch):
    graph.create()
    first = graph.issue()
    graph.now = NOW + timedelta(minutes=5)
    from app import tokens

    monkeypatch.setattr(tokens, "get_signing_key", lambda _: (_ for _ in ()).throw(ValueError()))
    assert (
        graph.issuer.revoke(first["receipt"]["issuanceId"], viewer_bearer=first["viewerAccessToken"])["status"]
        == "revoked"
    )
    with SessionDouble(graph) as db, db.begin():
        child = db.actual.execute(select(V2Issuance)).scalar_one()
        token = db.actual.get(OAuthToken, child.token_id)
        assert token.is_revoked is True
        assert token.access_token == hashlib.sha256(first["viewerAccessToken"].encode("ascii")).hexdigest()


def test_self_cancellation_denies_missing_native_birth(graph):
    graph.create()
    first = graph.issue()
    with SessionDouble(graph) as db, db.begin():
        row = db.actual.execute(select(V2Issuance)).scalar_one()
        db.actual.execute(update(V2TokenBirth).where(V2TokenBirth.token_id == row.token_id).values(birth_xid="other"))
    with pytest.raises(V2IssuanceUnavailable):
        graph.issuer.revoke(first["receipt"]["issuanceId"], viewer_bearer=first["viewerAccessToken"])


def test_revoke_commit_failure_publishes_no_ack_or_token_change(graph):
    graph.create()
    first = graph.issue()

    def deny(_session):
        raise ValueError("synthetic commit failure")

    event.listen(Session, "before_commit", deny)
    try:
        with pytest.raises(V2IssuanceUnavailable):
            graph.issuer.revoke(first["receipt"]["issuanceId"], viewer_bearer=first["viewerAccessToken"])
    finally:
        event.remove(Session, "before_commit", deny)
    assert graph.issue(recover_only=True)["currentActive"] is True
