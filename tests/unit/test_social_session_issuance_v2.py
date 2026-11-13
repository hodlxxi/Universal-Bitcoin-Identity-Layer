import hashlib
from datetime import timedelta
from unittest.mock import patch

import jwt
import pytest
from sqlalchemy import select, update

from app.models import OAuthToken
from app.services.social_session_issuance_v2_contract import SCOPE, V2IssuanceUnavailable
from app.services.social_session_issuance_v2_storage import V2Acceptance, V2Issuance
from tests.unit.test_social_session_issuance_v2_storage import NOW, VECTOR, SessionDouble, graph


def test_real_native_producer_and_reader_and_identical_recovery(graph):
    try:
        created = graph.create()
    except V2IssuanceUnavailable as failure:
        raise failure.__context__
    assert created == VECTOR["authorizationWire"]
    first = graph.issue()
    retry = graph.issue()
    assert first == retry
    credential = first["viewerAccessToken"]
    claims = jwt.decode(credential, graph.key.public_key(), algorithms=["RS256"], audience="social-client")
    assert claims["scope"] == SCOPE and first["currentActive"] is True
    with SessionDouble(graph) as s, s.begin():
        rows = s.actual.execute(select(V2Issuance)).scalars().all()
        assert len(rows) == 1
        i = rows[0]
        token = s.actual.get(OAuthToken, i.token_id)
        assert token.access_token == hashlib.sha256(credential.encode()).hexdigest()
        assert token.access_token != credential and token.refresh_token is None
        r = graph.reader(s)
        facts = r.read(
            i.issuance_id, verification_input_wire=VECTOR["preacceptedEnrollmentVerificationInputWire"]
        ).facts
        assert facts.acceptance_wire == VECTOR["acceptanceWire"]
        assert facts.parent_token_id == facts.approver_token_id
        assert facts.input_digest == VECTOR["preacceptedEnrollmentVerificationInputDigest"]
        assert facts.full_evidence_id == "00000000-0000-4000-8000-000000000001"
        assert facts.revision == first["receipt"]["socialSessionIssuanceRevision"]


def test_conflicting_delivery_and_original_exchange_fail_with_existing_grant(graph):
    graph.create()
    graph.issue()
    for change in (dict(delivery_key="56" * 32), dict(verifier="89" * 32), dict(secret="78" * 32)):
        with pytest.raises(V2IssuanceUnavailable):
            graph.issue(**change)
    with SessionDouble(graph) as s, s.begin():
        assert len(s.actual.execute(select(V2Issuance)).scalars().all()) == 1


def test_recover_never_creates_missing_authority(graph):
    graph.create()
    with pytest.raises(V2IssuanceUnavailable):
        graph.issue(recover_only=True)
    with SessionDouble(graph) as s, s.begin():
        assert s.actual.execute(select(V2Issuance)).scalars().all() == []
        assert s.actual.execute(select(V2Acceptance)).scalars().all() == []


def test_inactive_history_never_releases_bearer(graph):
    graph.create()
    first = graph.issue()
    graph.now = NOW + timedelta(minutes=5)
    result = graph.issue(recover_only=True)
    assert result["receipt"] == first["receipt"]
    assert result["currentActive"] is False
    assert result["viewerAccessToken"] is result["subject"] is None


def test_revoked_child_retains_history_and_cannot_deliver(graph):
    graph.create()
    first = graph.issue()
    with SessionDouble(graph) as s, s.begin():
        i = s.actual.execute(select(V2Issuance)).scalar_one()
        s.actual.execute(update(OAuthToken).where(OAuthToken.id == i.token_id).values(is_revoked=True))
    result = graph.issue(recover_only=True)
    assert result["receipt"] == first["receipt"] and result["viewerAccessToken"] is None


def test_wrong_original_approval_and_missing_original_key_fail_closed(graph, monkeypatch):
    graph.create()
    first = graph.issue()
    from app import tokens

    monkeypatch.setattr(tokens, "get_signing_key", lambda _directory: (_ for _ in ()).throw(ValueError()))
    with pytest.raises(V2IssuanceUnavailable):
        graph.issue(recover_only=True)
    with SessionDouble(graph) as s, s.begin():
        assert s.actual.execute(select(V2Issuance)).scalar_one().issuance_id == first["receipt"]["issuanceId"]


def test_acceptance_and_child_rollback_together_on_signer_failure(graph, monkeypatch):
    graph.create()
    from app import tokens

    monkeypatch.setattr(tokens, "get_signing_key", lambda _directory: (_ for _ in ()).throw(ValueError()))
    with pytest.raises(V2IssuanceUnavailable):
        graph.issue()
    with SessionDouble(graph) as s, s.begin():
        assert s.actual.execute(select(V2Acceptance)).scalars().all() == []
        assert s.actual.execute(select(V2Issuance)).scalars().all() == []
        from app.services.social_messaging_device_storage import SocialMessagingDeviceBindingRow

        assert s.actual.execute(select(SocialMessagingDeviceBindingRow)).scalars().all() == []


def test_owner_commit_failure_releases_no_result(graph):
    graph.create()
    # This is the actual owner commit path. The before_commit event simulates an
    # uncertain/failed commit without releasing command's already-built bearer.
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    def deny(session):
        raise ValueError("synthetic commit failure")

    event.listen(Session, "before_commit", deny)
    try:
        with pytest.raises(V2IssuanceUnavailable):
            graph.issue()
    finally:
        event.remove(Session, "before_commit", deny)
    with SessionDouble(graph) as s, s.begin():
        assert s.actual.execute(select(V2Issuance)).scalars().all() == []


def test_fractional_original_parent_expiry_floors_child(graph):
    from app.models import OAuthBrowserGeneration

    expiry = NOW + timedelta(seconds=42, microseconds=999999)
    with SessionDouble(graph) as s, s.begin():
        s.actual.execute(update(OAuthBrowserGeneration).values(expires_at=expiry.replace(tzinfo=None)))
    graph.create()
    result = graph.issue()
    assert result["receipt"]["expiresAt"] == int((NOW + timedelta(seconds=42)).timestamp()) * 1000


def test_uncertain_committed_response_recovers_original_grant(graph):
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    graph.create()

    def lost_response(session):
        raise ValueError("synthetic lost response after commit")

    event.listen(Session, "after_commit", lost_response)
    try:
        with pytest.raises(V2IssuanceUnavailable):
            graph.issue()
    finally:
        event.remove(Session, "after_commit", lost_response)
    with SessionDouble(graph) as s, s.begin():
        original = s.actual.execute(select(V2Issuance)).scalar_one()
        original_jti = original.token_id
        original_expiry = original.expires_at
    recovered = graph.issue(recover_only=True)
    decoded = jwt.decode(
        recovered["viewerAccessToken"], graph.key.public_key(), algorithms=["RS256"], audience="social-client"
    )
    assert decoded["jti"] == original_jti and decoded["exp"] == original_expiry
    assert graph.issue(recover_only=True) == recovered


def test_mismatched_approval_and_original_approver_cannot_create_acceptance(graph):
    import json

    from app.services.social_session_issuance_v2_contract import canonical

    graph.create()
    event = json.loads(VECTOR["approvalEventWire"])
    event["sig"] = "00" * 64
    for changes in (dict(approval_wire=canonical(event)), dict(approver_bearer=None)):
        with pytest.raises(V2IssuanceUnavailable):
            graph.issue(**changes)
        with SessionDouble(graph) as s, s.begin():
            assert s.actual.execute(select(V2Acceptance)).scalars().all() == []


def test_expiry_after_writes_and_before_owner_commit_discards_grant(graph, monkeypatch):
    graph.create()
    original_delivery = graph.issuer._delivery

    def cross_deadline(reader, issued, parent, acceptance):
        result = original_delivery(reader, issued, parent, acceptance)
        graph.now = NOW + timedelta(minutes=5)
        return result

    monkeypatch.setattr(graph.issuer, "_delivery", cross_deadline)
    with pytest.raises(V2IssuanceUnavailable):
        graph.issue()
    with SessionDouble(graph) as s, s.begin():
        assert s.actual.execute(select(V2Issuance)).scalars().all() == []


def test_native_locked_facts_cross_complete_actual_deadline_payload_consumer(graph):
    import json
    from pathlib import Path

    from app.services import social_messaging_device_verification_deadline_evidence_v1 as deadline
    from app.services.social_session_issuance_v2_contract import canonical

    graph.create()
    delivery = graph.issue()
    with SessionDouble(graph) as s, s.begin():
        facts = (
            graph.reader(s)
            .read(
                delivery["receipt"]["issuanceId"],
                verification_input_wire=VECTOR["preacceptedEnrollmentVerificationInputWire"],
            )
            .facts
        )
        fixture = json.loads(
            (
                Path(__file__).resolve().parents[2] / "tests/fixtures/"
                "social_messaging_device_verification_deadline_evidence_v1.json"
            ).read_bytes()
        )
        payload = json.loads(fixture["vector"]["payloadWire"])
        payload.update(
            operationId=facts.operation_id,
            socialSessionIssuanceId=facts.issuance_id,
            socialSessionIssuanceRevision=facts.revision,
            socialSessionTokenId=facts.token_id,
            parentOAuthTokenId=facts.parent_token_id,
            parentOAuthSessionId=facts.parent_session_id,
            parentOAuthBrowserGenerationId=facts.parent_browser_id,
            approverOAuthTokenId=facts.approver_token_id,
            approverOAuthSessionId=facts.approver_session_id,
            approverOAuthBrowserGenerationId=facts.approver_browser_id,
            phoneSessionExpiresAt=facts.phone_expires_at_ms,
            approverSessionExpiresAt=facts.approver_expires_at_ms,
            fullEvidenceId=facts.full_evidence_id,
            fullEvidenceVersion=facts.full_evidence_version,
            fullSourceEvidenceSha256=facts.full_source_evidence_sha256,
            fullProofId=facts.full_proof_id,
            fullExpiresAt=facts.full_expires_at_ms,
            observedAt=facts.observed_at_ms,
            expiresAt=facts.observed_at_ms + 1000,
            clientId=facts.client_id,
            servicePrincipal=facts.service_principal,
        )
        reservation = {
            key: payload[key]
            for key in (
                "acceptanceId",
                "associationId",
                "deviceId",
                "enrollmentChallengeId",
                "inputDigest",
                "operation",
                "operationId",
                "requestId",
                "subject",
            )
        }
        reservation.update(schema=deadline.RESERVATION_ID_PREIMAGE_SCHEMA, version=1)
        payload["reservationId"] = hashlib.sha256(
            deadline.RESERVATION_ID_DOMAIN.encode() + b"\0" + canonical(reservation).encode()
        ).hexdigest()
        without = {key: value for key, value in payload.items() if key != "jti"}
        payload["jti"] = hashlib.sha256(
            deadline.EVIDENCE_JTI_DOMAIN.encode() + b"\0" + canonical(without).encode()
        ).hexdigest()
        claims = deadline.parse_messaging_device_verification_deadline_evidence_payload_v1(
            canonical(payload), expected_input_wire=VECTOR["preacceptedEnrollmentVerificationInputWire"]
        )
        assert claims.social_session_issuance_revision == facts.revision
        assert claims.full_proof_id == facts.full_proof_id
        assert claims.parent_oauth_session_id == facts.parent_session_id
        # This is exact boundary/shape compatibility, not a dedicated signed
        # evidence producer or a reservation; neither is implemented here.


def test_current_full_deadline_after_delivery_work_fences_actual_owner_commit(graph, monkeypatch):
    from app.models import CurrentEntitlementEvidence

    with SessionDouble(graph) as s, s.begin():
        s.actual.execute(
            update(CurrentEntitlementEvidence).values(valid_until=(NOW + timedelta(seconds=3)).replace(tzinfo=None))
        )
    graph.create()
    original_delivery = graph.issuer._delivery

    def cross_full_only(reader, issued, parent, acceptance):
        result = original_delivery(reader, issued, parent, acceptance)
        graph.now = NOW + timedelta(seconds=3)
        assert int(graph.now.timestamp()) * 1000 < result["receipt"]["expiresAt"]
        return result

    monkeypatch.setattr(graph.issuer, "_delivery", cross_full_only)
    with pytest.raises(V2IssuanceUnavailable):
        graph.issue()
    with SessionDouble(graph) as s, s.begin():
        assert s.actual.execute(select(V2Issuance)).scalars().all() == []
        assert s.actual.execute(select(V2Acceptance)).scalars().all() == []


def test_full_expiry_during_successful_commit_retains_history_without_bearer(graph):
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    from app.models import CurrentEntitlementEvidence

    with SessionDouble(graph) as s, s.begin():
        s.actual.execute(
            update(CurrentEntitlementEvidence).values(valid_until=(NOW + timedelta(seconds=3)).replace(tzinfo=None))
        )
    graph.create()

    def expire_full(session):
        graph.now = NOW + timedelta(seconds=3)

    event.listen(Session, "after_commit", expire_full)
    try:
        result = graph.issue()
    finally:
        event.remove(Session, "after_commit", expire_full)
    assert result["currentActive"] is False
    assert result["subject"] is result["viewerAccessToken"] is None
    with SessionDouble(graph) as s, s.begin():
        assert s.actual.execute(select(V2Issuance)).scalar_one().issuance_id == result["receipt"]["issuanceId"]
