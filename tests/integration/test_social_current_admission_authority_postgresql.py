"""Disposable PostgreSQL proof for current Social admission authority only."""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, delete, select, text, update
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.models import CurrentEntitlementEvidence, OAuthSessionGeneration, OAuthToken, Session
from app.services import social_admission_session_binding as session_binding
from app.services import social_current_admission_authority as authority
from app.services import social_messaging_device_admission_contract as admission
from app.services import social_messaging_device_ed25519_association_lifecycle as ed_lifecycle
from app.services import social_messaging_device_proof_profile as profile
from app.services.current_entitlement_evidence_storage import (
    SqlAlchemyTransactionBoundCurrentFullVerifier,
    _lock_subject_for_evidence_change,
)
from app.services.oauth_session_lifecycle import SqlAlchemyOAuthSessionLifecycle
from app.services.social_device_ed25519_association_storage import SqlAlchemyEd25519AssociationStore
from app.services.social_device_verification_statement import AuthenticatedSocialDeviceVerificationStatementV1
from app.services.social_messaging_device_storage import SocialMessagingDeviceBindingRow, _lock_subject_user
from app.services.social_session_issuance import SocialSessionIssuance
from tests.integration.test_oauth_session_lifecycle_postgresql import authorize, exchange, fresh_browser, token_id
from tests.integration.test_social_device_ed25519_association_storage_postgresql import wait_until_blocked
from tests.integration.test_social_session_issuance_postgresql import generation_factory as generation_factory
from tests.integration.test_social_session_issuance_postgresql import ingress_live as ingress_live
from tests.integration.test_social_session_issuance_postgresql import issuance_ready as issuance_ready
from tests.integration.test_social_session_issuance_postgresql import issue
from tests.integration.test_social_session_issuance_postgresql import live as live
from tests.integration.test_social_session_issuance_postgresql import material as material
from tests.integration.test_social_session_issuance_postgresql import mobile_factory as mobile_factory
from tests.integration.test_social_session_issuance_postgresql import postgres_factory as postgres_factory
from tests.integration.test_social_session_issuance_postgresql import replay_ready as replay_ready
from tests.integration.test_social_session_issuance_postgresql import state as state

ROOT = Path(__file__).parents[2]
ED25519_MIGRATION = ROOT / "migrations/2026-09-22_social_device_ed25519_association_storage_v1.sql"
ERROR = "^social messaging device admission unavailable$"
OAUTH_ISSUER = "https://identity.example"
APPROVER_CLIENT = "other-client"


class _NoNetworkRedis:
    """Permit legacy app setup without opening a Redis connection."""

    def __init__(self, *args, **kwargs):
        pass

    @classmethod
    def from_url(cls, *args, **kwargs):
        return cls()

    @staticmethod
    def ping():
        return True

    def __getattr__(self, name):
        raise AssertionError(f"Redis authority use is prohibited: {name}")


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


@pytest.fixture(scope="module")
def authority_ready(issuance_ready):
    return issuance_ready


@pytest.fixture
def authority_live(request, authority_ready, monkeypatch):
    monkeypatch.setattr("redis.Redis", _NoNetworkRedis)
    live = request.getfixturevalue("live")
    engine, base_factory = authority_ready
    assert live["state"][1] is base_factory
    schema = "current_admission_" + uuid.uuid4().hex
    with engine.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
    isolated_engine = create_engine(
        engine.url,
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={
            "options": (f"-c search_path={schema},public " "-c statement_timeout=10000 -c lock_timeout=5000")
        },
    )
    try:
        with isolated_engine.begin() as connection:
            with connection.connection.cursor() as cursor:
                cursor.execute(ED25519_MIGRATION.read_text(encoding="ascii"))
        value = dict(live)
        state = list(live["state"])
        state[1] = sessionmaker(isolated_engine, expire_on_commit=False)
        value["state"] = tuple(state)
        yield value
    finally:
        isolated_engine.dispose()
        with engine.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')


def _authenticated_statement(input_wire: str, now_ms: int):
    value = admission.parse_verification_input_v1(input_wire)
    enrollment = profile.parse_enrollment_v2(value.challenge_wire)
    statement = object.__new__(AuthenticatedSocialDeviceVerificationStatementV1)
    values = {
        "result": admission.ENROLLMENT_V2_RESULT,
        "purpose": admission.STATEMENT_PURPOSE,
        "issuer": enrollment.audience,
        "challenge_kind": "enrollment-v2",
        "challenge_id": enrollment.enrollment_challenge_id,
        "attempt_id": value.context.attempt_id,
        "context_digest": admission.verification_context_digest_v1(value.context.wire),
        "input_digest": admission.verification_input_digest_v1(input_wire),
        "issued_at": now_ms,
        "expires_at": enrollment.expires_at,
    }
    for field, item in values.items():
        object.__setattr__(statement, field, item)
    return statement


def _association_input(context_wire: str, enrollment_wire: str, now_ms: int) -> str:
    enrollment = profile.parse_enrollment_v2(enrollment_wire)
    proof = profile.canonical_enrollment_proof_v2_bytes(
        enrollment_challenge_id=enrollment.enrollment_challenge_id,
        enrollment_digest=profile.enrollment_v2_digest(enrollment_wire),
        public_key=enrollment.ed25519_public_key,
        signature="11" * 64,
    ).decode("ascii")
    unsigned = profile.enrollment_approval_unsigned_event_v2(enrollment_wire)
    event_id = hashlib.sha256(
        canonical(
            [
                0,
                enrollment.subject,
                unsigned["created_at"],
                unsigned["kind"],
                unsigned["tags"],
                unsigned["content"],
            ]
        ).encode("ascii")
    ).hexdigest()
    approval = canonical(
        {
            **unsigned,
            "pubkey": enrollment.subject,
            "id": event_id,
            "sig": "22" * 64,
        }
    )
    return admission.canonical_verification_input_v1_bytes(
        context=context_wire,
        challenge=enrollment_wire,
        proof=proof,
        approval_event=approval,
        actual_request=None,
        routing_request=None,
    ).decode("ascii")


def _context_wire(
    *,
    enrollment_wire: str,
    association_id: str,
    association_version: int,
    predecessor: str | None,
    authority_epoch: int,
    session_value: str,
    approver_value: str,
    full_proof_id: str,
) -> str:
    enrollment = profile.parse_enrollment_v2(enrollment_wire)
    return admission.canonical_verification_context_v1_bytes(
        challenge_kind="enrollment-v2",
        challenge_id=enrollment.enrollment_challenge_id,
        attempt_id=hashlib.sha256((enrollment.enrollment_challenge_id + "attempt").encode()).hexdigest(),
        audience=enrollment.audience,
        subject=enrollment.subject,
        device_id=enrollment.device_id,
        binding_id=enrollment.x25519_binding_id,
        binding_version=enrollment.x25519_binding_version,
        x25519_public_key_commitment=enrollment.x25519_public_key_commitment,
        profile=profile.DEVICE_PROOF_PROFILE,
        ed25519_public_key=enrollment.ed25519_public_key,
        association_id=association_id,
        association_version=association_version,
        predecessor_association_id=predecessor,
        authority_epoch=authority_epoch,
        session_binding=session_value,
        approver_session_binding=approver_value,
        full_proof_id=full_proof_id,
        approver_full_proof_id=full_proof_id,
    ).decode("ascii")


def build_state(authority_live, *, establish_association: bool = True):
    _inputs, issued_value = issue(authority_live)
    factory = authority_live["state"][1]
    issuance_id = issued_value["receipt"]["issuanceId"]
    with factory() as db:
        issuance = db.execute(
            select(SocialSessionIssuance).where(SocialSessionIssuance.issuance_id == issuance_id)
        ).scalar_one()
        subject = issuance.subject
    oauth_state = authority_live["state"]
    approver_service = SqlAlchemyOAuthSessionLifecycle(
        factory,
        client_id=APPROVER_CLIENT,
        token_config=oauth_state[5],
        clock=lambda: oauth_state[3][0],
    )
    approver_service.test_browser_references = {}
    fresh_browser(approver_service, subject=subject)
    approver_code = authorize(approver_service, subject=subject)
    approver_response = exchange(approver_service, code=approver_code)
    approver_token_id = token_id(approver_response)
    with factory.begin() as db:
        issuance = db.execute(
            select(SocialSessionIssuance).where(SocialSessionIssuance.issuance_id == issuance_id)
        ).scalar_one()
        observed_s = issuance.issued_at + 1
        observed_ms = observed_s * 1000
        observed = datetime.fromtimestamp(observed_s, timezone.utc)
        parent = db.get(OAuthSessionGeneration, issuance.parent_token_id)
        approver = db.get(OAuthSessionGeneration, approver_token_id)
        full = SqlAlchemyTransactionBoundCurrentFullVerifier(db).verify_in_transaction(
            issuance.subject,
            now=observed,
        )
        binding = db.get(SocialMessagingDeviceBindingRow, issuance.binding_id)
        device_preimage = session_binding.canonical_session_binding_preimage_v1_bytes(
            subject=issuance.subject,
            device_id=issuance.device_id,
            x25519_binding_id=issuance.binding_id,
            social_session_issuance_id=issuance.issuance_id,
            social_session_token_id=issuance.token_id,
            parent_oauth_token_id=parent.token_id,
            parent_oauth_session_id=parent.session_id,
            parent_oauth_browser_generation_id=parent.browser_generation_id,
            client_id=issuance.client_id,
        ).decode("ascii")
        device_session_binding = session_binding.derive_session_binding_v1(device_preimage)
        approver_preimage = session_binding.canonical_approver_session_binding_preimage_v1_bytes(
            subject=approver.subject,
            oauth_token_id=approver.token_id,
            oauth_session_id=approver.session_id,
            oauth_browser_generation_id=approver.browser_generation_id,
            client_id=approver.client_id,
        ).decode("ascii")
        approver_session_binding = session_binding.derive_approver_session_binding_v1(approver_preimage)

        initial_enrollment = profile.canonical_enrollment_v2_bytes(
            audience="https://social.example",
            device_id=issuance.device_id,
            ed25519_public_key="c1" * 32,
            enrollment_challenge_id=uuid.uuid4().hex * 2,
            expires_at=observed_ms + 60_000,
            issued_at=observed_ms,
            subject=issuance.subject,
            x25519_binding_id=issuance.binding_id,
            x25519_binding_version=binding.binding_version,
            x25519_public_key_commitment=profile.x25519_public_key_commitment_v1(binding.public_key),
        ).decode("ascii")
        initial_id = ed_lifecycle.association_id_v1(initial_enrollment, 1, None)
        initial_context = _context_wire(
            enrollment_wire=initial_enrollment,
            association_id=initial_id,
            association_version=1,
            predecessor=None,
            authority_epoch=1,
            session_value=device_session_binding,
            approver_value=approver_session_binding,
            full_proof_id=full.proof_id,
        )
        initial_input = _association_input(initial_context, initial_enrollment, observed_ms)

        successor_enrollment = profile.canonical_enrollment_v2_bytes(
            audience="https://social.example",
            device_id=issuance.device_id,
            ed25519_public_key="c2" * 32,
            enrollment_challenge_id=uuid.uuid4().hex * 2,
            expires_at=observed_ms + 60_000,
            issued_at=observed_ms,
            subject=issuance.subject,
            x25519_binding_id=issuance.binding_id,
            x25519_binding_version=binding.binding_version,
            x25519_public_key_commitment=profile.x25519_public_key_commitment_v1(binding.public_key),
        ).decode("ascii")
        successor_id = ed_lifecycle.association_id_v1(successor_enrollment, 2, initial_id)
        successor_context = _context_wire(
            enrollment_wire=successor_enrollment,
            association_id=successor_id,
            association_version=2,
            predecessor=initial_id,
            authority_epoch=2,
            session_value=device_session_binding,
            approver_value=approver_session_binding,
            full_proof_id=full.proof_id,
        )
        successor_input = _association_input(
            successor_context,
            successor_enrollment,
            observed_ms,
        )
        if establish_association:
            store = SqlAlchemyEd25519AssociationStore(db)
            store.establish_initial(
                initial_input,
                _authenticated_statement(initial_input, observed_ms),
                now=observed_ms,
            )
            store.rotate(
                successor_input,
                _authenticated_statement(successor_input, observed_ms),
                now=observed_ms,
                expected_predecessor=initial_id,
                expected_epoch=1,
            )

        enrollment_context = admission.parse_verification_context_v1(successor_context)
        request_fields = json.loads(successor_context)
        request_fields.update(
            challengeKind="device-request-v1",
            challengeId=uuid.uuid4().hex * 2,
            predecessorAssociationId=None,
            approverSessionBinding=None,
            approverFullProofId=None,
        )
        request_context = admission.parse_verification_context_v1(canonical(request_fields))
        result = {
            "factory": factory,
            "observed_ms": observed_ms,
            "subject": issuance.subject,
            "device_id": issuance.device_id,
            "binding_id": issuance.binding_id,
            "issuance_id": issuance.issuance_id,
            "issuance_token_id": issuance.token_id,
            "issuance_expires_ms": issuance.expires_at * 1000,
            "device_client_id": issuance.client_id,
            "approver_session_id": approver.session_id,
            "approver_token_id": approver.token_id,
            "approver_client_id": approver.client_id,
            "association_id": successor_id,
            "authority_epoch": 2,
            "request_context": request_context,
            "enrollment_context": enrollment_context,
        }
    return result


def adapter(db, state, *, enrollment: bool):
    kwargs = {}
    if enrollment:
        kwargs = {
            "approver_oauth_session_id": state["approver_session_id"],
            "approver_client_id": state["approver_client_id"],
        }
    return authority.SqlAlchemyTransactionBoundAdmissionAuthority(
        db,
        device_issuance_id=state["issuance_id"],
        device_client_id=state["device_client_id"],
        oauth_issuer=OAUTH_ISSUER,
        **kwargs,
    )


def denied(db, state, context, *, enrollment: bool, observed_ms: int | None = None):
    with pytest.raises(admission.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
        adapter(db, state, enrollment=enrollment).lock_current_authority(
            context,
            observed_at=state["observed_ms"] if observed_ms is None else observed_ms,
        )


def replace_context(context, **updates):
    value = json.loads(context.wire)
    value.update(updates)
    return admission.parse_verification_context_v1(canonical(value))


def test_exact_request_and_enrollment_authority_are_provisional_and_caller_owned(
    authority_live,
):
    state = build_state(authority_live)
    for name, enrollment in (("request_context", False), ("enrollment_context", True)):
        with state["factory"]() as db:
            transaction = db.begin()
            commits = []
            original_commit = db.commit
            db.commit = lambda: commits.append(True)
            result = adapter(db, state, enrollment=enrollment).lock_current_authority(
                state[name],
                observed_at=state["observed_ms"],
            )
            assert result.context_digest == admission.verification_context_digest_v1(state[name].wire)
            assert result.authority_epoch == state["authority_epoch"]
            assert result.locked_deadline_ms > state["observed_ms"]
            if enrollment:
                assert result.approver_full_proof_id is not None
            else:
                assert result.approver_full_proof_id is None
            assert commits == []
            assert transaction.is_active and db.in_transaction()
            db.commit = original_commit
            transaction.rollback()
            assert not db.in_transaction()


def test_replaced_caller_transaction_is_denied(authority_live):
    state = build_state(authority_live)
    with state["factory"]() as db:
        original = db.begin()
        current = adapter(db, state, enrollment=False)
        original.rollback()
        replacement = db.begin()
        with pytest.raises(admission.SocialMessagingDeviceAdmissionUnavailable, match=ERROR):
            current.lock_current_authority(
                state["request_context"],
                observed_at=state["observed_ms"],
            )
        assert replacement.is_active and db.in_transaction()
        replacement.rollback()


@pytest.mark.parametrize(
    ("context_name", "field", "replacement"),
    (
        ("request_context", "fullProofId", "hodlxxi-full-entitlement-v1-sha256:" + "01" * 32),
        ("enrollment_context", "approverFullProofId", "hodlxxi-full-entitlement-v1-sha256:" + "02" * 32),
        ("request_context", "sessionBinding", "03" * 32),
        ("enrollment_context", "approverSessionBinding", "04" * 32),
        ("request_context", "bindingId", "05" * 32),
        ("request_context", "bindingVersion", 1024),
        (
            "request_context",
            "x25519PublicKeyCommitment",
            "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" + "06" * 32,
        ),
        ("request_context", "ed25519PublicKey", "07" * 32),
        ("request_context", "associationId", "08" * 32),
        ("request_context", "associationVersion", 3),
        ("enrollment_context", "predecessorAssociationId", "09" * 32),
        ("request_context", "authorityEpoch", 3),
        ("request_context", "deviceId", "0a" * 32),
    ),
)
def test_every_context_authority_substitution_is_denied(
    authority_live,
    context_name,
    field,
    replacement,
):
    state = build_state(authority_live)
    context = replace_context(state[context_name], **{field: replacement})
    with state["factory"]() as db:
        transaction = db.begin()
        denied(
            db,
            state,
            context,
            enrollment=context_name == "enrollment_context",
        )
        assert transaction.is_active
        transaction.rollback()


def test_absent_stale_and_revoked_full_are_denied(authority_live):
    state = build_state(authority_live)
    changes = (
        delete(CurrentEntitlementEvidence).where(CurrentEntitlementEvidence.subject_pubkey == state["subject"]),
        update(CurrentEntitlementEvidence)
        .where(CurrentEntitlementEvidence.subject_pubkey == state["subject"])
        .values(valid_until=datetime.fromtimestamp(state["observed_ms"] / 1000, timezone.utc)),
        update(CurrentEntitlementEvidence)
        .where(CurrentEntitlementEvidence.subject_pubkey == state["subject"])
        .values(revoked_at=datetime.fromtimestamp(state["observed_ms"] / 1000, timezone.utc)),
    )
    for change in changes:
        with state["factory"]() as db:
            transaction = db.begin()
            db.execute(change)
            denied(db, state, state["request_context"], enrollment=False)
            transaction.rollback()


def test_missing_expired_and_revoked_session_authorities_are_denied(authority_live):
    state = build_state(authority_live)
    missing = dict(state, issuance_id="0b" * 32)
    with state["factory"]() as db:
        transaction = db.begin()
        denied(db, missing, state["request_context"], enrollment=False)
        transaction.rollback()
    with state["factory"]() as db:
        transaction = db.begin()
        denied(
            db,
            state,
            state["request_context"],
            enrollment=False,
            observed_ms=state["issuance_expires_ms"],
        )
        transaction.rollback()
    with state["factory"]() as db:
        transaction = db.begin()
        db.execute(update(OAuthToken).where(OAuthToken.id == state["issuance_token_id"]).values(is_revoked=True))
        denied(db, state, state["request_context"], enrollment=False)
        transaction.rollback()


def test_independent_approver_missing_revoked_and_self_approval_are_denied(authority_live):
    state = build_state(authority_live)
    for session_id in ("0c" * 32, state["issuance_token_id"] * 2):
        changed = dict(state, approver_session_id=session_id)
        with state["factory"]() as db:
            transaction = db.begin()
            denied(db, changed, state["enrollment_context"], enrollment=True)
            transaction.rollback()
    with state["factory"]() as db:
        transaction = db.begin()
        db.execute(update(OAuthToken).where(OAuthToken.id == state["approver_token_id"]).values(is_revoked=True))
        denied(db, state, state["enrollment_context"], enrollment=True)
        transaction.rollback()
    with state["factory"]() as db:
        transaction = db.begin()
        db.execute(
            update(Session)
            .where(Session.session_id == state["approver_session_id"])
            .values(expires_at=datetime.fromtimestamp(state["observed_ms"] / 1000, timezone.utc))
        )
        denied(db, state, state["enrollment_context"], enrollment=True)
        transaction.rollback()


def test_inactive_or_expired_x25519_and_missing_binding_are_denied(authority_live):
    state = build_state(authority_live)
    missing = replace_context(state["request_context"], bindingId="0d" * 32)
    with state["factory"]() as db:
        transaction = db.begin()
        denied(db, state, missing, enrollment=False)
        transaction.rollback()
    with state["factory"]() as db:
        transaction = db.begin()
        instant = datetime.fromtimestamp(state["observed_ms"] / 1000, timezone.utc)
        db.execute(
            update(SocialMessagingDeviceBindingRow)
            .where(SocialMessagingDeviceBindingRow.binding_id == state["binding_id"])
            .values(active=False, retired_at=instant)
        )
        denied(db, state, state["request_context"], enrollment=False)
        transaction.rollback()
    with state["factory"]() as db:
        transaction = db.begin()
        row = db.get(SocialMessagingDeviceBindingRow, state["binding_id"])
        denied(
            db,
            state,
            state["request_context"],
            enrollment=False,
            observed_ms=int(row.expires_at.replace(tzinfo=timezone.utc).timestamp() * 1000),
        )
        transaction.rollback()


def test_missing_and_revoked_ed25519_authority_are_denied(authority_live):
    missing_state = build_state(authority_live, establish_association=False)
    with missing_state["factory"]() as db:
        transaction = db.begin()
        denied(db, missing_state, missing_state["request_context"], enrollment=False)
        transaction.rollback()


def test_revoked_ed25519_authority_is_denied(authority_live):
    state = build_state(authority_live)
    with state["factory"]() as db:
        transaction = db.begin()
        SqlAlchemyEd25519AssociationStore(db).revoke(
            state["subject"],
            state["device_id"],
            expected_association_id=state["association_id"],
            expected_epoch=state["authority_epoch"],
        )
        denied(db, state, state["request_context"], enrollment=False)
        transaction.rollback()


@pytest.mark.parametrize("race", ("x25519", "ed25519", "session", "full"))
def test_authority_waits_then_rechecks_post_commit_state(authority_live, race):
    state = build_state(authority_live)
    engine, factory = authority_live["state"][:2]
    ready = threading.Event()
    release = threading.Event()
    pids = {}

    def invalidate():
        with factory.begin() as db:
            pids["writer"] = db.execute(text("SELECT pg_backend_pid()")).scalar_one()
            instant = datetime.fromtimestamp(state["observed_ms"] / 1000, timezone.utc)
            if race == "x25519":
                SqlAlchemyTransactionBoundCurrentFullVerifier(db).verify_in_transaction(
                    state["subject"],
                    now=instant,
                )
                _lock_subject_user(db, state["subject"])
                row = db.get(
                    SocialMessagingDeviceBindingRow,
                    state["binding_id"],
                    with_for_update=True,
                )
                row.active = False
                row.retired_at = instant
                db.flush()
            elif race == "ed25519":
                SqlAlchemyEd25519AssociationStore(db).revoke(
                    state["subject"],
                    state["device_id"],
                    expected_association_id=state["association_id"],
                    expected_epoch=state["authority_epoch"],
                )
            elif race == "session":
                token = db.get(
                    OAuthToken,
                    state["issuance_token_id"],
                    with_for_update=True,
                )
                token.is_revoked = True
                db.flush()
            else:
                _lock_subject_for_evidence_change(db, state["subject"])
                evidence = db.execute(
                    select(CurrentEntitlementEvidence)
                    .where(CurrentEntitlementEvidence.subject_pubkey == state["subject"])
                    .with_for_update()
                ).scalar_one()
                evidence.revoked_at = instant
                db.flush()
            ready.set()
            assert release.wait(5)

    def read_authority():
        with factory() as db:
            transaction = db.begin()
            pids["reader"] = db.execute(text("SELECT pg_backend_pid()")).scalar_one()
            try:
                adapter(db, state, enrollment=False).lock_current_authority(
                    state["request_context"],
                    observed_at=state["observed_ms"],
                )
            except admission.SocialMessagingDeviceAdmissionUnavailable:
                transaction.rollback()
                return "denied"
            transaction.rollback()
            return "unexpected-success"

    with ThreadPoolExecutor(max_workers=2) as pool:
        writer = pool.submit(invalidate)
        assert ready.wait(5)
        reader = pool.submit(read_authority)
        while "reader" not in pids:
            threading.Event().wait(0.01)
        wait_until_blocked(engine, pids["reader"], pids["writer"])
        release.set()
        writer.result(timeout=5)
        assert reader.result(timeout=5) == "denied"
