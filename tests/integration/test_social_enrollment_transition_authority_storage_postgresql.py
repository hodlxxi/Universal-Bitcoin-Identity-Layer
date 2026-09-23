"""Disposable PostgreSQL proof for locked enrollment transition authority."""

from __future__ import annotations

import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import func, select, text, update

from app.models import CurrentEntitlementEvidence, OAuthSessionGeneration, OAuthToken, Session
from app.services import social_enrollment_transition_authority as contract
from app.services import social_enrollment_transition_authority_storage as storage
from app.services import social_messaging_device_admission_contract as admission
from app.services import social_messaging_device_ed25519_association_lifecycle as ed_lifecycle
from app.services import social_messaging_device_proof_profile as profile
from app.services.current_entitlement_evidence_storage import _lock_subject_for_evidence_change
from app.services.social_device_challenge_store import SocialDeviceAdmissionChallengeRow, SqlAlchemyDeviceChallengeStore
from app.services.social_device_ed25519_association_storage import (
    SocialDeviceEd25519AssociationEvent,
    SqlAlchemyEd25519AssociationStore,
)
from app.services.social_device_verification_statement import AuthenticatedSocialDeviceVerificationStatementV1
from app.services.social_messaging_device_storage import SocialMessagingDeviceBindingRow, _lock_subject_user
from app.services.social_session_issuance import SocialSessionIssuance
from tests.integration.test_social_current_admission_authority_postgresql import (
    OAUTH_ISSUER,
    _association_input,
    _context_wire,
    authority_live,
    authority_ready,
    build_state,
)
from tests.integration.test_social_device_ed25519_association_storage_postgresql import wait_until_blocked
from tests.integration.test_social_session_issuance_postgresql import generation_factory as generation_factory
from tests.integration.test_social_session_issuance_postgresql import ingress_live as ingress_live
from tests.integration.test_social_session_issuance_postgresql import issuance_ready as issuance_ready
from tests.integration.test_social_session_issuance_postgresql import live as live
from tests.integration.test_social_session_issuance_postgresql import material as material
from tests.integration.test_social_session_issuance_postgresql import mobile_factory as mobile_factory
from tests.integration.test_social_session_issuance_postgresql import postgres_factory as postgres_factory
from tests.integration.test_social_session_issuance_postgresql import replay_ready as replay_ready
from tests.integration.test_social_session_issuance_postgresql import state as state

ROOT = Path(__file__).parents[2]
CHALLENGE_MIGRATION = ROOT / "migrations/2026-09-21_social_device_challenge_store_v1.sql"
ERROR = "^social enrollment transition authority storage unavailable$"


@pytest.fixture
def transition_live(authority_live):
    factory = authority_live["state"][1]
    engine = factory.kw["bind"]
    with engine.begin() as connection:
        with connection.connection.cursor() as cursor:
            cursor.execute(CHALLENGE_MIGRATION.read_text(encoding="ascii"))
    return authority_live


def _statement(input_wire: str, observed_at: int) -> AuthenticatedSocialDeviceVerificationStatementV1:
    value = admission.parse_verification_input_v1(input_wire)
    enrollment = profile.parse_enrollment_v2(value.challenge_wire)
    result = object.__new__(AuthenticatedSocialDeviceVerificationStatementV1)
    fields = {
        "issuer": value.context.audience,
        "audience": "https://ubid.example/internal/v1/social/device-admission/consume",
        "client_id": "social-device-admission-client-v1",
        "service_principal": "social-device-verifier-v1",
        "purpose": admission.STATEMENT_PURPOSE,
        "result": admission.ENROLLMENT_V2_RESULT,
        "challenge_kind": "enrollment-v2",
        "challenge_id": value.context.challenge_id,
        "attempt_id": value.context.attempt_id,
        "context_digest": admission.verification_context_digest_v1(value.context.wire),
        "input_digest": admission.verification_input_digest_v1(value.wire),
        "issued_at": observed_at,
        "expires_at": min(observed_at + 9_000, enrollment.expires_at),
        "token_id": uuid.uuid4().hex * 2,
        "key_id": "social-device-verifier-rs256-v1",
        "key_fingerprint": "sha256:" + "ab" * 32,
    }
    for name, item in fields.items():
        object.__setattr__(result, name, item)
    return result


def _enrollment(state, public_key: str, challenge_id: str) -> str:
    context = state["enrollment_context"]
    return profile.canonical_enrollment_v2_bytes(
        audience=context.audience,
        device_id=context.device_id,
        ed25519_public_key=public_key,
        enrollment_challenge_id=challenge_id,
        expires_at=state["observed_ms"] + 60_000,
        issued_at=state["observed_ms"],
        subject=context.subject,
        x25519_binding_id=context.binding_id,
        x25519_binding_version=context.binding_version,
        x25519_public_key_commitment=context.x25519_public_key_commitment,
    ).decode("ascii")


def _candidate_context(
    state,
    enrollment_wire: str,
    *,
    association_id: str,
    association_version: int,
    predecessor: str | None,
    authority_epoch: int,
    updates: dict[str, object] | None = None,
) -> str:
    base = state["enrollment_context"]
    wire = _context_wire(
        enrollment_wire=enrollment_wire,
        association_id=association_id,
        association_version=association_version,
        predecessor=predecessor,
        authority_epoch=authority_epoch,
        session_value=base.session_binding,
        approver_value=base.approver_session_binding,
        full_proof_id=base.full_proof_id,
    )
    if updates:
        fields = json.loads(wire)
        fields.update(updates)
        wire = json.dumps(fields, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        admission.parse_verification_context_v1(wire)
    return wire


def build_transition(
    transition_live,
    kind: str,
    *,
    context_updates=None,
    enrollment_updates=None,
    create_challenge=True,
):
    state = build_state(transition_live, establish_association=False)
    factory = state["factory"]
    initial_enrollment = _enrollment(state, "d1" * 32, uuid.uuid4().hex * 2)
    initial_id = ed_lifecycle.association_id_v1(initial_enrollment, 1, None)
    initial_context = _candidate_context(
        state,
        initial_enrollment,
        association_id=initial_id,
        association_version=1,
        predecessor=None,
        authority_epoch=1,
    )
    initial_input = _association_input(initial_context, initial_enrollment, state["observed_ms"])

    if kind != "initial":
        with factory.begin() as db:
            SqlAlchemyEd25519AssociationStore(db).establish_initial(
                initial_input,
                _statement(initial_input, state["observed_ms"]),
                now=state["observed_ms"],
            )
        if kind == "reenroll":
            with factory.begin() as db:
                SqlAlchemyEd25519AssociationStore(db).revoke(
                    state["subject"],
                    state["device_id"],
                    expected_association_id=initial_id,
                    expected_epoch=1,
                )

    if kind == "initial":
        enrollment_wire = initial_enrollment
        association_id = initial_id
        version = epoch = 1
        predecessor = None
    else:
        enrollment_wire = _enrollment(state, "d2" * 32, uuid.uuid4().hex * 2)
        if enrollment_updates:
            enrollment_fields = json.loads(enrollment_wire)
            enrollment_fields.update(enrollment_updates)
            enrollment_wire = json.dumps(
                enrollment_fields,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            profile.parse_enrollment_v2(enrollment_wire)
        version = 2
        epoch = 2 if kind == "rotate" else 3
        predecessor = initial_id
        association_id = ed_lifecycle.association_id_v1(enrollment_wire, version, predecessor)
    context_wire = _candidate_context(
        state,
        enrollment_wire,
        association_id=association_id,
        association_version=version,
        predecessor=predecessor,
        authority_epoch=epoch,
        updates=context_updates,
    )
    input_wire = _association_input(context_wire, enrollment_wire, state["observed_ms"])
    value = admission.parse_verification_input_v1(input_wire)
    authenticated = _statement(input_wire, state["observed_ms"])
    if create_challenge:
        with factory.begin() as db:
            SqlAlchemyDeviceChallengeStore(db).create_issued(
                context_wire=context_wire,
                challenge_wire=enrollment_wire,
            )
    return {
        **state,
        "kind": kind,
        "value": value,
        "statement": authenticated,
        "initial_id": initial_id,
    }


def adapter(db, state):
    return storage.SqlAlchemyTransactionBoundEnrollmentTransitionAuthority(
        db,
        device_issuance_id=state["issuance_id"],
        device_client_id=state["device_client_id"],
        oauth_issuer=OAUTH_ISSUER,
        approver_oauth_session_id=state["approver_session_id"],
        approver_client_id=state["approver_client_id"],
    )


def denied(db, state, *, observed_at=None, statement=None):
    with pytest.raises(storage.SocialEnrollmentTransitionAuthorityStorageUnavailable, match=ERROR):
        adapter(db, state).lock_transition_authority(
            state["value"],
            state["statement"] if statement is None else statement,
            observed_at=state["observed_ms"] if observed_at is None else observed_at,
        )


@pytest.mark.parametrize(
    ("kind", "expected"),
    (("initial", "initial"), ("rotate", "rotate"), ("reenroll", "reenroll")),
)
def test_transition_authority_is_locked_pre_effect_read_only_and_caller_owned(transition_live, kind, expected):
    state = build_transition(transition_live, kind)
    factory = state["factory"]
    with factory() as db:
        transaction = db.begin()
        before = db.execute(select(func.count()).select_from(SocialDeviceEd25519AssociationEvent)).scalar_one()
        commits = []
        rollbacks = []
        original_commit = db.commit
        original_rollback = db.rollback
        db.commit = lambda: commits.append(True)
        db.rollback = lambda: rollbacks.append(True)
        result = adapter(db, state).lock_transition_authority(
            state["value"],
            state["statement"],
            observed_at=state["observed_ms"],
        )
        assert type(result) is contract.EnrollmentTransitionAuthorityV1
        assert result.transition_kind == expected
        assert result.proposed_association_id == state["value"].context.association_id
        assert result.observed_at == state["observed_ms"]
        assert result.locked_deadline_ms > result.observed_at
        assert contract.prepared_enrollment_effect_v1(result).operation == "enrollment-activate"
        assert db.execute(select(func.count()).select_from(SocialDeviceEd25519AssociationEvent)).scalar_one() == before
        challenge = db.get(SocialDeviceAdmissionChallengeRow, result.challenge_id, populate_existing=True)
        assert challenge.state == "issued"
        assert commits == rollbacks == []
        assert transaction.is_active and db.in_transaction()
        db.commit = original_commit
        db.rollback = original_rollback
        challenge.state = "invalidated"
        db.flush()
        transaction.rollback()
        assert not db.in_transaction()
    with factory() as db:
        challenge = db.get(SocialDeviceAdmissionChallengeRow, result.challenge_id)
        assert challenge.state == "issued"
    assert storage.FINAL_ADMISSION == "denied"


def test_rotation_success_does_not_require_proposed_successor_to_be_current(transition_live):
    state = build_transition(transition_live, "rotate")
    with state["factory"]() as db:
        transaction = db.begin()
        current = SqlAlchemyEd25519AssociationStore(db).lock_current_association(state["subject"], state["device_id"])
        assert current.association_id == state["initial_id"]
        assert current.association_id != state["value"].context.association_id
        result = adapter(db, state).lock_transition_authority(
            state["value"], state["statement"], observed_at=state["observed_ms"]
        )
        assert result.pre_effect_association_id == current.association_id
        transaction.rollback()


@pytest.mark.parametrize("scenario", ("missing", "terminal", "expired", "untyped_statement"))
def test_missing_terminal_expired_and_untyped_challenge_or_statement_are_denied(transition_live, scenario):
    state = build_transition(
        transition_live,
        "initial",
        create_challenge=scenario != "missing",
    )
    with state["factory"]() as db:
        transaction = db.begin()
        if scenario == "terminal":
            db.execute(
                update(SocialDeviceAdmissionChallengeRow)
                .where(SocialDeviceAdmissionChallengeRow.challenge_id == state["value"].context.challenge_id)
                .values(state="invalidated")
            )
        if scenario == "expired":
            challenge = db.get(SocialDeviceAdmissionChallengeRow, state["value"].context.challenge_id)
            observed_at = json.loads(challenge.challenge_wire)["expiresAt"]
        else:
            observed_at = None
        denied(
            db,
            state,
            observed_at=observed_at,
            statement=object() if scenario == "untyped_statement" else None,
        )
        transaction.rollback()


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("fullProofId", "hodlxxi-full-entitlement-v1-sha256:" + "31" * 32),
        ("approverFullProofId", "hodlxxi-full-entitlement-v1-sha256:" + "32" * 32),
        ("sessionBinding", "33" * 32),
        ("approverSessionBinding", "34" * 32),
        ("predecessorAssociationId", "36" * 32),
        ("associationId", "37" * 32),
        ("associationVersion", 9),
        ("authorityEpoch", 9),
    ),
)
def test_stale_or_mismatched_locked_authority_and_proposal_are_denied(transition_live, field, replacement):
    state = build_transition(transition_live, "rotate", context_updates={field: replacement})
    with state["factory"]() as db:
        transaction = db.begin()
        denied(db, state)
        transaction.rollback()


def test_x25519_commitment_mismatch_is_denied(transition_live):
    state = build_transition(
        transition_live,
        "rotate",
        enrollment_updates={
            "x25519PublicKeyCommitment": "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" + "35" * 32
        },
    )
    with state["factory"]() as db:
        transaction = db.begin()
        denied(db, state)
        transaction.rollback()


@pytest.mark.parametrize("role", ("device_revoked", "device_expired", "approver_revoked", "approver_expired"))
def test_device_and_approver_session_revocation_or_expiry_are_denied(transition_live, role):
    state = build_transition(transition_live, "initial")
    with state["factory"]() as db:
        transaction = db.begin()
        if role == "device_revoked":
            db.execute(update(OAuthToken).where(OAuthToken.id == state["issuance_token_id"]).values(is_revoked=True))
        elif role == "approver_revoked":
            db.execute(update(OAuthToken).where(OAuthToken.id == state["approver_token_id"]).values(is_revoked=True))
        elif role == "approver_expired":
            db.execute(
                update(Session)
                .where(Session.session_id == state["approver_session_id"])
                .values(expires_at=datetime.fromtimestamp(state["observed_ms"] / 1000, timezone.utc))
            )
        else:
            issuance = db.execute(
                select(SocialSessionIssuance).where(SocialSessionIssuance.issuance_id == state["issuance_id"])
            ).scalar_one()
            parent = db.get(OAuthSessionGeneration, issuance.parent_token_id)
            db.execute(
                update(Session)
                .where(Session.session_id == parent.session_id)
                .values(expires_at=datetime.fromtimestamp(state["observed_ms"] / 1000, timezone.utc))
            )
        denied(db, state)
        transaction.rollback()


def test_replaced_caller_transaction_is_denied(transition_live):
    state = build_transition(transition_live, "initial")
    with state["factory"]() as db:
        original = db.begin()
        current = adapter(db, state)
        original.rollback()
        replacement = db.begin()
        with pytest.raises(storage.SocialEnrollmentTransitionAuthorityStorageUnavailable, match=ERROR):
            current.lock_transition_authority(state["value"], state["statement"], observed_at=state["observed_ms"])
        assert replacement.is_active and db.in_transaction()
        replacement.rollback()


@pytest.mark.parametrize("race", ("challenge", "full", "session", "x25519", "ed25519"))
def test_lock_waits_recheck_one_coherent_pre_effect_state(transition_live, race):
    state = build_transition(transition_live, "rotate")
    factory = state["factory"]
    engine = factory.kw["bind"]
    ready = threading.Event()
    release = threading.Event()
    pids = {}

    def invalidate():
        with factory.begin() as db:
            pids["writer"] = db.execute(text("SELECT pg_backend_pid()")).scalar_one()
            instant = datetime.fromtimestamp(state["observed_ms"] / 1000, timezone.utc)
            if race == "challenge":
                db.execute(
                    update(SocialDeviceAdmissionChallengeRow)
                    .where(SocialDeviceAdmissionChallengeRow.challenge_id == state["value"].context.challenge_id)
                    .values(state="invalidated")
                )
            elif race == "full":
                _lock_subject_for_evidence_change(db, state["subject"])
                evidence = db.execute(
                    select(CurrentEntitlementEvidence)
                    .where(CurrentEntitlementEvidence.subject_pubkey == state["subject"])
                    .with_for_update()
                ).scalar_one()
                evidence.revoked_at = instant
                db.flush()
            elif race == "session":
                token = db.get(OAuthToken, state["issuance_token_id"], with_for_update=True)
                token.is_revoked = True
                db.flush()
            elif race == "x25519":
                _lock_subject_for_evidence_change(db, state["subject"])
                _lock_subject_user(db, state["subject"])
                binding = db.get(SocialMessagingDeviceBindingRow, state["binding_id"], with_for_update=True)
                binding.active = False
                binding.retired_at = instant
                db.flush()
            else:
                SqlAlchemyEd25519AssociationStore(db).revoke(
                    state["subject"],
                    state["device_id"],
                    expected_association_id=state["initial_id"],
                    expected_epoch=1,
                )
            ready.set()
            assert release.wait(5)

    def read_authority():
        with factory() as db:
            transaction = db.begin()
            pids["reader"] = db.execute(text("SELECT pg_backend_pid()")).scalar_one()
            try:
                adapter(db, state).lock_transition_authority(
                    state["value"], state["statement"], observed_at=state["observed_ms"]
                )
            except storage.SocialEnrollmentTransitionAuthorityStorageUnavailable:
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
