"""Synthetic PostgreSQL rehearsal using the existing guarded disposable target."""

import json
import subprocess
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import event, func, select, text
from sqlalchemy.exc import IntegrityError, InternalError

from app.models import CurrentEntitlementEvidence, Session, User
from app.services import social_messaging_mobile_authorization as protocol
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement_evidence import CONTRACT_VERSION
from app.services.social_messaging_device_binding_authorization import (
    SIGNATURE_FORMAT,
    DeviceBindingAuthorizationUnavailable,
)
from app.services.social_messaging_device_binding_authorization_storage import (
    SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage,
)
from app.services.social_messaging_device_storage import (
    SocialMessagingDeviceBindingRow,
    SqlAlchemyTransactionBoundSocialMessagingDeviceStorage,
)
from app.services.social_messaging_mobile_authorization_storage import (
    MobileAcceptanceRow,
    MobileExchangeRow,
    MobileOperationRow,
    MobileRequestRow,
    MobileSessionHandoffRow,
    SqlAlchemyMobileAuthorizationService,
    _binding,
)
from tests.integration.test_social_messaging_device_binding_authorization_storage_postgresql import (
    postgres_factory as postgres_factory,
)
from tests.unit.test_social_messaging_mobile_authorization import (
    FIRST,
    REVISION,
    SUBJECT,
    VECTORS,
    event_for,
    source_for,
    submission_for,
)

NOW = FIRST["now"]
START = protocol._second(VECTORS["pairingContext"]["createdAt"])
LOGIN = VECTORS["legacyContext"]["loginContext"]
DESKTOP = VECTORS["pairingContext"]["desktopContext"]
CHALLENGE = VECTORS["legacyContext"]["challenge"]
PAIRING = VECTORS["pairingContext"]["pairingId"]
AUTH_SESSION = "synthetic-authenticated-session"
MIGRATION = Path(__file__).parents[2] / "migrations/2026-09-13_social_messaging_mobile_authorization_v1.sql"


@pytest.fixture(scope="module")
def mobile_factory(postgres_factory):
    engine, factory = postgres_factory
    with engine.begin() as connection:
        Session.__table__.create(connection)
        connection.exec_driver_sql(MIGRATION.read_text())
    return engine, factory


@pytest.fixture(autouse=True)
def seed(mobile_factory):
    engine, factory = mobile_factory
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "TRUNCATE social_messaging_mobile_session_handoffs, social_messaging_mobile_exchanges, "
            "social_messaging_mobile_acceptances, social_messaging_mobile_operations, "
            "social_messaging_device_authorization_binding_owners, social_messaging_device_authorization_requests, "
            "social_messaging_device_binding_authorization_replay, social_messaging_device_binding_authorization_evidence, "
            "social_messaging_device_bindings, sessions, current_entitlement_evidence, users CASCADE"
        )
    timestamp = datetime.fromtimestamp(START, timezone.utc)
    with factory.begin() as session:
        user_id = str(uuid.uuid4())
        session.add(User(id=user_id, pubkey=SUBJECT, is_active=True, created_at=timestamp.replace(tzinfo=None)))
        session.flush()
        session.add(
            Session(
                session_id=AUTH_SESSION,
                user_id=user_id,
                session_type="web",
                is_active=True,
                created_at=(timestamp - timedelta(seconds=60)).replace(tzinfo=None),
                expires_at=(timestamp + timedelta(hours=2)).replace(tzinfo=None),
            )
        )
        session.add(
            CurrentEntitlementEvidence(
                evidence_id=str(uuid.uuid4()),
                contract_version=CONTRACT_VERSION,
                subject_pubkey=SUBJECT,
                identity_class=IdentityClass.FULL.value,
                current_full_relation_satisfied=True,
                evidence_source="synthetic-mobile-test",
                evidence_version="v1",
                source_evidence_sha256="ab" * 32,
                observed_at=timestamp - timedelta(seconds=60),
                valid_until=timestamp + timedelta(seconds=600),
                revoked_at=None,
                created_at=timestamp,
            )
        )


def service(mobile_factory, now=NOW):
    return SqlAlchemyMobileAuthorizationService(
        mobile_factory[1],
        clock=lambda: now,
        legacy_challenge_factory=lambda: CHALLENGE,
    )


def reserve(mobile_factory):
    return service(mobile_factory).reserve_legacy(
        FIRST["content"],
        session_id=AUTH_SESSION,
        subject=SUBJECT,
        login_context=LOGIN,
    )


def offer(mobile_factory):
    values = iter((bytes.fromhex(PAIRING), bytes.fromhex(VECTORS["pairingSecret"])))
    return service(mobile_factory, START).create_pairing(
        session_id=AUTH_SESSION,
        subject=SUBJECT,
        desktop_context=DESKTOP,
        revision=REVISION,
        random_bytes=lambda _size: next(values),
    )


def scan(mobile_factory, qr):
    return service(mobile_factory).scan_pairing(
        source_for(),
        qr=qr,
        possession_proof=FIRST[protocol.QR]["possessionProof"],
    )


def claim(mobile_factory):
    return service(mobile_factory).claim_approval(
        PAIRING,
        session_id=AUTH_SESSION,
        subject=SUBJECT,
        desktop_context=DESKTOP,
        revision=REVISION,
        authorization_digest=FIRST[protocol.QR]["digest"],
        human_code=FIRST[protocol.QR]["comparisonCode"],
    )


def accept(mobile_factory, method=protocol.LEGACY, now=NOW, **changes):
    kwargs = dict(
        method=method,
        session_id=AUTH_SESSION,
        subject=SUBJECT,
        context_id=LOGIN if method == protocol.LEGACY else DESKTOP,
        authorization_digest=FIRST[method]["digest"],
        revision=None if method == protocol.LEGACY else REVISION,
    )
    kwargs.update(changes)
    return service(mobile_factory, now).accept(
        CHALLENGE if method == protocol.LEGACY else PAIRING,
        submission_for() if method == protocol.LEGACY else event_for(),
        **kwargs,
    )


def prepare(mobile_factory, method):
    if method == protocol.LEGACY:
        reserve(mobile_factory)
    else:
        _offer, qr = offer(mobile_factory)
        scan(mobile_factory, qr)
        claim(mobile_factory)


def count(mobile_factory, model):
    with mobile_factory[1]() as session:
        return session.scalar(select(func.count()).select_from(model))


def exchange(mobile_factory, now=NOW, **changes):
    kwargs = dict(
        verifier=VECTORS["exchangeVerifier"],
        subject=SUBJECT,
        revision=REVISION,
        authorization_digest=FIRST[protocol.QR]["digest"],
    )
    kwargs.update(changes)
    return service(mobile_factory, now).consume_exchange(PAIRING, **kwargs)


@pytest.mark.parametrize("method", [protocol.LEGACY, protocol.QR])
def test_recreation_one_shot_and_exact_lost_response_recovery(mobile_factory, method):
    prepare(mobile_factory, method)
    mobile_factory[0].dispose()
    result = accept(mobile_factory, method)
    mobile_factory[0].dispose()
    assert accept(mobile_factory, method, now=NOW + 301) == result
    assert count(mobile_factory, MobileAcceptanceRow) == 1
    assert count(mobile_factory, SocialMessagingDeviceBindingRow) == 1
    assert count(mobile_factory, MobileRequestRow) == 1


@pytest.mark.parametrize("method", [protocol.LEGACY, protocol.QR])
def test_simultaneous_accepts_have_one_durable_winner(mobile_factory, method):
    prepare(mobile_factory, method)
    gate = threading.Barrier(2)

    def worker():
        gate.wait(timeout=10)
        return accept(mobile_factory, method)

    with ThreadPoolExecutor(2) as pool:
        first, second = pool.submit(worker), pool.submit(worker)
        assert first.result(timeout=20) == second.result(timeout=20)
    assert count(mobile_factory, MobileAcceptanceRow) == 1
    assert count(mobile_factory, SocialMessagingDeviceBindingRow) == 1


def test_scan_and_claim_grant_nothing_and_claim_never_reopens(mobile_factory):
    _offer, qr = offer(mobile_factory)
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        exchange(mobile_factory)
    scan(mobile_factory, qr)
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        accept(mobile_factory, protocol.QR)
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        scan(mobile_factory, qr)
    claim(mobile_factory)
    mobile_factory[0].dispose()
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        claim(mobile_factory)
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        exchange(mobile_factory)
    assert count(mobile_factory, MobileAcceptanceRow) == 0
    assert count(mobile_factory, SocialMessagingDeviceBindingRow) == 0


@pytest.mark.parametrize("change", ["subject", "context", "logout", "replacement", "generation", "inactive_user"])
@pytest.mark.parametrize("method", [protocol.LEGACY, protocol.QR])
def test_authentication_swaps_fail_closed(mobile_factory, change, method):
    prepare(mobile_factory, method)
    args = {}
    if change == "subject":
        args["subject"] = "ab" * 32
    elif change == "context":
        args["context_id"] = "ab" * 32
    else:
        with mobile_factory[1].begin() as session:
            auth = session.get(Session, AUTH_SESSION)
            if change == "logout":
                auth.is_active = False
            elif change == "generation":
                auth.created_at += timedelta(seconds=1)
            elif change == "inactive_user":
                session.get(User, auth.user_id).is_active = False
            else:
                session.add(
                    Session(
                        session_id="synthetic-replacement",
                        user_id=auth.user_id,
                        session_type=auth.session_type,
                        is_active=True,
                        created_at=auth.created_at,
                        expires_at=auth.expires_at,
                    )
                )
                args["session_id"] = "synthetic-replacement"
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        accept(mobile_factory, method, **args)
    assert count(mobile_factory, MobileAcceptanceRow) == 0


@pytest.mark.parametrize("method", [protocol.LEGACY, protocol.QR])
@pytest.mark.parametrize("failure", ["expiry", "limited", "expired_full", "revoked_full"])
def test_expiration_and_current_full_remain_independent(mobile_factory, method, failure):
    prepare(mobile_factory, method)
    with mobile_factory[1].begin() as session:
        evidence = session.scalar(select(CurrentEntitlementEvidence))
        if failure == "limited":
            evidence.identity_class = IdentityClass.LIMITED.value
            evidence.current_full_relation_satisfied = False
        elif failure == "expired_full":
            evidence.valid_until = datetime.fromtimestamp(NOW, timezone.utc)
        elif failure == "revoked_full":
            evidence.revoked_at = datetime.fromtimestamp(NOW, timezone.utc)
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        accept(mobile_factory, method, now=START + 300 if failure == "expiry" else NOW)
    assert count(mobile_factory, MobileAcceptanceRow) == 0
    assert count(mobile_factory, SocialMessagingDeviceBindingRow) == 0


@pytest.mark.parametrize("status", ["cancelled", "abandoned", "rejected", "expired"])
@pytest.mark.parametrize("method", [protocol.LEGACY, protocol.QR])
def test_terminal_policy_and_phone_pending_state(mobile_factory, status, method):
    prepare(mobile_factory, method)
    kwargs = dict(
        method=method,
        session_id=AUTH_SESSION,
        subject=SUBJECT,
        context_id=LOGIN if method == protocol.LEGACY else DESKTOP,
    )
    identifier = CHALLENGE if method == protocol.LEGACY else PAIRING
    if status == "expired":
        result = service(mobile_factory, START + 300).status(identifier, **kwargs)
        assert json.loads(result)["status"] == status
    else:
        assert service(mobile_factory).close(identifier, status=status, **kwargs) == status
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        accept(mobile_factory, method)
    if method == protocol.QR:
        result = service(mobile_factory).phone_status(
            PAIRING,
            verifier=VECTORS["exchangeVerifier"],
            authorization_digest=FIRST[protocol.QR]["digest"],
            revision=REVISION,
        )
        assert json.loads(result)["status"] == status


def test_legacy_reservation_is_immutable_and_globally_reserved(mobile_factory):
    reserve(mobile_factory)
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        reserve(mobile_factory)
    with mobile_factory[1]() as session:
        row = session.get(MobileOperationRow, CHALLENGE)
        assert row.source == source_for(FIRST, protocol.LEGACY)
    with pytest.raises((IntegrityError, InternalError)):
        with mobile_factory[1].begin() as session:
            session.execute(
                text("UPDATE social_messaging_mobile_operations SET context_id = :context"), dict(context="ab" * 32)
            )


@pytest.mark.parametrize("method", [protocol.LEGACY, protocol.QR])
def test_changed_proof_digest_or_method_cannot_recover(mobile_factory, method):
    prepare(mobile_factory, method)
    accept(mobile_factory, method)
    for change in (dict(authorization_digest="ab" * 32), dict(revision="ab" * 32)):
        with pytest.raises(protocol.MobileAuthorizationUnavailable):
            accept(mobile_factory, method, **change)
    kwargs = dict(
        method=method,
        session_id=AUTH_SESSION,
        subject=SUBJECT,
        context_id=LOGIN if method == protocol.LEGACY else DESKTOP,
        authorization_digest=FIRST[method]["digest"],
        revision=None if method == protocol.LEGACY else REVISION,
    )
    proof = json.loads(submission_for() if method == protocol.LEGACY else event_for())
    proof["signature" if method == protocol.LEGACY else "sig"] = "ab" * 64
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        service(mobile_factory).accept(
            CHALLENGE if method == protocol.LEGACY else PAIRING, protocol.canonical(proof), **kwargs
        )
    kwargs["method"] = protocol.QR if method == protocol.LEGACY else protocol.LEGACY
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        service(mobile_factory).accept(CHALLENGE if method == protocol.LEGACY else PAIRING, event_for(), **kwargs)


def test_exchange_fixed_vector_and_recovery_without_second_consumption(mobile_factory):
    prepare(mobile_factory, protocol.QR)
    accept(mobile_factory, protocol.QR)
    assert exchange(mobile_factory) == FIRST[protocol.QR]["exchangeIdentity"]
    mobile_factory[0].dispose()
    assert exchange(mobile_factory, now=NOW + 301) == FIRST[protocol.QR]["exchangeIdentity"]
    assert count(mobile_factory, MobileSessionHandoffRow) == 1
    assert count(mobile_factory, Session) == 1


@pytest.mark.parametrize(
    "changes",
    [dict(verifier="ab" * 32), dict(subject="ab" * 32), dict(revision="ab" * 32), dict(authorization_digest="ab" * 32)],
)
def test_exchange_substitution_rejected(mobile_factory, changes):
    prepare(mobile_factory, protocol.QR)
    accept(mobile_factory, protocol.QR)
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        exchange(mobile_factory, **changes)
    assert count(mobile_factory, MobileSessionHandoffRow) == 0


def test_expired_exchange_is_not_fresh_consumption(mobile_factory):
    prepare(mobile_factory, protocol.QR)
    accept(mobile_factory, protocol.QR)
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        exchange(mobile_factory, now=START + 300)
    assert count(mobile_factory, MobileSessionHandoffRow) == 0


@pytest.mark.parametrize(
    "table",
    ["social_messaging_device_bindings", "social_messaging_mobile_acceptances", "social_messaging_mobile_exchanges"],
)
def test_write_failure_rolls_back_entire_acceptance(mobile_factory, table):
    prepare(mobile_factory, protocol.QR)
    engine = mobile_factory[0]

    def fail(_connection, _cursor, statement, _parameters, _context, _executemany):
        if statement.startswith("INSERT INTO " + table + " "):
            raise RuntimeError("synthetic write failure")

    event.listen(engine, "before_cursor_execute", fail)
    try:
        with pytest.raises(protocol.MobileAuthorizationUnavailable):
            accept(mobile_factory, protocol.QR)
    finally:
        event.remove(engine, "before_cursor_execute", fail)
    assert count(mobile_factory, MobileAcceptanceRow) == 0
    assert count(mobile_factory, SocialMessagingDeviceBindingRow) == 0
    assert count(mobile_factory, MobileExchangeRow) == 0
    with mobile_factory[1]() as session:
        assert session.get(MobileOperationRow, PAIRING).status == "approval-claimed"
    assert accept(mobile_factory, protocol.QR)


def test_public_only_rows_and_no_validity_extension(mobile_factory):
    prepare(mobile_factory, protocol.QR)
    accept(mobile_factory, protocol.QR)
    exchange(mobile_factory)
    with mobile_factory[1]() as session:
        for model in (MobileOperationRow, MobileAcceptanceRow, MobileExchangeRow, MobileSessionHandoffRow):
            row = session.scalar(select(model))
            data = json.dumps({column.name: getattr(row, column.name) for column in model.__table__.columns})
            assert VECTORS["pairingSecret"] not in data
            assert VECTORS["exchangeVerifier"] not in data
            assert AUTH_SESSION not in data
            assert "privateKey" not in data and "CryptoKey" not in data
        receipt = session.scalar(select(MobileAcceptanceRow))
        evidence = session.scalar(select(CurrentEntitlementEvidence))
        binding = session.scalar(select(SocialMessagingDeviceBindingRow))
        assert receipt.current_full_expires_at == int(evidence.valid_until.timestamp())
        assert protocol._second(
            json.loads(protocol.parse_json(source_for())["content"])["authorization"]["bindingExpiresAt"]
        ) == int(binding.expires_at.timestamp())


def nostr_accept(mobile_factory, entry):
    claim = protocol.parse_json(entry["content"])["authorization"]
    payload = protocol.canonical(
        dict(
            claim,
            digest=entry["semanticDigest"],
            signatureFormat=SIGNATURE_FORMAT,
            signature=entry[protocol.NOSTR]["signature"],
        )
    )
    with mobile_factory[1].begin() as session:
        return SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage(
            session,
            clock=lambda: datetime.fromtimestamp(entry["now"], timezone.utc),
        ).authorize_lifecycle(payload, authenticated_subject=SUBJECT)


def prepare_entry(mobile_factory, entry, method):
    svc = service(mobile_factory, entry["now"])
    if method == protocol.LEGACY:
        svc.reserve_legacy(entry["content"], session_id=AUTH_SESSION, subject=SUBJECT, login_context=LOGIN)
    else:
        _offer, qr = offer(mobile_factory)
        svc.scan_pairing(source_for(entry), qr=qr, possession_proof=entry[method]["possessionProof"])
        svc.claim_approval(
            PAIRING,
            session_id=AUTH_SESSION,
            subject=SUBJECT,
            desktop_context=DESKTOP,
            revision=REVISION,
            authorization_digest=entry[method]["digest"],
            human_code=entry[method]["comparisonCode"],
        )
    return svc


@pytest.mark.parametrize("entry", VECTORS["entries"], ids=lambda item: item["operation"])
@pytest.mark.parametrize("method", [protocol.LEGACY, protocol.QR])
def test_real_lifecycle_consumer_all_operations_and_revoke_exchange_denial(mobile_factory, entry, method):
    if entry["operation"] in ("rotate", "revoke"):
        nostr_accept(mobile_factory, FIRST)
    if entry["operation"] == "revoke":
        nostr_accept(mobile_factory, VECTORS["entries"][1])
    if entry["operation"] == "adopt":
        candidate = protocol.parse_authorization(source_for(), subject=SUBJECT, expected_method=protocol.QR, now=NOW)
        with mobile_factory[1].begin() as session:
            SqlAlchemyTransactionBoundSocialMessagingDeviceStorage(session).apply_authorized(
                _binding(candidate),
                now=datetime.fromtimestamp(NOW, timezone.utc),
            )
    svc = prepare_entry(mobile_factory, entry, method)
    result = svc.accept(
        CHALLENGE if method == protocol.LEGACY else PAIRING,
        submission_for(entry) if method == protocol.LEGACY else event_for(entry),
        method=method,
        session_id=AUTH_SESSION,
        subject=SUBJECT,
        context_id=LOGIN if method == protocol.LEGACY else DESKTOP,
        revision=None if method == protocol.LEGACY else REVISION,
        authorization_digest=entry[method]["digest"],
    )
    assert json.loads(result)["bindingId"] == entry["bindingId"]
    allowed = method == protocol.QR and entry["operation"] != "revoke"
    assert count(mobile_factory, MobileExchangeRow) == int(allowed)
    if allowed:
        assert (
            svc.consume_exchange(
                PAIRING,
                verifier=VECTORS["exchangeVerifier"],
                subject=SUBJECT,
                revision=REVISION,
                authorization_digest=entry[method]["digest"],
            )
            == entry[method]["exchangeIdentity"]
        )
    elif method == protocol.QR:
        with pytest.raises(protocol.MobileAuthorizationUnavailable):
            svc.consume_exchange(
                PAIRING,
                verifier=VECTORS["exchangeVerifier"],
                subject=SUBJECT,
                revision=REVISION,
                authorization_digest=entry[method]["digest"],
            )
    assert count(mobile_factory, Session) == 1


def test_nostr_cannot_consume_mobile_reserved_global_request(mobile_factory):
    reserve(mobile_factory)
    with pytest.raises(DeviceBindingAuthorizationUnavailable):
        nostr_accept(mobile_factory, FIRST)
    assert count(mobile_factory, SocialMessagingDeviceBindingRow) == 0
    assert accept(mobile_factory)


def test_mobile_cannot_reserve_existing_nostr_request(mobile_factory):
    nostr_accept(mobile_factory, FIRST)
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        reserve(mobile_factory)
    assert count(mobile_factory, MobileOperationRow) == 0
    assert count(mobile_factory, MobileRequestRow) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("challenge", "22345678-1234-4234-8234-123456789abc"),
        ("loginContext", "ab" * 32),
        ("method", protocol.QR),
        ("authorizationDigest", "ab" * 32),
    ],
)
def test_legacy_submitted_challenge_and_proposal_substitution(mobile_factory, field, value):
    reserve(mobile_factory)
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        service(mobile_factory).accept(
            CHALLENGE,
            submission_for(**{field: value}),
            method=protocol.LEGACY,
            session_id=AUTH_SESSION,
            subject=SUBJECT,
            context_id=LOGIN,
            authorization_digest=FIRST[protocol.LEGACY]["digest"],
        )
    assert count(mobile_factory, MobileAcceptanceRow) == 0


def test_transcript_operation_and_proposal_substitution(mobile_factory):
    prepare(mobile_factory, protocol.QR)
    for entry in VECTORS["entries"][1:]:
        with pytest.raises(protocol.MobileAuthorizationUnavailable):
            service(mobile_factory, entry["now"]).accept(
                PAIRING,
                event_for(entry),
                method=protocol.QR,
                session_id=AUTH_SESSION,
                subject=SUBJECT,
                context_id=DESKTOP,
                revision=REVISION,
                authorization_digest=FIRST[protocol.QR]["digest"],
            )
    assert count(mobile_factory, MobileAcceptanceRow) == 0


def test_simultaneous_exchange_creates_exactly_one_handoff(mobile_factory):
    prepare(mobile_factory, protocol.QR)
    accept(mobile_factory, protocol.QR)
    gate = threading.Barrier(2)

    def worker():
        gate.wait(timeout=10)
        return exchange(mobile_factory)

    with ThreadPoolExecutor(2) as pool:
        first, second = pool.submit(worker), pool.submit(worker)
        assert first.result(timeout=20) == second.result(timeout=20)
    assert count(mobile_factory, MobileSessionHandoffRow) == 1


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE social_messaging_mobile_operations SET status='awaiting-approval'",
        "UPDATE social_messaging_mobile_operations SET source='{}'",
        "DELETE FROM social_messaging_mobile_acceptances",
        "UPDATE social_messaging_mobile_acceptances SET result_source='{}'",
        "UPDATE social_messaging_device_authorization_requests SET digest=repeat('a',64)",
    ],
)
def test_database_rejects_reopening_and_replay_mutation(mobile_factory, statement):
    prepare(mobile_factory, protocol.QR)
    accept(mobile_factory, protocol.QR)
    with pytest.raises((IntegrityError, InternalError)):
        with mobile_factory[1].begin() as session:
            session.execute(text(statement))


def test_database_refuses_accepted_state_without_receipt(mobile_factory):
    prepare(mobile_factory, protocol.QR)
    with pytest.raises((IntegrityError, InternalError)):
        with mobile_factory[1].begin() as session:
            session.execute(text("UPDATE social_messaging_mobile_operations SET status='accepted'"))
    assert count(mobile_factory, MobileAcceptanceRow) == 0


def test_migration_is_transactionally_rollback_safe(mobile_factory):
    engine = mobile_factory[0]
    root = Path(__file__).parents[2]
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.exec_driver_sql("CREATE SCHEMA mobile_rollback_test")
            connection.exec_driver_sql("SET LOCAL search_path TO mobile_rollback_test")
            connection.exec_driver_sql("CREATE TABLE users (LIKE public.users INCLUDING ALL)")
            for path in (
                root / "migrations/2026-09-04_social_messaging_device_bindings_v1.sql",
                root / "migrations/2026-09-10_social_messaging_device_binding_authorization_v1.sql",
                MIGRATION,
            ):
                connection.exec_driver_sql(path.read_text())
            assert (
                connection.scalar(
                    text("SELECT to_regclass('mobile_rollback_test.social_messaging_mobile_acceptances')")
                )
                is not None
            )
        finally:
            transaction.rollback()
        assert connection.scalar(text("SELECT to_regnamespace('mobile_rollback_test')")) is None


def test_phone_can_classify_a_lost_scan_without_grant_or_private_key(mobile_factory):
    _offer, qr = offer(mobile_factory)
    arguments = dict(
        qr=qr,
        possession_proof=FIRST[protocol.QR]["possessionProof"],
        verifier=VECTORS["exchangeVerifier"],
        revision=REVISION,
    )
    result = service(mobile_factory).recover_pairing_proposal(source_for(), **arguments)
    assert json.loads(result)["status"] == "never-accepted"
    assert count(mobile_factory, MobileRequestRow) == 0
    scan(mobile_factory, qr)
    result = service(mobile_factory).recover_pairing_proposal(source_for(), **arguments)
    assert json.loads(result)["status"] == "awaiting-approval"
    claim(mobile_factory)
    accept(mobile_factory, protocol.QR)
    result = service(mobile_factory, START + 301).recover_pairing_proposal(source_for(), **arguments)
    assert json.loads(result)["status"] == "accepted"


def test_mismatched_phone_recovery_proof_cannot_inspect_state(mobile_factory):
    _offer, qr = offer(mobile_factory)
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        service(mobile_factory).recover_pairing_proposal(
            source_for(),
            qr=qr,
            possession_proof=FIRST[protocol.QR]["possessionProof"],
            verifier="ab" * 32,
            revision=REVISION,
        )
    assert count(mobile_factory, MobileRequestRow) == 0


def test_session_creation_precision_has_no_early_acceptance_tolerance(mobile_factory):
    with mobile_factory[1].begin() as session:
        session.get(Session, AUTH_SESSION).created_at = datetime.fromtimestamp(NOW).replace(microsecond=1)
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        reserve(mobile_factory)
    assert count(mobile_factory, MobileRequestRow) == 0


def test_session_expiry_is_rechecked_after_mutation_locks(mobile_factory, monkeypatch):
    reserve(mobile_factory)
    with mobile_factory[1].begin() as session:
        session.get(Session, AUTH_SESSION).expires_at = datetime.fromtimestamp(NOW + 1)
    current = [NOW]
    original = SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage._lock_mutation

    def delayed(storage, **kwargs):
        original(storage, **kwargs)
        current[0] = NOW + 1

    monkeypatch.setattr(SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage, "_lock_mutation", delayed)
    svc = SqlAlchemyMobileAuthorizationService(mobile_factory[1], clock=lambda: current[0])
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        svc.accept(
            CHALLENGE,
            submission_for(),
            method=protocol.LEGACY,
            session_id=AUTH_SESSION,
            subject=SUBJECT,
            context_id=LOGIN,
            authorization_digest=FIRST[protocol.LEGACY]["digest"],
        )
    assert count(mobile_factory, MobileAcceptanceRow) == 0


def test_fractional_session_expiry_is_never_extended(mobile_factory):
    reserve(mobile_factory)
    with mobile_factory[1].begin() as session:
        session.get(Session, AUTH_SESSION).expires_at = datetime.fromtimestamp(NOW).replace(microsecond=500000)
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        accept(mobile_factory)


def test_separate_process_recovers_exact_acceptance_without_signer(mobile_factory):
    reserve(mobile_factory)
    accepted = accept(mobile_factory)
    program = """
import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from app.services.social_messaging_mobile_authorization_storage import SqlAlchemyMobileAuthorizationService
from tests.unit.test_social_messaging_mobile_authorization import FIRST, SUBJECT, VECTORS, submission_for
engine = create_engine(os.environ['HODLXXI_SOCIAL_BINDING_AUTHORIZATION_POSTGRES_DSN'])
with engine.connect() as connection:
    observed = connection.execute(text(
        "SELECT current_database(), current_setting('data_directory'), "
        "current_setting('port'), current_setting('listen_addresses')"
    )).one()
    assert observed == (
        'hodlxxi_social_binding_authorization_test',
        os.environ['HODLXXI_SOCIAL_BINDING_AUTHORIZATION_POSTGRES_DATA'],
        os.environ['HODLXXI_SOCIAL_BINDING_AUTHORIZATION_POSTGRES_PORT'], '',
    )
service = SqlAlchemyMobileAuthorizationService(sessionmaker(bind=engine), clock=lambda: FIRST['now'] + 301)
print(service.accept(
    VECTORS['legacyContext']['challenge'], submission_for(), method='legacy_challenge_v1',
    session_id='synthetic-authenticated-session', subject=SUBJECT,
    context_id=VECTORS['legacyContext']['loginContext'], authorization_digest=FIRST['legacy_challenge_v1']['digest'],
))
engine.dispose()
"""
    result = subprocess.run([sys.executable, "-c", program], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0
    assert result.stdout.strip() == accepted


def test_caller_cannot_import_an_old_legacy_login_envelope(mobile_factory):
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        service(mobile_factory).reserve_legacy(
            source_for(FIRST, protocol.LEGACY),
            session_id=AUTH_SESSION,
            subject=SUBJECT,
            login_context=LOGIN,
        )
    assert count(mobile_factory, MobileRequestRow) == 0


def test_server_uuid_is_reserved_before_release_and_old_signature_cannot_authorize(mobile_factory, monkeypatch):
    import app.services.social_messaging_mobile_authorization_storage as storage

    generated = "22345678-1234-4234-8234-123456789abc"
    monkeypatch.setattr(storage, "uuid4", lambda: uuid.UUID(generated))
    svc = SqlAlchemyMobileAuthorizationService(mobile_factory[1], clock=lambda: NOW)
    issued = json.loads(
        svc.reserve_legacy(FIRST["content"], session_id=AUTH_SESSION, subject=SUBJECT, login_context=LOGIN)
    )
    assert issued["challenge"] == generated
    with mobile_factory[1]() as session:
        reserved = session.get(MobileOperationRow, generated)
        assert protocol.parse_json(reserved.source)["context"]["challenge"] == generated
        assert reserved.status == "reserved"
    # Even rewriting the submitted metadata cannot turn the old Bitcoin
    # signature into proof for this newly generated challenge.
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        svc.accept(
            generated,
            submission_for(challenge=generated, authorizationDigest=issued["authorizationDigest"]),
            method=protocol.LEGACY,
            session_id=AUTH_SESSION,
            subject=SUBJECT,
            context_id=LOGIN,
            authorization_digest=issued["authorizationDigest"],
        )
    assert count(mobile_factory, MobileAcceptanceRow) == 0


def test_desktop_snapshot_uses_exact_phone_transcript_after_recreation(mobile_factory):
    offered, qr = offer(mobile_factory)
    arguments = dict(session_id=AUTH_SESSION, subject=SUBJECT, desktop_context=DESKTOP, revision=REVISION)
    assert service(mobile_factory).pairing_snapshot(PAIRING, **arguments) == offered
    scan(mobile_factory, qr)
    mobile_factory[0].dispose()
    snapshot = service(mobile_factory).pairing_snapshot(PAIRING, **arguments)
    assert snapshot.source == source_for()
    assert snapshot.acceptance is None
    assert (
        protocol.unsigned_event(
            snapshot.source,
            subject=SUBJECT,
            expected_method=protocol.QR,
            now=NOW,
        )["eventId"]
        == FIRST[protocol.QR]["eventId"]
    )
    claim(mobile_factory)
    snapshot = service(mobile_factory).pairing_snapshot(PAIRING, **arguments)
    assert snapshot.status == "approval-claimed" and snapshot.acceptance is None
    accepted = json.loads(accept(mobile_factory, protocol.QR))
    snapshot = service(mobile_factory).pairing_snapshot(PAIRING, **arguments)
    assert snapshot.status == "accepted"
    assert snapshot.acceptance.authorization_digest == accepted["authorizationDigest"]
    arguments["revision"] = "ab" * 32
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        service(mobile_factory).pairing_snapshot(PAIRING, **arguments)


def test_missing_global_replay_guard_denies_all_mobile_commands(mobile_factory):
    engine, _factory = mobile_factory
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "ALTER TABLE social_messaging_device_binding_authorization_replay DISABLE TRIGGER trg_social_nostr_global_request"
        )
    try:
        with pytest.raises(protocol.MobileAuthorizationUnavailable):
            reserve(mobile_factory)
    finally:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER TABLE social_messaging_device_binding_authorization_replay ENABLE TRIGGER trg_social_nostr_global_request"
            )
    assert count(mobile_factory, MobileRequestRow) == 0


def test_migration_backfills_existing_nostr_ownership_without_changing_result(mobile_factory):
    nostr_accept(mobile_factory, FIRST)
    tables = (
        "social_messaging_device_bindings",
        "social_messaging_device_binding_authorization_evidence",
        "social_messaging_device_binding_authorization_replay",
    )
    with mobile_factory[0].connect() as connection:
        transaction = connection.begin()
        try:
            connection.exec_driver_sql("CREATE SCHEMA mobile_backfill_test")
            connection.exec_driver_sql("SET LOCAL search_path TO mobile_backfill_test, public")
            # LIKE retains original column/check/unique definitions; input rows
            # were produced by the real Nostr adapter before this schema exists.
            for table in tables:
                connection.exec_driver_sql(f"CREATE TABLE {table} (LIKE public.{table} INCLUDING ALL)")
                connection.exec_driver_sql(f"INSERT INTO {table} SELECT * FROM public.{table}")
            before = connection.scalar(
                text("SELECT result_payload FROM social_messaging_device_binding_authorization_replay")
            )
            connection.exec_driver_sql(MIGRATION.read_text())
            owner = connection.execute(
                text("SELECT request_id, owner, digest FROM social_messaging_device_authorization_requests")
            ).one()
            assert owner == (FIRST["proposal"]["requestId"], "nostr", FIRST["semanticDigest"])
            binding_owner = connection.execute(
                text("SELECT binding_id, request_id FROM social_messaging_device_authorization_binding_owners")
            ).one()
            assert binding_owner == (FIRST["bindingId"], FIRST["proposal"]["requestId"])
            assert (
                connection.scalar(
                    text("SELECT result_payload FROM social_messaging_device_binding_authorization_replay")
                )
                == before
            )
        finally:
            transaction.rollback()
        assert connection.scalar(text("SELECT to_regnamespace('mobile_backfill_test')")) is None


def test_phone_resolves_offer_and_constructs_exact_phase_one_transcript(mobile_factory):
    offered, qr = offer(mobile_factory)
    resolved = service(mobile_factory).pairing_offer_for_scan(qr=qr)
    assert resolved == offered
    context = protocol.canonical(
        dict(
            pairingId=resolved.pairing_id,
            secretCommitment=resolved.secret_commitment,
            desktopContext=resolved.desktop_context,
            createdAt=resolved.created_at,
            expiresAt=resolved.expires_at,
            exchangeCommitment=protocol.phone_exchange_commitment(VECTORS["exchangeVerifier"]),
        )
    )
    source = protocol.create_authorization(
        FIRST[protocol.QR]["content"], context, protocol.QR, subject=resolved.subject, now=NOW
    )
    assert source == source_for()
    assert count(mobile_factory, MobileRequestRow) == 0
    assert count(mobile_factory, MobileExchangeRow) == 0
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        service(mobile_factory).pairing_offer_for_scan(qr=protocol.create_pairing_qr(PAIRING, "ab" * 32))
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        service(mobile_factory, START + 300).pairing_offer_for_scan(qr=qr)
    scan(mobile_factory, qr)
    with pytest.raises(protocol.MobileAuthorizationUnavailable):
        service(mobile_factory).pairing_offer_for_scan(qr=qr)
