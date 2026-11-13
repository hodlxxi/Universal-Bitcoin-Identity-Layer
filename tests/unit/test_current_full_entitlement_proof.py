from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

from app.models import CurrentEntitlementEvidence, User
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement_evidence import CONTRACT_VERSION, CurrentEntitlementEvidenceRecord
from app.services.current_entitlement_evidence_storage import (
    CurrentEntitlementEvidenceStorageError,
    SqlAlchemyCurrentEntitlementEvidenceRepository,
    SqlAlchemyTransactionBoundCurrentFullVerifier,
    VerifiedCurrentFullEvidenceV1,
    _subject_lock_keys,
)
from app.services.current_full_entitlement_proof import (
    CurrentFullEntitlementProofState,
    CurrentFullEntitlementProofUnavailable,
    VerifiedCurrentFullEntitlement,
    canonical_full_entitlement_proof_preimage,
    produce_verified_current_full_entitlement,
    validate_current_full_entitlement_composition,
    validate_verified_current_full_entitlement,
)

SUBJECT = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
OTHER_SUBJECT = "c6047f9441ed7d6d3045406e95c07cd85a49886dd5c2dc239e9e7c5c2f24f044"
USER_ID = "00000000-0000-4000-8000-000000000002"
NOW = datetime(2026, 9, 8, 22, 30, tzinfo=timezone.utc)


def evidence(*, subject=SUBJECT, identity=IdentityClass.FULL, **changes):
    values = dict(
        evidence_id="00000000-0000-4000-8000-000000000001",
        contract_version=CONTRACT_VERSION,
        subject_pubkey=subject,
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


def state(**changes):
    values = dict(
        user_id=USER_ID,
        user_subject=SUBJECT,
        user_is_active=True,
        evidence=evidence(),
    )
    values.update(changes)
    return CurrentFullEntitlementProofState(**values)


def orm_evidence(value=None):
    value = value or evidence()
    values = vars(value).copy()
    values["identity_class"] = value.identity_class.value
    return CurrentEntitlementEvidence(**values)


def test_exact_canonical_preimage_and_fixed_digest_vector():
    expected = (
        b'{"domain":"HODLXXI_FULL_ENTITLEMENT_V1","proof":{"evidence":{"contractVersion":'
        b'"hodlxxi.current_entitlement_evidence.v1","createdAt":"2026-09-08T22:30:00Z",'
        b'"currentFullRelationSatisfied":true,"evidenceId":"00000000-0000-4000-8000-000000000001",'
        b'"evidenceSource":"offline_verifier","evidenceVersion":"v1","identityClass":"full",'
        b'"observedAt":"2026-09-08T22:29:59Z","revokedAt":null,"sourceEvidenceSha256":'
        b'"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","subject":'
        b'"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",'
        b'"validUntil":"2026-09-08T22:35:00Z"},"schema":"hodlxxi.full_entitlement_proof.v1",'
        b'"user":{"id":"00000000-0000-4000-8000-000000000002","isActive":true,"subject":'
        b'"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"},"version":1}}'
    )
    proof = produce_verified_current_full_entitlement(state(), now=NOW)

    assert canonical_full_entitlement_proof_preimage(state()) == expected
    assert proof == VerifiedCurrentFullEntitlement(
        "hodlxxi-full-entitlement-v1-sha256:b4ac158d3851b0d0dde4f76f290e89d8da3b81aef080ff8994dd781bda945b76",
        SUBJECT,
        NOW - timedelta(seconds=1),
        NOW + timedelta(minutes=5),
    )


def test_canonical_preimage_rejects_mapping_inherited_accessor_and_extra_state():
    class InheritedState(CurrentFullEntitlementProofState):
        pass

    current = state()
    for invalid in (
        vars(current.evidence),
        SimpleNamespace(**vars(current.evidence)),
        InheritedState(current.user_id, current.user_subject, current.user_is_active, current.evidence),
        {"state": current, "extra": True},
    ):
        with pytest.raises(CurrentFullEntitlementProofUnavailable):
            canonical_full_entitlement_proof_preimage(invalid)


@pytest.mark.parametrize(
    "invalid",
    (
        state(user_is_active=False),
        state(user_subject=OTHER_SUBJECT),
        state(evidence=evidence(identity=IdentityClass.LIMITED)),
        state(evidence=evidence(revoked_at=NOW)),
        state(evidence=evidence(valid_until=NOW)),
        state(evidence=evidence(observed_at=NOW + timedelta(seconds=1), created_at=NOW + timedelta(seconds=1))),
        state(
            evidence=evidence(observed_at=NOW + timedelta(microseconds=1), created_at=NOW + timedelta(microseconds=1))
        ),
    ),
)
def test_inactive_limited_revoked_expired_future_mismatched_or_noncanonical_state_is_rejected(invalid):
    with pytest.raises(CurrentFullEntitlementProofUnavailable):
        produce_verified_current_full_entitlement(invalid, now=NOW)


def test_proof_validator_binds_exact_type_subject_and_current_validity():
    proof = produce_verified_current_full_entitlement(state(), now=NOW)
    assert validate_verified_current_full_entitlement(proof, subject=SUBJECT, now=NOW) == proof
    for invalid in (
        None,
        {"proof_id": proof.proof_id},
        proof.proof_id,
        replace(proof, proof_id="invalid"),
        replace(proof, subject=OTHER_SUBJECT),
        replace(proof, valid_from=NOW + timedelta(seconds=1)),
        replace(proof, expires_at=NOW),
    ):
        with pytest.raises(CurrentFullEntitlementProofUnavailable):
            validate_verified_current_full_entitlement(invalid, subject=SUBJECT, now=NOW)


def test_fractional_materialized_rows_compose_in_the_same_canonical_second():
    original = state()
    proof = produce_verified_current_full_entitlement(original, now=NOW)
    fractional = state(
        evidence=replace(
            original.evidence,
            observed_at=original.evidence.observed_at.replace(microsecond=412345),
            valid_until=original.evidence.valid_until.replace(microsecond=412345),
            created_at=original.evidence.created_at.replace(microsecond=987654),
        )
    )
    assert produce_verified_current_full_entitlement(fractional, now=NOW) == proof
    assert validate_current_full_entitlement_composition(proof, fractional, now=NOW) == proof
    session = TransactionSession(rows=(orm_evidence(fractional.evidence),))
    assert SqlAlchemyTransactionBoundCurrentFullVerifier(session).verify_in_transaction(SUBJECT, now=NOW) == proof


@pytest.mark.parametrize("field", ("observed_at", "valid_until", "created_at"))
def test_canonical_second_boundary_cannot_match_a_verified_proof(field):
    original = state()
    proof = produce_verified_current_full_entitlement(original, now=NOW)
    delta = timedelta(seconds=-1 if field == "observed_at" else 1)
    replacement = replace(original.evidence, **{field: getattr(original.evidence, field) + delta})
    with pytest.raises(CurrentFullEntitlementProofUnavailable):
        validate_current_full_entitlement_composition(proof, state(evidence=replacement), now=NOW)


def test_flooring_never_extends_expiry_or_activates_future_evidence():
    fractional = evidence(valid_until=NOW + timedelta(seconds=1, microseconds=999999))
    result = produce_verified_current_full_entitlement(state(evidence=fractional), now=NOW)
    assert result.expires_at == NOW + timedelta(seconds=1)
    assert result.expires_at < fractional.valid_until
    for current in (NOW + timedelta(seconds=1), NOW + timedelta(seconds=2)):
        with pytest.raises(CurrentFullEntitlementProofUnavailable):
            produce_verified_current_full_entitlement(state(evidence=fractional), now=current)
        with pytest.raises(CurrentFullEntitlementProofUnavailable):
            validate_verified_current_full_entitlement(result, subject=SUBJECT, now=current)
    with pytest.raises(CurrentFullEntitlementProofUnavailable):
        produce_verified_current_full_entitlement(
            state(evidence=evidence(valid_until=NOW - timedelta(microseconds=1))), now=NOW
        )


def test_composition_requires_verified_proof_and_entire_row_identity():
    original = state()
    proof = produce_verified_current_full_entitlement(original, now=NOW)
    for invalid in (None, proof.proof_id, original.evidence, {"proof_id": proof.proof_id}):
        with pytest.raises(CurrentFullEntitlementProofUnavailable):
            validate_current_full_entitlement_composition(invalid, original, now=NOW)
    for replacement in (
        replace(original.evidence, source_evidence_sha256="c" * 64),
        replace(original.evidence, evidence_id="00000000-0000-4000-8000-000000000099"),
    ):
        with pytest.raises(CurrentFullEntitlementProofUnavailable):
            validate_current_full_entitlement_composition(proof, state(evidence=replacement), now=NOW)


def test_real_adoption_intent_accepts_fractional_authoritative_materialization():
    from app.services.social_messaging_device_binding_authorization_intent import (
        derive_trusted_authorization_intent,
        parse_authorization_intent_proposal,
    )
    from app.services.social_messaging_mobile_authorization import canonical
    from tests.unit.test_social_messaging_device_binding_authorization import legacy_binding
    from tests.unit.test_social_messaging_device_binding_authorization_intent import Bindings, SignatureVerifier, State

    binding = legacy_binding()
    fractional = evidence(
        created_at=NOW.replace(microsecond=651234),
        observed_at=(NOW - timedelta(seconds=1)).replace(microsecond=123456),
        valid_until=(NOW + timedelta(minutes=5)).replace(microsecond=123456),
    )
    # Real materialization preserves these fractions; the real locked-reader
    # and real intent producer compose here with a no-I/O transaction double.
    verifier = SqlAlchemyTransactionBoundCurrentFullVerifier(TransactionSession(rows=(orm_evidence(fractional),)))
    intent = derive_trusted_authorization_intent(
        parse_authorization_intent_proposal(
            canonical(dict(operation="adopt", requestId="aa" * 32, bindingId=binding.binding_id))
        ),
        authenticated_subject=SUBJECT,
        state_provider=State(),
        binding_state=Bindings(binding),
        current_full=verifier,
        now=NOW,
        binding_lifetime_seconds=2592000,
        signature_verifier=SignatureVerifier(),
    )
    assert intent.claim.binding == binding
    assert intent.claim.action == "adopt"


class Result:
    def __init__(self, values=()):
        self.values = list(values)

    def scalars(self):
        return self

    def all(self):
        return self.values


_DEFAULT_ROWS = object()


class TransactionSession:
    def __init__(self, *, user=None, rows=_DEFAULT_ROWS, active=True):
        self.user = user or User(id=USER_ID, pubkey=SUBJECT, is_active=True, metadata_json={})
        self.rows = list((orm_evidence(),) if rows is _DEFAULT_ROWS else rows)
        self.active = active
        self.statements = []

    def get_bind(self):
        return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

    def in_transaction(self):
        return self.active

    def execute(self, statement):
        self.statements.append(statement)
        if len(self.statements) == 1:
            return Result()
        if len(self.statements) == 2:
            return Result((self.user,))
        return Result(self.rows)

    def commit(self):
        pytest.fail("transaction-bound verifier committed caller session")

    def rollback(self):
        pytest.fail("transaction-bound verifier rolled back caller session")

    def close(self):
        pytest.fail("transaction-bound verifier closed caller session")


class GuardedTransactionSession(TransactionSession):
    """Offline native-transaction seam; SQL still uses real model statements."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.transaction = SimpleNamespace(is_active=True)
        self.nested = None
        self.is_active = True
        self.new, self.dirty, self.deleted = (), (), ()
        self.connection_value = GuardedConnection()
        self.connection_value.on_subject_lock = self._execute_connection_lock
        self.bound_reads = []
        self.mutate = lambda: None
        self.mutate_at = None

    def get_transaction(self):
        return self.transaction

    def get_nested_transaction(self):
        return self.nested

    def connection(self):
        return self.connection_value

    def execute(self, statement, **kwargs):
        if kwargs:
            assert kwargs == {"bind_arguments": {"bind": self.connection_value}}
            self.bound_reads.append(self.connection_value)
        result = super().execute(statement)
        if len(self.statements) == self.mutate_at:
            self.mutate()
        return result

    def _execute_connection_lock(self, statement):
        result = TransactionSession.execute(self, statement)
        if len(self.statements) == self.mutate_at:
            self.mutate()
        return result

    def begin(self):
        pytest.fail("verifier began caller transaction")


class GuardedConnection:
    def __init__(self):
        self.transaction = SimpleNamespace(is_active=True)
        self.nested = None
        self.closed = False
        self.invalidated = False
        self.active = True
        self.connection = SimpleNamespace(dbapi_connection=SimpleNamespace(autocommit=False))
        self.isolation = "read committed"
        self.statements = []
        self.on_subject_lock = lambda statement: Result()

    def in_transaction(self):
        return self.active

    def get_transaction(self):
        return self.transaction

    def get_nested_transaction(self):
        return self.nested

    def execute(self, statement):
        self.statements.append(str(statement))
        if "pg_advisory_xact_lock" in str(statement):
            return self.on_subject_lock(statement)
        return SimpleNamespace(scalar_one=lambda: self.isolation)


def test_provenance_subject_lock_uses_guarded_connection():
    class RoutingSession(GuardedTransactionSession):
        def __init__(self):
            super().__init__()
            self.routed_subject_locks = []

        def execute(self, statement, **kwargs):
            if "pg_advisory_xact_lock" in str(statement):
                self.routed_subject_locks.append(statement)
            return super().execute(statement, **kwargs)

    session = RoutingSession()
    result = SqlAlchemyTransactionBoundCurrentFullVerifier(session).verify_with_evidence_in_transaction(
        SUBJECT, now=NOW
    )
    assert result.verified_entitlement == produce_verified_current_full_entitlement(state(), now=NOW)
    assert not session.routed_subject_locks, "CURRENT_FULL_REVIEW_REGRESSION_LOCK_CONNECTION"
    assert sum("pg_advisory_xact_lock" in sql for sql in session.connection_value.statements) == 1
    assert session.bound_reads == [session.connection_value, session.connection_value]


@pytest.mark.parametrize("fractional", [False, True])
def test_provenance_is_exact_frozen_and_equivalent_to_legacy(fractional):
    record = evidence()
    if fractional:
        record = replace(
            record,
            observed_at=record.observed_at.replace(microsecond=123456),
            valid_until=record.valid_until.replace(microsecond=123456),
            created_at=record.created_at.replace(microsecond=654321),
        )
    session = GuardedTransactionSession(rows=(orm_evidence(record),))
    result = SqlAlchemyTransactionBoundCurrentFullVerifier(session).verify_with_evidence_in_transaction(
        SUBJECT, now=NOW
    )
    old = SqlAlchemyTransactionBoundCurrentFullVerifier(
        TransactionSession(rows=(orm_evidence(record),))
    ).verify_in_transaction(SUBJECT, now=NOW)
    assert type(result) is VerifiedCurrentFullEvidenceV1
    assert (
        result.verified_entitlement == old == produce_verified_current_full_entitlement(state(evidence=record), now=NOW)
    )
    assert (result.evidence_id, result.evidence_version, result.source_evidence_sha256) == (
        record.evidence_id,
        record.evidence_version,
        record.source_evidence_sha256,
    )
    assert old.expires_at == record.valid_until.replace(microsecond=0)
    assert len(session.statements) == 3
    assert session.bound_reads == [session.connection_value, session.connection_value]
    assert "pg_advisory_xact_lock" in _postgresql(session.statements[0])
    assert "users" in _postgresql(session.statements[1]) and "FOR UPDATE" in _postgresql(session.statements[1])
    assert "current_entitlement_evidence" in _postgresql(session.statements[2])
    assert "FOR UPDATE" in _postgresql(session.statements[2])
    session.rows[0].evidence_version = "mutated"
    assert result.evidence_version == record.evidence_version
    with pytest.raises(FrozenInstanceError):
        result.evidence_version = "mutated"
    with pytest.raises(FrozenInstanceError):
        result.verified_entitlement.expires_at = NOW


def test_provenance_snapshots_validated_record_before_mutable_orm_changes(monkeypatch):
    import app.services.current_entitlement_evidence_storage as storage

    row = orm_evidence()
    producer = storage.produce_verified_current_full_entitlement

    def produce_and_mutate(current, *, now):
        proof = producer(current, now=now)
        row.evidence_id = "changed"
        row.evidence_version = "changed"
        row.source_evidence_sha256 = "changed"
        return proof

    monkeypatch.setattr(storage, "produce_verified_current_full_entitlement", produce_and_mutate)
    result = storage.SqlAlchemyTransactionBoundCurrentFullVerifier(
        GuardedTransactionSession(rows=(row,))
    ).verify_with_evidence_in_transaction(SUBJECT, now=NOW)
    assert result == VerifiedCurrentFullEvidenceV1(producer(state(), now=NOW), evidence().evidence_id, "v1", "b" * 64)


@pytest.mark.parametrize("method", ["verify_in_transaction", "verify_with_evidence_in_transaction"])
@pytest.mark.parametrize("negative", ["limited", "revoked", "expired", "future", "tied", "malformed", "mismatched"])
def test_shared_evaluator_never_falls_back_to_older_full(method, negative):
    latest = orm_evidence(evidence(observed_at=NOW, created_at=NOW))
    older = orm_evidence()
    if negative == "limited":
        latest.identity_class, latest.current_full_relation_satisfied = "limited", False
    elif negative == "revoked":
        latest.revoked_at = NOW
    elif negative == "expired":
        latest.valid_until = NOW
    elif negative == "future":
        latest.observed_at = latest.created_at = NOW + timedelta(seconds=1)
    elif negative == "tied":
        latest.observed_at = older.observed_at
    elif negative == "malformed":
        latest.source_evidence_sha256 = "invalid"
    else:
        latest.subject_pubkey = OTHER_SUBJECT
    session = GuardedTransactionSession(rows=(latest, older))
    with pytest.raises(
        CurrentEntitlementEvidenceStorageError, match="^current entitlement evidence storage unavailable$"
    ):
        getattr(SqlAlchemyTransactionBoundCurrentFullVerifier(session), method)(SUBJECT, now=NOW)


@pytest.mark.parametrize("read", [1, 2, 3])
@pytest.mark.parametrize(
    "change",
    [
        "session_root",
        "session_inactive",
        "session_savepoint",
        "inactive_savepoint",
        "connection",
        "database_root",
        "database_inactive",
        "database_savepoint",
        "physical_connection",
        "closed",
        "invalidated",
        "autocommit",
        "isolation",
    ],
)
def test_provenance_rejects_transaction_changes_during_each_locked_read(read, change):
    session = GuardedTransactionSession()
    connection = session.connection_value
    session.mutate_at = read

    def mutate():
        if change == "session_root":
            session.transaction = SimpleNamespace(is_active=True)
        elif change == "session_inactive":
            session.transaction.is_active = False
        elif change == "session_savepoint":
            session.nested = SimpleNamespace(is_active=True)
        elif change == "inactive_savepoint":
            session.nested.is_active = False
        elif change == "connection":
            session.connection_value = GuardedConnection()
        elif change == "database_root":
            connection.transaction = SimpleNamespace(is_active=True)
        elif change == "database_inactive":
            connection.transaction.is_active = False
        elif change == "database_savepoint":
            connection.nested = SimpleNamespace(is_active=True)
        elif change == "physical_connection":
            connection.connection.dbapi_connection = SimpleNamespace(autocommit=False)
        elif change == "autocommit":
            connection.connection.dbapi_connection.autocommit = True
        elif change == "isolation":
            connection.isolation = "repeatable read"
        else:
            setattr(connection, change, True)

    if change == "inactive_savepoint":
        session.nested = SimpleNamespace(is_active=True)
    session.mutate = mutate
    with pytest.raises(CurrentEntitlementEvidenceStorageError):
        SqlAlchemyTransactionBoundCurrentFullVerifier(session).verify_with_evidence_in_transaction(SUBJECT, now=NOW)
    assert len(session.statements) == read


@pytest.mark.parametrize("invalid", ["no_root", "inactive", "dirty", "autocommit", "isolation"])
def test_provenance_rejects_invalid_initial_transaction_without_authority_reads(invalid):
    session = GuardedTransactionSession()
    if invalid == "no_root":
        session.transaction = None
    elif invalid == "inactive":
        session.active = False
    elif invalid == "dirty":
        session.dirty = (object(),)
    elif invalid == "autocommit":
        session.connection_value.connection.dbapi_connection.autocommit = True
    else:
        session.connection_value.isolation = "serializable"
    with pytest.raises(CurrentEntitlementEvidenceStorageError):
        SqlAlchemyTransactionBoundCurrentFullVerifier(session).verify_with_evidence_in_transaction(SUBJECT, now=NOW)
    assert not session.statements


@pytest.mark.parametrize("method", ["verify_in_transaction", "verify_with_evidence_in_transaction"])
@pytest.mark.parametrize("user_state", ["missing", "duplicate", "inactive", "mismatched"])
def test_shared_evaluator_rejects_invalid_users(method, user_state):
    class InvalidUserSession(GuardedTransactionSession):
        def execute(self, statement, **kwargs):
            result = super().execute(statement, **kwargs)
            if len(self.statements) == 2:
                if user_state == "missing":
                    return Result()
                if user_state == "duplicate":
                    return Result((self.user, self.user))
            return result

    session = InvalidUserSession()
    if user_state == "inactive":
        session.user.is_active = False
    elif user_state == "mismatched":
        session.user.pubkey = OTHER_SUBJECT
    with pytest.raises(CurrentEntitlementEvidenceStorageError):
        getattr(SqlAlchemyTransactionBoundCurrentFullVerifier(session), method)(SUBJECT, now=NOW)
    assert len(session.statements) == 2


@pytest.mark.parametrize("method", ["verify_in_transaction", "verify_with_evidence_in_transaction"])
@pytest.mark.parametrize("boundary", ["expiry", "future_fraction", "floored_expiry", "fractional_now", "missing"])
def test_shared_evaluator_preserves_exact_time_boundaries(method, boundary):
    record = evidence()
    clock = NOW
    if boundary == "expiry":
        record = replace(record, valid_until=NOW)
    elif boundary == "future_fraction":
        future = NOW + timedelta(microseconds=1)
        record = replace(record, observed_at=future, created_at=future)
    elif boundary == "floored_expiry":
        record = replace(record, valid_until=NOW + timedelta(microseconds=999999))
    elif boundary == "fractional_now":
        clock += timedelta(microseconds=1)
    session = GuardedTransactionSession(rows=() if boundary == "missing" else (orm_evidence(record),))
    with pytest.raises(CurrentEntitlementEvidenceStorageError):
        getattr(SqlAlchemyTransactionBoundCurrentFullVerifier(session), method)(SUBJECT, now=clock)


def test_provenance_preserves_existing_active_savepoints_and_caller_ownership():
    session = GuardedTransactionSession()
    session.nested = SimpleNamespace(is_active=True)
    session.connection_value.nested = SimpleNamespace(is_active=True)
    root, nested = session.transaction, session.nested
    database_root, database_nested = session.connection_value.transaction, session.connection_value.nested
    SqlAlchemyTransactionBoundCurrentFullVerifier(session).verify_with_evidence_in_transaction(SUBJECT, now=NOW)
    assert session.transaction is root and root.is_active
    assert session.nested is nested and nested.is_active
    assert session.connection_value.transaction is database_root and database_root.is_active
    assert session.connection_value.nested is database_nested and database_nested.is_active


def _postgresql(statement):
    return str(statement.compile(dialect=postgresql.dialect()))


def test_transaction_bound_reader_requires_active_postgresql_transaction_and_locks_authority_rows():
    session = TransactionSession()
    result = SqlAlchemyTransactionBoundCurrentFullVerifier(session).verify_in_transaction(SUBJECT, now=NOW)

    assert result == produce_verified_current_full_entitlement(state(), now=NOW)
    assert len(session.statements) == 3
    assert "pg_advisory_xact_lock" in _postgresql(session.statements[0])
    assert "FOR UPDATE" in _postgresql(session.statements[1])
    assert "users" in _postgresql(session.statements[1])
    assert "FOR UPDATE" in _postgresql(session.statements[2])
    assert "current_entitlement_evidence" in _postgresql(session.statements[2])

    for invalid in (
        TransactionSession(active=False),
        TransactionSession(user=User(id=USER_ID, pubkey=SUBJECT, is_active=False)),
        TransactionSession(rows=()),
    ):
        with pytest.raises(CurrentEntitlementEvidenceStorageError):
            SqlAlchemyTransactionBoundCurrentFullVerifier(invalid).verify_in_transaction(SUBJECT, now=NOW)


def test_transaction_bound_reader_rejects_replaced_and_ambiguous_latest_evidence():
    replacement = evidence(
        identity=IdentityClass.LIMITED,
        evidence_id="00000000-0000-4000-8000-000000000003",
        observed_at=NOW,
        created_at=NOW,
        valid_until=NOW + timedelta(minutes=5),
    )
    with pytest.raises(CurrentEntitlementEvidenceStorageError):
        SqlAlchemyTransactionBoundCurrentFullVerifier(
            TransactionSession(rows=(orm_evidence(replacement), orm_evidence()))
        ).verify_in_transaction(SUBJECT, now=NOW)

    tied = evidence(evidence_id="00000000-0000-4000-8000-000000000004")
    with pytest.raises(CurrentEntitlementEvidenceStorageError):
        SqlAlchemyTransactionBoundCurrentFullVerifier(
            TransactionSession(rows=(orm_evidence(tied), orm_evidence()))
        ).verify_in_transaction(SUBJECT, now=NOW)


class WriterSession:
    def __init__(self, events):
        self.events = events

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.events.append(("close",))

    def get_bind(self):
        return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

    def execute(self, statement):
        parameters = tuple(statement.compile().params.values())
        self.events.append(("lock", parameters))
        return Result()

    def add(self, _row):
        self.events.append(("add",))

    def add_all(self, rows):
        self.events.append(("add_all", len(rows)))

    def commit(self):
        self.events.append(("commit",))

    def rollback(self):
        self.events.append(("rollback",))

    def close(self):
        self.events.append(("close",))


def test_all_evidence_writer_paths_take_the_same_subject_lock_in_deterministic_order():
    events = []
    repository = SqlAlchemyCurrentEntitlementEvidenceRepository(lambda: WriterSession(events))
    repository.append(evidence())
    assert events[:2] == [("lock", _subject_lock_keys(SUBJECT)), ("add",)]

    events.clear()
    first = evidence(subject=OTHER_SUBJECT, evidence_id="00000000-0000-4000-8000-000000000010")
    second = evidence(subject=SUBJECT, evidence_id="00000000-0000-4000-8000-000000000011")
    repository.append_pair((first, second))
    assert [event for event in events if event[0] == "lock"] == [
        ("lock", _subject_lock_keys(subject)) for subject in sorted((SUBJECT, OTHER_SUBJECT))
    ]


def test_fractional_precision_is_rejected_outside_trusted_evidence_producer():
    original = state()
    proof = produce_verified_current_full_entitlement(original, now=NOW)
    for field in ("valid_from", "expires_at"):
        fractional = replace(proof, **{field: getattr(proof, field) + timedelta(microseconds=1)})
        with pytest.raises(CurrentFullEntitlementProofUnavailable):
            validate_verified_current_full_entitlement(fractional, subject=SUBJECT, now=NOW)
        with pytest.raises(CurrentFullEntitlementProofUnavailable):
            validate_current_full_entitlement_composition(fractional, original, now=NOW)
    fractional_now = NOW + timedelta(microseconds=1)
    with pytest.raises(CurrentFullEntitlementProofUnavailable):
        produce_verified_current_full_entitlement(original, now=fractional_now)
    with pytest.raises(CurrentFullEntitlementProofUnavailable):
        validate_verified_current_full_entitlement(proof, subject=SUBJECT, now=fractional_now)
    with pytest.raises(CurrentFullEntitlementProofUnavailable):
        validate_current_full_entitlement_composition(proof, original, now=fractional_now)
