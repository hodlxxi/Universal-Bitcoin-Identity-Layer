"""Receipt identity, immutable history, and transaction-bound adapter tests."""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy import inspect as inspect_database
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session as SqlAlchemySession
from sqlalchemy.schema import CreateTable
from sqlalchemy.sql.dml import Insert
from sqlalchemy.sql.selectable import Select

from app.services import social_enrollment_receipt_storage as storage
from app.services import social_enrollment_transition_authority as transition
from tests.unit.test_social_enrollment_transition_authority import _authorize

ROOT = Path(__file__).parents[2]
MIGRATION = ROOT / "migrations/2026-09-23_social_device_admission_receipt_consumption_v1.sql"
SOURCE_FIXTURE = ROOT / "tests/fixtures/social_enrollment_transition_authority_effect_identity_v1.json"
FIXTURE = json.loads((ROOT / "tests/fixtures/social_enrollment_receipt_identity_v1.json").read_bytes())
ERROR = "^social enrollment receipt storage unavailable$"


def durable_row(name: str, **changes):
    authority = _authorize(name)
    vector = FIXTURE["vectors"][name]
    prepared = transition.prepared_enrollment_effect_v1(authority)
    row = {
        "receipt_id": vector["receiptId"],
        "challenge_id": authority.challenge_id,
        "operation": "enrollment-activate",
        "decided_at": vector["decidedAt"],
        "effect_id": prepared.effect_id,
        "effect_digest": prepared.effect_digest,
        "proposed_association_id": authority.proposed_association_id,
        "authority_wire": authority.wire,
        "receipt_wire": vector["receiptWire"],
    }
    row.update(changes)
    return row


class Result:
    def __init__(self, value):
        self.value = value

    def scalar_one(self):
        return self.value

    def mappings(self):
        return self

    def one(self):
        if self.value is None:
            raise ValueError
        return self.value

    def one_or_none(self):
        return self.value


class Session:
    def __init__(self, row=None):
        self.row = row
        self.transaction = SimpleNamespace(is_active=True)
        self.nested = None
        self.is_active = True
        self.dialect = "postgresql"
        self.isolation = "read committed"
        self.guards = 5
        self.new, self.dirty, self.deleted = set(), set(), set()
        self.driver = SimpleNamespace(autocommit=False)
        self.statements = []
        self.bound_connection = SimpleNamespace(
            closed=False,
            invalidated=False,
            in_transaction=self.in_transaction,
            get_transaction=self.get_transaction,
            get_nested_transaction=self.get_nested_transaction,
            connection=SimpleNamespace(dbapi_connection=self.driver),
            execute=self.execute,
        )

    def get_transaction(self):
        return self.transaction

    def get_nested_transaction(self):
        return self.nested

    def in_transaction(self):
        return self.transaction is not None

    def get_bind(self):
        return SimpleNamespace(dialect=SimpleNamespace(name=self.dialect))

    def connection(self):
        return self.bound_connection

    def execute(self, statement, _parameters=None):
        self.statements.append(statement)
        sql = str(statement)
        if sql == "SHOW transaction_isolation":
            return Result(self.isolation)
        if "pg_trigger" in sql:
            return Result(self.guards)
        if isinstance(statement, Insert):
            if self.row is not None:
                raise ValueError("duplicate")
            self.row = statement.compile().params
        elif isinstance(statement, Select) and "WHERE" in sql and self.row is not None:
            pass
        return Result(self.row)


@pytest.mark.parametrize("name", ("initial", "rotation", "reenrollment"))
def test_receipt_identity_and_wire_fixed_vectors(name):
    authority = _authorize(name)
    vector = FIXTURE["vectors"][name]
    assert (
        storage.canonical_enrollment_receipt_id_preimage_v1_bytes(authority).decode("ascii")
        == vector["receiptIdPreimage"]
    )
    assert storage.enrollment_receipt_id_v1(authority) == vector["receiptId"]
    assert (
        hashlib.sha256(
            storage.RECEIPT_ID_DOMAIN.encode("ascii") + b"\0" + vector["receiptIdPreimage"].encode("ascii")
        ).hexdigest()
        == vector["receiptId"]
    )
    stored = storage.parse_stored_enrollment_receipt_v1(durable_row(name))
    assert stored.receipt_wire == vector["receiptWire"]
    assert stored.receipt.receipt_id == vector["receiptId"]
    assert stored.receipt.decided_at == vector["decidedAt"]
    assert stored.bearer_authority == stored.reexecution_authority == "none"


def test_receipt_identity_excludes_decided_at_and_is_stable_for_recovery():
    authority = _authorize("initial")
    first = storage.enrollment_receipt_id_v1(authority)
    assert first == storage.enrollment_receipt_id_v1(authority)
    assert "decidedAt" not in storage.canonical_enrollment_receipt_id_preimage_v1_bytes(authority).decode("ascii")
    assert "decidedAt" in FIXTURE["vectors"]["initial"]["receiptWire"]


def test_fixture_is_independent_and_does_not_rewrite_frozen_source():
    assert FIXTURE["schema"] == "hodlxxi.social_enrollment_receipt_identity_vectors.v1"
    assert FIXTURE["version"] == 1
    assert hashlib.sha256(SOURCE_FIXTURE.read_bytes()).hexdigest() == FIXTURE["sourceFixtureSha256"]


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("receipt_id", "00" * 32),
        ("challenge_id", "01" * 32),
        ("operation", "ciphertext-submit"),
        ("decided_at", 0),
        ("effect_id", "02" * 32),
        ("effect_digest", "03" * 32),
        ("proposed_association_id", "04" * 32),
        ("authority_wire", " {}"),
        ("receipt_wire", " {}"),
    ),
)
def test_stored_column_or_wire_mismatch_fails_closed(field, replacement):
    with pytest.raises(storage.SocialEnrollmentReceiptStorageUnavailable, match=ERROR):
        storage.parse_stored_enrollment_receipt_v1(durable_row("initial", **{field: replacement}))


def test_stored_receipt_is_frozen_and_repr_hides_wires():
    value = storage.parse_stored_enrollment_receipt_v1(durable_row("initial"))
    with pytest.raises(FrozenInstanceError):
        value.effect_id = "00" * 32
    assert value.receipt_wire not in repr(value)


def test_store_derives_every_identity_and_never_owns_transaction():
    authority = _authorize("initial")
    session = Session()
    store = storage.SqlAlchemyEnrollmentAdmissionReceiptStore(session)
    result = store.store_committed(
        authority,
        proposed_association_id=authority.proposed_association_id,
        decided_at=FIXTURE["vectors"]["initial"]["decidedAt"],
    )
    assert result == storage.parse_stored_enrollment_receipt_v1(durable_row("initial"))
    assert store.read_by_challenge_id(authority.challenge_id) == result
    assert not any(hasattr(store, name) for name in ("begin", "commit", "rollback", "close"))
    inserts = [item for item in session.statements if isinstance(item, Insert)]
    sql = str(inserts[0].compile(dialect=postgresql.dialect()))
    assert "ON CONFLICT" not in sql and "RETURNING" in sql


def test_store_requires_exact_typed_authority_association_and_integer_time():
    authority = _authorize("initial")
    for value, association, decided_at in (
        (object(), authority.proposed_association_id, 1),
        (authority, "00" * 32, 1),
        (authority, authority.proposed_association_id, True),
        (authority, authority.proposed_association_id, 9007199254740992),
    ):
        with pytest.raises(storage.SocialEnrollmentReceiptStorageUnavailable, match=ERROR):
            storage.SqlAlchemyEnrollmentAdmissionReceiptStore(Session()).store_committed(
                value,
                proposed_association_id=association,
                decided_at=decided_at,
            )


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("dialect", "sqlite"),
        ("is_active", False),
        ("transaction", None),
        ("isolation", "repeatable read"),
        ("guards", 4),
        ("new", {1}),
        ("dirty", {1}),
        ("deleted", {1}),
    ),
)
def test_store_requires_clean_read_committed_postgresql_transaction(field, replacement):
    session = Session()
    setattr(session, field, replacement)
    with pytest.raises(storage.SocialEnrollmentReceiptStorageUnavailable, match=ERROR):
        storage.SqlAlchemyEnrollmentAdmissionReceiptStore(session)


def test_real_sqlite_has_metadata_only_and_grants_no_authority():
    engine = create_engine("sqlite:///:memory:")
    try:
        storage.Base.metadata.create_all(engine)
        assert storage.TABLE in inspect_database(engine).get_table_names()
        with SqlAlchemySession(engine) as session, session.begin():
            with pytest.raises(storage.SocialEnrollmentReceiptStorageUnavailable, match=ERROR):
                storage.SqlAlchemyEnrollmentAdmissionReceiptStore(session)
        storage.Base.metadata.drop_all(engine)
    finally:
        engine.dispose()


def test_model_and_migration_freeze_immutable_postgresql_contract():
    table = storage.SocialEnrollmentAdmissionReceiptRow.__table__
    assert set(table.c.keys()) == {
        "receipt_id",
        "challenge_id",
        "operation",
        "decided_at",
        "effect_id",
        "effect_digest",
        "proposed_association_id",
        "authority_wire",
        "receipt_wire",
    }
    sql = MIGRATION.read_text(encoding="ascii")
    ddl = str(CreateTable(table).compile(dialect=postgresql.dialect()))
    for constraint in table.constraints:
        if constraint.name:
            assert constraint.name in sql
    assert "DEFERRABLE INITIALLY DEFERRED" in sql
    assert "BEFORE INSERT OR UPDATE OR DELETE" in sql
    assert "BEFORE TRUNCATE" in sql
    assert "CREATE OR REPLACE FUNCTION guard_social_device_challenge_v1" in sql
    assert "CURRENT_TIMESTAMP" not in ddl + sql
    assert "DROP TABLE" not in sql


def test_source_is_dormant_syntax_valid_and_has_no_ambient_authority():
    source = Path(storage.__file__).read_text(encoding="ascii")
    ast.parse(source)
    for forbidden in (
        "DATABASE_URL",
        "create_engine(",
        "datetime.now",
        "time.time",
        ".commit(",
        ".rollback(",
        ".close(",
        "requests.",
        "socket.",
    ):
        assert forbidden not in source
    assert storage.RUNTIME_ENABLED is False
    assert storage.EFFECT_EXECUTION == "not_implemented_as_atomic_owner"
    assert storage.FINAL_ADMISSION == "denied"
