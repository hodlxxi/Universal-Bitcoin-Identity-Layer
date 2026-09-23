"""Offline storage boundary and cross-contract vectors; no database fallback."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import re
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy import inspect as inspect_database
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session as SqlAlchemySession
from sqlalchemy.schema import CreateTable
from sqlalchemy.sql.dml import Insert

from app.services import social_device_challenge_store as storage
from app.services import social_device_verification_statement as verifier
from app.services import social_messaging_device_admission_contract as contract

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = json.loads((ROOT / "tests/fixtures/social_device_admission_v1.json").read_bytes())
VECTORS = FIXTURE["vectors"]
DENIED = storage.SocialDeviceChallengeStorageUnavailable
ERROR = "^social device challenge storage unavailable$"
MIGRATION = ROOT / "migrations/2026-09-21_social_device_challenge_store_v1.sql"


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def arguments(name="ciphertextSubmit"):
    v = VECTORS[name]
    return {
        key: v[wire]
        for key, wire in (
            ("context_wire", "contextWire"),
            ("challenge_wire", "challengeWire"),
            ("actual_request_wire", "actualRequestWire"),
            ("routing_request_wire", "routingRequestWire"),
        )
    }


def persisted(name="ciphertextSubmit", **changes):
    v = VECTORS[name]
    row = dict(
        challenge_id=json.loads(v["contextWire"])["challengeId"],
        context_wire=v["contextWire"],
        challenge_wire=v["challengeWire"],
        routing_request_wire=v["routingRequestWire"],
        state="issued",
    )
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
            raise ValueError("synthetic missing row")
        return self.value


class Session:
    """Only exercises SQL construction/lifecycle; PostgreSQL tests prove locks."""

    def __init__(self, row=None):
        self.row = row
        self.transaction = SimpleNamespace(is_active=True)
        self.nested = None
        self.is_active = True
        self.dialect = "postgresql"
        self.isolation = "read committed"
        self.guards = 2
        self.new, self.dirty, self.deleted = set(), set(), set()
        self.statements = []
        self.failure = None
        self.driver = SimpleNamespace(autocommit=False)
        self.bound_connection = SimpleNamespace(
            closed=False,
            invalidated=False,
            in_transaction=self.in_transaction,
            get_transaction=self.get_transaction,
            get_nested_transaction=self.get_nested_transaction,
            connection=SimpleNamespace(dbapi_connection=self.driver),
            execute=self.execute,
        )

    def connection(self):
        return self.bound_connection

    def get_transaction(self):
        return self.transaction

    def get_nested_transaction(self):
        return self.nested

    def in_transaction(self):
        return self.transaction is not None

    def get_bind(self):
        return SimpleNamespace(dialect=SimpleNamespace(name=self.dialect))

    def execute(self, statement):
        self.statements.append(statement)
        sql = str(statement)
        if sql == "SHOW transaction_isolation":
            return Result(self.isolation)
        if "pg_trigger" in sql:
            return Result(self.guards)
        if self.failure:
            raise self.failure
        if isinstance(statement, Insert):
            if self.row is not None:
                raise IntegrityError("synthetic", {}, Exception("private diagnostic"))
            self.row = statement.compile().params
        return Result(self.row)


@pytest.mark.parametrize("name", VECTORS)
def test_create_read_exact_bytes_and_real_next_consumers(name):
    session = Session()
    store = storage.SqlAlchemyDeviceChallengeStore(session)
    created = store.create_issued(**arguments(name))
    v = VECTORS[name]
    for result in (
        created,
        store.read(created.context.challenge_id),
        store.read_for_update(created.context.challenge_id),
    ):
        assert result == created
        assert result.context == contract.parse_verification_context_v1(v["contextWire"])
        assert result.context.wire.encode("ascii") == v["contextWire"].encode("ascii")
        assert result.challenge_wire.encode("ascii") == v["challengeWire"].encode("ascii")
        assert result.actual_request_wire == v["actualRequestWire"]
        assert result.routing_request_wire == v["routingRequestWire"]
        assert result.issued_at == json.loads(v["challengeWire"])["issuedAt"]
        assert result.expires_at == json.loads(v["challengeWire"])["expiresAt"]
        assert result.state == "issued"
        input_wire = contract.canonical_verification_input_v1_bytes(
            context=result.context.wire,
            challenge=result.challenge_wire,
            proof=v["proofWire"],
            approval_event=v["approvalEventWire"],
            actual_request=result.actual_request_wire,
            routing_request=result.routing_request_wire,
        ).decode("ascii")
        assert input_wire == v["inputWire"]
        assert contract.parse_verification_input_v1(input_wire).operation == result.operation
        config = FIXTURE["configuration"]
        authenticated = verifier.verify_social_device_verification_statement_v1(
            v["compactJws"],
            config=verifier.SocialDeviceVerificationStatementConfig(
                enabled=True,
                issuer=config["issuer"],
                audience=config["audience"],
                client_id=config["clientId"],
                service_principal=config["servicePrincipal"],
                trusted_jwks=(FIXTURE["publicVerificationMaterial"]["jwk"],),
            ),
            expected_context_wire=result.context.wire,
            expected_input_wire=input_wire,
            now=v["now"],
            challenge_expires_at=result.expires_at,
            session_expires_at=v["sessionExpiresAt"],
            approver_session_expires_at=v["approverSessionExpiresAt"],
        )
        assert authenticated.challenge_id == result.context.challenge_id
    assert session.row == persisted(name)


def test_model_stores_only_required_wires_state_and_one_indexed_duplicate():
    table = storage.SocialDeviceAdmissionChallengeRow.__table__
    assert set(table.c.keys()) == {"challenge_id", "context_wire", "challenge_wire", "routing_request_wire", "state"}
    assert [c.name for c in table.primary_key] == ["challenge_id"]
    assert not table.indexes
    assert not table.foreign_keys
    ddl = str(CreateTable(table).compile(dialect=postgresql.dialect()))
    sql = MIGRATION.read_text()
    for constraint in table.constraints:
        if constraint.name:
            assert constraint.name in sql
    assert "PRIMARY KEY (challenge_id)" in ddl
    assert "CURRENT_TIMESTAMP" not in ddl + sql
    assert "ON CONFLICT" not in sql


def test_shared_sqlite_metadata_create_and_drop_after_challenge_model_import():
    engine = create_engine("sqlite:///:memory:")
    try:
        storage.Base.metadata.create_all(engine)
        assert {
            "users",
            "oauth_tokens",
            "oauth_codes",
            "agent_events",
            storage.TABLE,
        } <= set(inspect_database(engine).get_table_names())
        storage.Base.metadata.drop_all(engine)
        assert inspect_database(engine).get_table_names() == []
    finally:
        engine.dispose()


def test_real_sqlite_session_still_cannot_construct_authoritative_challenge_store():
    engine = create_engine("sqlite:///:memory:")
    try:
        with SqlAlchemySession(engine) as session, session.begin():
            with pytest.raises(DENIED, match=ERROR):
                storage.SqlAlchemyDeviceChallengeStore(session)
    finally:
        engine.dispose()


def test_postgresql_constraint_compilation_matches_unchanged_migration():
    assert hashlib.sha256(MIGRATION.read_bytes()).hexdigest() == (
        "2379d18b81e468ff9044ca2209db9f38e1b23cccac70520bfed24b4765d42ef2"
    )
    migration = re.sub(r"\s+", "", MIGRATION.read_text())
    table = storage.SocialDeviceAdmissionChallengeRow.__table__
    for constraint in table.constraints:
        if constraint.name:
            expression = str(constraint.sqltext.compile(dialect=postgresql.dialect()))
            expected = re.sub(r"\s+", "", f"CONSTRAINT {constraint.name} CHECK ({expression})")
            assert expected in migration
    sqlite_ddl = str(CreateTable(table).compile(dialect=sqlite.dialect()))
    assert not any(token in sqlite_ddl for token in ("!~", "::json", "octet_length"))


@pytest.mark.parametrize("name", VECTORS)
def test_immutable_record_and_nullability(name):
    result = storage.parse_stored_device_challenge_v1(persisted(name))
    with pytest.raises(FrozenInstanceError):
        result.challenge_wire = "replacement"
    with pytest.raises(FrozenInstanceError):
        result.context.authority_epoch = 9
    assert result.context.wire not in repr(result)
    if name == "enrollmentV2":
        assert result.operation == "enrollment-activate"
        assert result.actual_request_wire is result.routing_request_wire is None
        assert result.context.approver_session_binding is not None
        assert result.context.approver_full_proof_id is not None
    else:
        assert result.actual_request_wire is not None
        assert result.context.approver_session_binding is result.context.approver_full_proof_id is None
        assert (result.routing_request_wire is None) == (name == "recipientSelfRead")


@pytest.mark.parametrize(
    "name,field,value",
    [
        ("enrollmentV2", "actual_request_wire", VECTORS["ciphertextSubmit"]["actualRequestWire"]),
        ("enrollmentV2", "routing_request_wire", VECTORS["ciphertextSubmit"]["routingRequestWire"]),
        ("ciphertextSubmit", "actual_request_wire", None),
        ("ciphertextSubmit", "actual_request_wire", VECTORS["recipientSelfRead"]["actualRequestWire"]),
        ("ciphertextSubmit", "actual_request_wire", b"bytes"),
        ("ciphertextSubmit", "routing_request_wire", None),
        ("recipientSelfRead", "routing_request_wire", VECTORS["ciphertextSubmit"]["routingRequestWire"]),
    ],
)
def test_wrong_request_and_routing_nullability_denied_before_insert(name, field, value):
    session = Session()
    args = arguments(name)
    args[field] = value
    with pytest.raises(DENIED, match=ERROR):
        storage.SqlAlchemyDeviceChallengeStore(session).create_issued(**args)
    assert session.row is None


@pytest.mark.parametrize("field", ("context_wire", "challenge_wire", "routing_request_wire"))
@pytest.mark.parametrize("mutation", ("whitespace", "duplicate", "non_ascii", "bytes", "unknown", "numeric"))
def test_noncanonical_persisted_wires_fail_closed(field, mutation):
    row = persisted()
    wire = row[field]
    value = json.loads(wire)
    if mutation == "whitespace":
        row[field] = " " + wire
    elif mutation == "duplicate":
        row[field] = '{"version":1,' + wire[1:]
    elif mutation == "non_ascii":
        row[field] = wire + "é"
    elif mutation == "bytes":
        row[field] = wire.encode("ascii")
    elif mutation == "unknown":
        row[field] = canonical({**value, "unknown": None})
    else:
        row[field] = wire.replace('"version":1', '"version":1.0')
    with pytest.raises(DENIED, match=ERROR):
        storage.parse_stored_device_challenge_v1(row)


@pytest.mark.parametrize(
    "field,value",
    [
        ("subject", "01" * 32),
        ("deviceId", "02" * 32),
        ("sessionBinding", "03" * 32),
        ("bindingId", "04" * 32),
        ("bindingVersion", 1024),
        ("authorityEpoch", 0),
        ("authorityEpoch", True),
        ("challengeId", "05" * 32),
        ("associationVersion", 0),
        ("fullProofId", "06" * 32),
        ("approverSessionBinding", "07" * 32),
    ],
)
def test_wrong_subject_device_session_binding_epoch_and_context_metadata_denied(field, value):
    row = persisted()
    context = json.loads(row["context_wire"])
    assert context[field] != value
    context[field] = value
    row["context_wire"] = canonical(context)
    with pytest.raises(DENIED, match=ERROR):
        storage.parse_stored_device_challenge_v1(row)


@pytest.mark.parametrize("field", ("ed25519PublicKey", "x25519PublicKeyCommitment", "subject", "bindingId"))
def test_enrollment_key_and_context_binding_mismatch(field):
    row = persisted("enrollmentV2")
    context = json.loads(row["context_wire"])
    context[field] = context[field][:-2] + "aa"
    row["context_wire"] = canonical(context)
    with pytest.raises(DENIED, match=ERROR):
        storage.parse_stored_device_challenge_v1(row)


@pytest.mark.parametrize(
    "changes",
    [
        {"challenge_id": "ff" * 32},
        {"state": "verified"},
        {"state": None},
        {"subject": "ff" * 32},
        {"device_id": "ff" * 32},
        {"session_binding": "ff" * 32},
        {"binding_id": "ff" * 32},
        {"authority_epoch": 2},
        {"issued_at": 1},
    ],
)
def test_indexed_metadata_mismatch_or_unrecognized_denormalized_metadata_denied(changes):
    with pytest.raises(DENIED, match=ERROR):
        storage.parse_stored_device_challenge_v1(persisted(**changes))


@pytest.mark.parametrize("state", contract.CHALLENGE_STATES)
def test_pure_decoder_knows_frozen_state_vocabulary_without_transition_api(state):
    assert storage.parse_stored_device_challenge_v1(persisted(state=state)).state == state


@pytest.mark.parametrize("name", VECTORS)
def test_exact_millisecond_deadlines_and_expiry_does_not_mutate_evidence(name):
    row = persisted(name)
    challenge = json.loads(row["challenge_wire"])
    challenge["issuedAt"] += 123
    challenge["expiresAt"] += 123
    row["challenge_wire"] = canonical(challenge)
    record = storage.parse_stored_device_challenge_v1(row)
    for now, disposition in (
        (record.issued_at - 1, "not_yet_valid"),
        (record.issued_at, "current"),
        (record.expires_at - 1, "current"),
        (record.expires_at, "expired"),
        (record.expires_at + 1, "expired"),
    ):
        assert record.inspect_deadline(now=now).disposition == disposition
    assert record.issued_at == challenge["issuedAt"]
    assert record.expires_at == challenge["expiresAt"]
    assert storage.parse_stored_device_challenge_v1(row) == record
    assert record.state == "issued"
    with pytest.raises(DENIED, match=ERROR):
        record.inspect_deadline(now=True)


@pytest.mark.parametrize(
    "field,value",
    [
        ("dialect", "sqlite"),
        ("is_active", False),
        ("transaction", None),
        ("isolation", "repeatable read"),
        ("guards", 1),
        ("guards", 0),
        ("new", {1}),
        ("dirty", {1}),
        ("deleted", {1}),
    ],
)
def test_requires_active_clean_postgresql_transaction_and_migration_guards(field, value):
    session = Session()
    setattr(session, field, value)
    with pytest.raises(DENIED, match=ERROR):
        storage.SqlAlchemyDeviceChallengeStore(session)


@pytest.mark.parametrize("change", ("ended", "replaced", "savepoint", "failed", "guards_removed", "dirty"))
def test_transaction_identity_and_health_rechecked_on_every_operation(change):
    session = Session(persisted())
    store = storage.SqlAlchemyDeviceChallengeStore(session)
    if change == "ended":
        session.transaction.is_active = False
    elif change == "replaced":
        session.transaction = SimpleNamespace(is_active=True)
    elif change == "savepoint":
        session.nested = object()
    elif change == "failed":
        session.is_active = False
    elif change == "guards_removed":
        session.guards = 0
    else:
        session.dirty.add(1)
    with pytest.raises(DENIED, match=ERROR):
        store.read_for_update(session.row["challenge_id"])


@pytest.mark.parametrize("change", ("autocommit", "closed", "invalidated", "replaced", "physical_savepoint"))
def test_physical_connection_is_pinned_active_and_never_autocommit(change):
    session = Session(persisted())
    store = storage.SqlAlchemyDeviceChallengeStore(session)
    if change == "autocommit":
        session.driver.autocommit = True
    elif change == "replaced":
        session.bound_connection = Session().bound_connection
    elif change == "physical_savepoint":
        session.bound_connection.get_nested_transaction = lambda: SimpleNamespace(is_active=True)
    else:
        setattr(session.bound_connection, change, True)
    with pytest.raises(DENIED, match=ERROR):
        store.read_for_update(session.row["challenge_id"])


def test_insert_never_upserts_and_duplicate_never_becomes_success():
    session = Session()
    store = storage.SqlAlchemyDeviceChallengeStore(session)
    result = store.create_issued(**arguments())
    original = dict(session.row)
    inserts = [s for s in session.statements if isinstance(s, Insert)]
    sql = str(inserts[0].compile(dialect=postgresql.dialect()))
    assert "INSERT INTO" in sql and "RETURNING" in sql and "ON CONFLICT" not in sql
    with pytest.raises(DENIED, match=ERROR) as failure:
        store.create_issued(**arguments())
    assert failure.value.__context__ is failure.value.__cause__ is None
    assert session.row == original
    with pytest.raises(DENIED, match=ERROR):
        store.read(result.context.challenge_id)


def test_create_rejects_even_canonical_evidence_rewritten_by_database():
    class RewritingSession(Session):
        def execute(self, statement):
            result = super().execute(statement)
            if isinstance(statement, Insert):
                context = json.loads(self.row["context_wire"])
                context["authorityEpoch"] += 1
                self.row["context_wire"] = canonical(context)
            return result

    with pytest.raises(DENIED, match=ERROR):
        storage.SqlAlchemyDeviceChallengeStore(RewritingSession()).create_issued(**arguments())


@pytest.mark.parametrize("lock", (False, True))
def test_unknown_challenge_and_sql_failure_fail_closed(lock):
    session = Session()
    store = storage.SqlAlchemyDeviceChallengeStore(session)
    read = store.read_for_update if lock else store.read
    with pytest.raises(DENIED, match=ERROR):
        read("ff" * 32)
    session = Session(persisted())
    store = storage.SqlAlchemyDeviceChallengeStore(session)
    session.failure = OperationalError("private statement", {}, Exception("private data"))
    with pytest.raises(DENIED, match=ERROR) as failure:
        (store.read_for_update if lock else store.read)(session.row["challenge_id"])
    assert failure.value.__context__ is failure.value.__cause__ is None


def test_read_for_update_selects_one_authoritative_key_without_skip_or_second_transaction():
    session = Session(persisted())
    store = storage.SqlAlchemyDeviceChallengeStore(session)
    result = store.read_for_update(session.row["challenge_id"])
    statement = session.statements[-1]
    sql = str(statement.compile(dialect=postgresql.dialect()))
    assert "FOR UPDATE OF social_device_admission_challenges" in sql
    assert "WHERE social_device_admission_challenges.challenge_id =" in sql
    assert "SKIP LOCKED" not in sql
    assert statement.compile().params == {"challenge_id_1": result.context.challenge_id}
    assert statement.get_execution_options()["autoflush"] is False
    assert not any(hasattr(store, name) for name in ("begin", "commit", "rollback", "close", "consume", "update"))
    store.read(result.context.challenge_id)
    assert "FOR UPDATE" not in str(session.statements[-1].compile(dialect=postgresql.dialect()))


def test_migration_separates_immutable_evidence_and_reserved_consumed_state():
    sql = MIGRATION.read_text()
    assert "CREATE TABLE social_device_admission_challenges" in sql
    assert "BEFORE INSERT OR UPDATE OR DELETE" in sql
    assert "BEFORE TRUNCATE" in sql
    assert "NEW.state <> 'issued'" in sql
    assert "NEW.state NOT IN ('expired','invalidated','cancelled')" in sql
    assert "OLD.state <> 'issued'" in sql
    assert "IS DISTINCT FROM" in sql
    assert "DROP TABLE" not in sql


def test_no_io_at_import_no_runtime_dependency_no_admission_api():
    source = inspect.getsource(storage)
    tree = ast.parse(source)
    modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | {
        a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names
    }
    assert modules == {
        "__future__",
        "dataclasses",
        "typing",
        "sqlalchemy",
        "sqlalchemy.engine",
        "sqlalchemy.ext.compiler",
        "sqlalchemy.orm",
        "sqlalchemy.sql.expression",
        "app.models",
        "app.services",
        "app.services.social_messaging_device_proof_profile",
    }
    with (
        patch("socket.socket", side_effect=AssertionError("I/O forbidden")),
        patch("sqlalchemy.create_engine", side_effect=AssertionError("engine forbidden")),
    ):
        import importlib.util

        # Test a fresh module execution without re-registering the ORM class.
        # Base metadata is deliberately isolated for this import-only check.
        from sqlalchemy.orm import declarative_base

        with patch("app.models.Base", declarative_base()):
            spec = importlib.util.spec_from_file_location("app.services._challenge_import_test", storage.__file__)
            module = importlib.util.module_from_spec(spec)
            import sys

            with patch.dict(sys.modules, {spec.name: module}):
                spec.loader.exec_module(module)
        assert module.RUNTIME_ENABLED is False
    consumers = []
    for path in ROOT.joinpath("app").rglob("*.py"):
        if path != Path(storage.__file__) and "social_device_challenge_store" in path.read_text():
            consumers.append(path.relative_to(ROOT).as_posix())
    assert sorted(consumers) == [
        "app/services/social_enrollment_receipt_storage.py",
        "app/services/social_enrollment_transition_authority_storage.py",
    ]
    assert storage.FINAL_ADMISSION == "denied"
    assert storage.CHALLENGE_CONSUMPTION == "transaction_bound_enrollment_only"
    assert storage.OPERATION_EFFECT == "not_implemented"
    assert storage.RECEIPT_ISSUANCE == "separate_transaction_bound_primitive"
    assert not any(name in source for name in ("authorized=True", "verified=True", "admitted=True"))
    methods = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert "record_enrollment_consumed" in methods
    assert not methods & {"consume", "admit", "issue_receipt", "record_consumed_challenge_transition"}


def test_all_six_fixture_hashes_unchanged():
    expected = {
        "social_device_admission_v1.json": "09722ca9ab230a7bbc73b2228dfed5e80cdd2c2bb44a32e8571bdcf246ca4324",
        "social_messaging_device_proof_profile_v1.json": "f616cee3db22d906d309953ae74b5626109a643884edd27b00fba68325508477",
        "social_mobile_device_authorization_v1.json": "26f335b718a771d08aacc7ebbe63895d395e2e2376d12484fb19ab30c0db7356",
        "social_mobile_authorization_ingress_v1.json": "d8f40ccc552c18c1beadb5ddb9d6a12b4b42c48dbe1eaf82c96f97233eca2e7d",
        "social_session_issuance_v1.json": "474bdfa4d3c300da0e78e5cde9a2b8dd263ee1e68227bb3a5000687d2ce230f3",
        "social_messaging_phase3_routing_v1.json": "90f7c3726a9dfcfa655630626d53d65b410e5e330456d5114d04982a53da2f1c",
    }
    for name, digest in expected.items():
        assert hashlib.sha256(ROOT.joinpath("tests/fixtures", name).read_bytes()).hexdigest() == digest
