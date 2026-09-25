"""Offline routing-registry contract tests; PostgreSQL authority never falls back."""

from __future__ import annotations

import ast
import hashlib
import inspect
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy import inspect as inspect_database
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session as SqlAlchemySession
from sqlalchemy.schema import CreateTable
from sqlalchemy.sql.dml import Insert
from sqlalchemy.sql.selectable import Select

from app.services import social_messaging_recipient_routing as routing
from app.services import social_messaging_recipient_routing_storage as storage
from tests.unit.test_social_messaging_recipient_routing import (
    ALIAS_SECRET,
    RECIPIENT,
    VIEWER_A,
    decision_route,
    snapshot_route,
    valid_decision,
    valid_snapshot,
)

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations/2026-09-24_social_messaging_recipient_routing_registry_v1.sql"
DENIED = routing.RecipientMessagingRoutingUnavailable
ERROR = "^recipient messaging routing unavailable$"


class Result:
    def __init__(self, rows=None, scalar=None):
        self.rows = [] if rows is None else rows
        self.scalar = scalar

    def scalar_one(self):
        return self.scalar

    def mappings(self):
        return self

    def all(self):
        return list(self.rows)

    def one(self):
        if len(self.rows) != 1:
            raise ValueError("synthetic cardinality")
        return self.rows[0]


class Session:
    """Small SQLAlchemy-construction fake; integration tests prove PostgreSQL."""

    def __init__(self, database=None):
        self.database = database or {
            storage.HANDLE_TABLE: [],
            storage.SNAPSHOT_TABLE: [],
            storage.SNAPSHOT_ROUTE_TABLE: [],
            storage.DECISION_TABLE: [],
            storage.DECISION_ROUTE_TABLE: [],
        }
        self.transaction = SimpleNamespace(is_active=True)
        self.nested = None
        self.is_active = True
        self.dialect = "postgresql"
        self.isolation = "read committed"
        self.guards = storage._EXPECTED_TRIGGER_COUNT
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

    def _insert(self, statement):
        table = statement.table.name
        row = dict(statement.compile().params)
        rows = self.database[table]
        keys = {
            storage.HANDLE_TABLE: ("device_handle",),
            storage.SNAPSHOT_TABLE: ("snapshot_id",),
            storage.SNAPSHOT_ROUTE_TABLE: ("snapshot_id", "route_ordinal"),
            storage.DECISION_TABLE: ("message_id",),
            storage.DECISION_ROUTE_TABLE: ("message_id", "route_ordinal"),
        }[table]
        if any(all(item[key] == row[key] for key in keys) for item in rows):
            raise ValueError("synthetic duplicate")
        if table == storage.HANDLE_TABLE:
            namespace = (
                "alias_version",
                "viewer_subject",
                "recipient_subject",
                "device_id",
                "binding_id",
                "binding_version",
            )
            if any(all(item[key] == row[key] for key in namespace) for item in rows):
                raise ValueError("synthetic namespace remap")
        rows.append(row)
        return Result([row])

    def _select(self, statement):
        table = statement.get_final_froms()[0].name
        values = list(statement.compile().params.values())
        rows = self.database[table]
        if table == storage.HANDLE_TABLE:
            selected = [row for row in rows if row["device_handle"] == values[0]]
        elif table in {storage.SNAPSHOT_TABLE, storage.SNAPSHOT_ROUTE_TABLE}:
            selected = [row for row in rows if row["snapshot_id"] == values[0]]
        else:
            selected = [row for row in rows if row["message_id"] == values[0]]
        ordinal = "route_ordinal"
        if selected and ordinal in selected[0]:
            selected.sort(key=lambda row: row[ordinal])
        return Result(selected)

    def execute(self, statement, parameters=None):
        self.statements.append((statement, parameters))
        sql = str(statement)
        if sql == "SHOW transaction_isolation":
            return Result(scalar=self.isolation)
        if "FROM pg_trigger" in sql:
            return Result(scalar=self.guards)
        if "pg_advisory_xact_lock" in sql:
            return Result(scalar=None)
        if isinstance(statement, Insert):
            return self._insert(statement)
        if isinstance(statement, Select):
            return self._select(statement)
        raise AssertionError(sql)


def repository(database=None):
    session = Session(database)
    return storage.SqlAlchemyRecipientRoutingRepository(session), session


def snapshot_rows(snapshot):
    return (
        {
            "snapshot_id": snapshot.recipient_package_snapshot_id,
            "viewer_subject": snapshot.viewer_subject,
            "recipient_subject": snapshot.recipient_subject,
            "alias_version": snapshot.alias_version,
            "issued_at": snapshot.issued_at,
            "expires_at": snapshot.expires_at,
            "route_count": len(snapshot.routes),
            "snapshot_wire": routing.canonical_routing_snapshot_bytes(snapshot).decode("ascii"),
        },
        [
            {
                "snapshot_id": snapshot.recipient_package_snapshot_id,
                "route_ordinal": ordinal,
                "device_handle": route.device_handle,
                "device_id": route.device_id,
                "binding_id": route.binding_id,
                "binding_version": route.binding_version,
                "authorization_proof_id": route.authorization_proof_id,
                "authorization_valid_from": route.authorization_valid_from,
                "authorization_expires_at": route.authorization_expires_at,
            }
            for ordinal, route in enumerate(snapshot.routes, start=1)
        ],
    )


def decision_rows(decision):
    return (
        {
            "message_id": decision.message_id,
            "envelope_digest": decision.envelope_digest,
            "snapshot_id": decision.recipient_package_snapshot_id,
            "viewer_subject": decision.viewer_subject,
            "recipient_subject": decision.recipient_subject,
            "expires_at": decision.expires_at,
            "route_count": len(decision.routes),
            "decision_wire": routing.canonical_routing_decision_bytes(decision).decode("ascii"),
        },
        [
            {
                "message_id": decision.message_id,
                "route_ordinal": ordinal,
                "device_handle": route.device_handle,
                "device_id": route.device_id,
                "binding_id": route.binding_id,
                "binding_version": route.binding_version,
            }
            for ordinal, route in enumerate(decision.routes, start=1)
        ],
    )


def test_exact_snapshot_and_decision_bytes_roundtrip_through_real_protocol_types():
    snapshot = valid_snapshot(snapshot_route(1), snapshot_route(2))
    decision = valid_decision(decision_route(1), decision_route(2))
    snapshot_row, snapshot_route_rows = snapshot_rows(snapshot)
    decision_row, decision_route_rows = decision_rows(decision)
    assert storage.parse_stored_routing_snapshot_v1(snapshot_row, snapshot_route_rows) == snapshot
    assert storage.parse_stored_routing_decision_v1(decision_row, decision_route_rows) == decision
    assert snapshot_row["snapshot_wire"].encode("ascii") == routing.canonical_routing_snapshot_bytes(snapshot)
    assert decision_row["decision_wire"].encode("ascii") == routing.canonical_routing_decision_bytes(decision)


@pytest.mark.parametrize("kind", ("snapshot", "decision"))
@pytest.mark.parametrize("mutation", ("whitespace", "duplicate", "unknown", "route_drop", "metadata"))
def test_malformed_duplicate_incomplete_or_mismatched_history_denied(kind, mutation):
    if kind == "snapshot":
        value = valid_snapshot()
        row, routes = snapshot_rows(value)
        parse = storage.parse_stored_routing_snapshot_v1
        wire_key = "snapshot_wire"
        metadata_key = "viewer_subject"
    else:
        value = valid_decision()
        row, routes = decision_rows(value)
        parse = storage.parse_stored_routing_decision_v1
        wire_key = "decision_wire"
        metadata_key = "recipient_subject"
    if mutation == "whitespace":
        row[wire_key] = " " + row[wire_key]
    elif mutation == "duplicate":
        row[wire_key] = '{"version":1,' + row[wire_key][1:]
    elif mutation == "unknown":
        row[wire_key] = row[wire_key][:-1] + ',"unknown":null}'
    elif mutation == "route_drop":
        routes.clear()
    else:
        row[metadata_key] = "ff" * 32
    with pytest.raises(DENIED, match=ERROR):
        parse(row, routes)


def test_adapter_implements_exact_protocol_with_idempotence_and_complete_routes():
    repo, session = repository()
    snapshot = valid_snapshot(snapshot_route(1), snapshot_route(2))
    assert repo.retain_snapshot(snapshot) == snapshot
    assert repo.retain_snapshot(snapshot) == snapshot
    assert repo.read_snapshot(snapshot.recipient_package_snapshot_id) == snapshot
    assert len(session.database[storage.HANDLE_TABLE]) == 2
    assert len(session.database[storage.SNAPSHOT_ROUTE_TABLE]) == 2
    decision = valid_decision(decision_route(1), decision_route(2))
    assert repo.record_decision(decision) == decision
    assert repo.record_decision(decision) == decision
    assert len(session.database[storage.DECISION_TABLE]) == 1
    assert len(session.database[storage.DECISION_ROUTE_TABLE]) == 2


def test_same_tuple_renewal_is_allowed_but_same_namespace_cannot_remap():
    repo, session = repository()
    snapshot = valid_snapshot()
    repo.retain_snapshot(snapshot)
    renewal = replace(
        snapshot,
        recipient_package_snapshot_id="sha256:" + "22" * 32,
        issued_at=snapshot.issued_at + 1_000,
        expires_at=snapshot.expires_at + 1_000,
    )
    assert repo.retain_snapshot(renewal) == renewal
    assert len(session.database[storage.HANDLE_TABLE]) == 1
    assert len(session.database[storage.SNAPSHOT_TABLE]) == 2

    remapped_route = replace(snapshot.routes[0], device_handle="d_" + "A" * 22)
    remapped = replace(
        snapshot,
        recipient_package_snapshot_id="sha256:" + "33" * 32,
        routes=(remapped_route,),
    )
    with pytest.raises(DENIED, match=ERROR):
        repo.retain_snapshot(remapped)


def test_alias_version_rotation_adds_namespace_without_remapping_old_handle():
    repo, session = repository()
    original = valid_snapshot()
    repo.retain_snapshot(original)
    route = original.routes[0]
    rotated_handle = routing.derive_recipient_device_handle(
        viewer=original.viewer_subject,
        target=original.recipient_subject,
        binding_id=route.binding_id,
        alias_secret=ALIAS_SECRET,
        alias_version=2,
    )
    rotated = replace(
        original,
        alias_version=2,
        recipient_package_snapshot_id="sha256:" + "44" * 32,
        routes=(replace(route, device_handle=rotated_handle),),
    )
    assert repo.retain_snapshot(rotated) == rotated
    owners = {row["device_handle"]: row for row in session.database[storage.HANDLE_TABLE]}
    assert set(owners) == {route.device_handle, rotated_handle}
    assert owners[route.device_handle]["alias_version"] == 1
    assert owners[rotated_handle]["alias_version"] == 2


def test_handle_collision_and_message_digest_change_deny_without_oracle():
    repo, _session = repository()
    snapshot = valid_snapshot()
    repo.retain_snapshot(snapshot)
    conflicting = replace(
        snapshot,
        recipient_package_snapshot_id="sha256:" + "55" * 32,
        viewer_subject="02" * 32,
    )
    with pytest.raises(DENIED, match=ERROR):
        repo.retain_snapshot(conflicting)

    repo, _session = repository()
    repo.retain_snapshot(snapshot)
    decision = valid_decision()
    repo.record_decision(decision)
    changed = replace(decision, envelope_digest="hodlxxi-social-message-envelope-v1-sha256:" + "cd" * 32)
    with pytest.raises(DENIED, match=ERROR) as failure:
        repo.record_decision(changed)
    assert failure.value.__cause__ is failure.value.__context__ is None


def test_decision_requires_exact_retained_snapshot_and_route_set():
    repo, _session = repository()
    with pytest.raises(DENIED, match=ERROR):
        repo.record_decision(valid_decision())

    repo, _session = repository()
    repo.retain_snapshot(valid_snapshot())
    wrong = replace(valid_decision(), routes=(replace(decision_route(), device_id="ff" * 32),))
    with pytest.raises(DENIED, match=ERROR):
        repo.record_decision(wrong)


def test_registry_exposes_no_current_handle_resolution():
    assert not hasattr(storage.SqlAlchemyRecipientRoutingRepository, "_read_handle_owner_for_current_authority")


def test_unknown_snapshot_is_none_but_malformed_or_corrupt_history_denies():
    repo, session = repository()
    assert repo.read_snapshot("sha256:" + "ff" * 32) is None
    snapshot = repo.retain_snapshot(valid_snapshot())
    session.database[storage.SNAPSHOT_ROUTE_TABLE].clear()
    with pytest.raises(DENIED, match=ERROR):
        repo.read_snapshot(snapshot.recipient_package_snapshot_id)


@pytest.mark.parametrize(
    "field,value",
    [
        ("dialect", "sqlite"),
        ("is_active", False),
        ("transaction", None),
        ("isolation", "repeatable read"),
        ("guards", 14),
        ("new", {1}),
        ("dirty", {1}),
        ("deleted", {1}),
    ],
)
def test_requires_one_clean_read_committed_postgresql_transaction_and_all_guards(field, value):
    session = Session()
    setattr(session, field, value)
    with pytest.raises(DENIED, match=ERROR):
        storage.SqlAlchemyRecipientRoutingRepository(session)


@pytest.mark.parametrize("change", ("ended", "replaced", "savepoint", "autocommit", "connection"))
def test_session_connection_transaction_and_savepoint_are_pinned(change):
    repo, session = repository()
    if change == "ended":
        session.transaction.is_active = False
    elif change == "replaced":
        session.transaction = SimpleNamespace(is_active=True)
    elif change == "savepoint":
        session.nested = object()
    elif change == "autocommit":
        session.driver.autocommit = True
    else:
        session.bound_connection = Session().bound_connection
    with pytest.raises(DENIED, match=ERROR):
        repo.read_snapshot("sha256:" + "ff" * 32)


def test_real_sqlite_transaction_and_schema_only_metadata_never_grant_authority():
    engine = create_engine("sqlite:///:memory:")
    try:
        storage.Base.metadata.create_all(engine)
        assert {
            storage.HANDLE_TABLE,
            storage.SNAPSHOT_TABLE,
            storage.SNAPSHOT_ROUTE_TABLE,
            storage.DECISION_TABLE,
            storage.DECISION_ROUTE_TABLE,
        } <= set(inspect_database(engine).get_table_names())
        with SqlAlchemySession(engine) as session, session.begin():
            with pytest.raises(DENIED, match=ERROR):
                storage.SqlAlchemyRecipientRoutingRepository(session)
        storage.Base.metadata.drop_all(engine)
    finally:
        engine.dispose()


def test_models_and_migration_freeze_five_tables_complete_guards_and_no_upsert():
    sql = MIGRATION.read_text(encoding="ascii")
    tables = (
        storage.RecipientRoutingHandleOwnerRow.__table__,
        storage.RecipientRoutingSnapshotRow.__table__,
        storage.RecipientRoutingSnapshotRouteRow.__table__,
        storage.RecipientRoutingDecisionRow.__table__,
        storage.RecipientRoutingDecisionRouteRow.__table__,
    )
    for table in tables:
        ddl = str(CreateTable(table).compile(dialect=postgresql.dialect()))
        assert f"CREATE TABLE {table.name}" in ddl
        assert f"CREATE TABLE {table.name}" in sql
        for constraint in table.constraints:
            if constraint.name:
                assert constraint.name in sql
    assert sql.count("BEFORE UPDATE OR DELETE") == 5
    assert sql.count("BEFORE TRUNCATE") == 5
    assert sql.count("CREATE CONSTRAINT TRIGGER") == 5
    assert "ON CONFLICT" not in sql
    assert "CURRENT_TIMESTAMP" not in sql
    assert "DROP TABLE" not in sql
    sqlite_ddl = "".join(str(CreateTable(table).compile(dialect=sqlite.dialect())) for table in tables)
    assert not any(token in sqlite_ddl for token in ("!~", "::json", "octet_length"))


def test_rows_and_historical_owner_are_frozen_and_repr_excludes_mapping():
    snapshot = valid_snapshot()
    route = snapshot.routes[0]
    owner = storage._expected_owner(snapshot, route)
    with pytest.raises(FrozenInstanceError):
        owner.binding_id = "ff" * 32
    assert repr(owner).startswith("<")


def test_no_io_at_import_no_runtime_composition_and_exact_nonclaims():
    source = inspect.getsource(storage)
    tree = ast.parse(source)
    assert not any(
        node.id in {"create_engine", "sessionmaker"} for node in ast.walk(tree) if isinstance(node, ast.Name)
    )
    with (
        patch("socket.socket", side_effect=AssertionError("I/O forbidden")),
        patch("sqlalchemy.create_engine", side_effect=AssertionError("engine forbidden")),
    ):
        assert storage.RUNTIME_ENABLED is False
    assert storage.CIPHERTEXT_PERSISTENCE == "not_implemented"
    assert storage.RECIPIENT_SELF_READ == "not_granted"
    assert storage.REQUEST_ADMISSION == storage.RECEIPT_ISSUANCE == storage.CHALLENGE_CONSUMPTION == "not_implemented"
    assert not any(
        hasattr(storage.SqlAlchemyRecipientRoutingRepository, name) for name in ("begin", "commit", "rollback", "close")
    )


def test_protected_fixture_and_migration_hashes_are_unchanged():
    expected = {
        "migrations/2026-09-21_social_device_challenge_store_v1.sql": "2379d18b81e468ff9044ca2209db9f38e1b23cccac70520bfed24b4765d42ef2",
        "migrations/2026-09-22_social_device_ed25519_association_storage_v1.sql": "c9f24d95dff9eae349374e35f3edcef31877647b4ad7a1c9de59d68b16599122",
        "migrations/2026-09-23_social_device_admission_receipt_consumption_v1.sql": "9772d46d3c756f8818a75720293d105a5edb0ff9e8c6ea9edb7a6ff8652a2168",
        "tests/fixtures/social_device_admission_v1.json": "09722ca9ab230a7bbc73b2228dfed5e80cdd2c2bb44a32e8571bdcf246ca4324",
        "tests/fixtures/social_messaging_phase3_routing_v1.json": "90f7c3726a9dfcfa655630626d53d65b410e5e330456d5114d04982a53da2f1c",
        "tests/fixtures/social_device_request_operation_effect_v1.json": "5b452309c560d924614dad01d37dce13a4da63ab5b3ae2514f718609393bcd68",
    }
    for relative, digest in expected.items():
        assert hashlib.sha256(ROOT.joinpath(relative).read_bytes()).hexdigest() == digest
