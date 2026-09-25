"""Offline contract tests for the dormant ACTIVE alias-namespace reader."""

from __future__ import annotations

import ast
import hashlib
import inspect
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy import inspect as inspect_database
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session as SqlAlchemySession
from sqlalchemy.schema import CreateIndex, CreateTable
from sqlalchemy.sql.selectable import Select

from app.services import social_messaging_active_alias_namespace_storage as storage

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations/2026-09-24_social_messaging_active_alias_namespace_v1.sql"
PR557_MIGRATION = ROOT / "migrations/2026-09-24_social_messaging_recipient_routing_registry_v1.sql"
ALIAS_SECRET = bytes(range(32))
ROTATED_SECRET = bytes(reversed(range(32)))
COMMITMENT_V1 = (
    "hodlxxi-social-active-alias-namespace-v1-sha256:"
    "6e35acd92e03e0d6506601b4dfde5a812d4ba0a568cd7ade1428b41b74dae2a8"
)
COMMITMENT_V2 = (
    "hodlxxi-social-active-alias-namespace-v1-sha256:"
    "97ca381e2e16c7f10003dbc2230e69af6bd5a1fe24342cd796a2ca03a97067be"
)
DENIED = storage.ActiveAliasNamespaceUnavailable
ERROR = "^social messaging active alias namespace unavailable$"


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


class Session:
    """Small SQLAlchemy-construction fake; integration tests prove locking."""

    def __init__(self, rows=None):
        self.rows = [] if rows is None else rows
        self.transaction = SimpleNamespace(is_active=True)
        self.nested = None
        self.is_active = True
        self.dialect = "postgresql"
        self.isolation = "read committed"
        self.guards = storage._EXPECTED_TRIGGER_COUNT
        self.indexes = 1
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

    def execute(self, statement, parameters=None):
        self.statements.append((statement, parameters))
        sql = str(statement)
        if sql == "SHOW transaction_isolation":
            return Result(scalar=self.isolation)
        if "FROM pg_trigger" in sql:
            return Result(scalar=self.guards)
        if "FROM pg_index" in sql:
            return Result(scalar=self.indexes)
        if isinstance(statement, Select):
            assert statement._for_update_arg is not None
            return Result([row for row in self.rows if row["lifecycle_state"] == storage.ACTIVE_NAMESPACE_STATE])
        raise AssertionError(sql)


def namespace_row(*, secret=ALIAS_SECRET, version=1, state=storage.ACTIVE_NAMESPACE_STATE):
    return {
        "alias_version": version,
        "secret_commitment": storage.active_alias_namespace_secret_commitment(
            alias_secret=secret,
            alias_version=version,
        ),
        "lifecycle_state": state,
    }


def reader(rows=None, *, secret=ALIAS_SECRET, version=1):
    session = Session(rows)
    value = storage.SqlAlchemyTransactionBoundActiveAliasNamespaceReader(
        session,
        configured_alias_secret=secret,
        configured_alias_version=version,
    )
    return value, session


def test_secret_commitment_has_fixed_domain_separated_vectors():
    assert (
        storage.active_alias_namespace_secret_commitment(
            alias_secret=ALIAS_SECRET,
            alias_version=1,
        )
        == COMMITMENT_V1
    )
    assert (
        storage.active_alias_namespace_secret_commitment(
            alias_secret=ALIAS_SECRET,
            alias_version=2,
        )
        == COMMITMENT_V2
    )
    assert storage.active_alias_namespace_secret_commitment(
        alias_secret=ROTATED_SECRET,
        alias_version=1,
    ) not in {COMMITMENT_V1, COMMITMENT_V2}


@pytest.mark.parametrize(
    "secret,version",
    [
        (b"short", 1),
        (bytearray(32), 1),
        (ALIAS_SECRET, True),
        (ALIAS_SECRET, 0),
        (ALIAS_SECRET, 2_147_483_648),
    ],
)
def test_secret_commitment_rejects_noncanonical_configuration(secret, version):
    with pytest.raises(ValueError, match="^invalid active alias namespace configuration$"):
        storage.active_alias_namespace_secret_commitment(
            alias_secret=secret,
            alias_version=version,
        )


def test_reader_locks_exact_active_row_and_retains_no_secret():
    value, session = reader([namespace_row()])
    result = value.lock_configured_active_namespace()
    assert result == storage.LockedActiveAliasNamespaceV1(
        alias_version=1,
        secret_commitment=COMMITMENT_V1,
        lifecycle_state=storage.ACTIVE_NAMESPACE_STATE,
    )
    assert not hasattr(value, "_configured_alias_secret")
    assert ALIAS_SECRET not in value.__dict__.values()
    selects = [statement for statement, _parameters in session.statements if isinstance(statement, Select)]
    assert len(selects) == 1
    compiled = str(selects[0].compile(dialect=postgresql.dialect()))
    assert "FOR UPDATE OF social_messaging_active_alias_namespaces" in compiled
    assert "alias_version =" not in compiled


@pytest.mark.parametrize(
    "rows,secret,version",
    [
        ([], ALIAS_SECRET, 1),
        ([namespace_row()], ROTATED_SECRET, 1),
        ([namespace_row()], ALIAS_SECRET, 2),
        ([namespace_row(), namespace_row(secret=ROTATED_SECRET, version=2)], ALIAS_SECRET, 1),
    ],
)
def test_missing_ambiguous_stale_or_secret_mismatched_active_state_denies(rows, secret, version):
    value, _session = reader(rows, secret=secret, version=version)
    with pytest.raises(DENIED, match=ERROR) as failure:
        value.lock_configured_active_namespace()
    assert failure.value.__cause__ is failure.value.__context__ is None


def test_old_namespace_and_version_order_never_select_current_state():
    rows = [
        namespace_row(secret=ROTATED_SECRET, version=99, state=storage.RETIRED_NAMESPACE_STATE),
        namespace_row(secret=ALIAS_SECRET, version=2),
    ]
    current, _session = reader(rows, secret=ALIAS_SECRET, version=2)
    assert current.lock_configured_active_namespace().alias_version == 2

    stale, _session = reader(rows, secret=ROTATED_SECRET, version=99)
    with pytest.raises(DENIED, match=ERROR):
        stale.lock_configured_active_namespace()


@pytest.mark.parametrize(
    "row",
    [
        {"alias_version": 1, "secret_commitment": COMMITMENT_V1},
        namespace_row(state=storage.RETIRED_NAMESPACE_STATE),
        {**namespace_row(), "alias_version": True},
        {**namespace_row(), "secret_commitment": COMMITMENT_V1.upper()},
    ],
)
def test_stored_row_parser_rejects_missing_retired_or_noncanonical_state(row):
    with pytest.raises(DENIED, match=ERROR):
        storage.parse_stored_active_alias_namespace_v1(row)


@pytest.mark.parametrize(
    "field,value",
    [
        ("dialect", "sqlite"),
        ("is_active", False),
        ("transaction", None),
        ("isolation", "repeatable read"),
        ("guards", 1),
        ("indexes", 0),
        ("new", {1}),
        ("dirty", {1}),
        ("deleted", {1}),
    ],
)
def test_reader_requires_clean_read_committed_postgresql_and_complete_guards(field, value):
    session = Session([namespace_row()])
    setattr(session, field, value)
    with pytest.raises(DENIED, match=ERROR):
        storage.SqlAlchemyTransactionBoundActiveAliasNamespaceReader(
            session,
            configured_alias_secret=ALIAS_SECRET,
            configured_alias_version=1,
        )


@pytest.mark.parametrize("change", ("ended", "replaced", "savepoint", "autocommit", "connection"))
def test_session_connection_transaction_and_savepoint_are_pinned(change):
    value, session = reader([namespace_row()])
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
        value.lock_configured_active_namespace()


def test_real_sqlite_metadata_never_grants_namespace_authority():
    engine = create_engine("sqlite:///:memory:")
    try:
        storage.Base.metadata.create_all(engine)
        assert storage.NAMESPACE_TABLE in inspect_database(engine).get_table_names()
        with SqlAlchemySession(engine) as session, session.begin():
            with pytest.raises(DENIED, match=ERROR):
                storage.SqlAlchemyTransactionBoundActiveAliasNamespaceReader(
                    session,
                    configured_alias_secret=ALIAS_SECRET,
                    configured_alias_version=1,
                )
        storage.Base.metadata.drop_all(engine)
    finally:
        engine.dispose()


def test_model_and_migration_freeze_empty_registry_and_one_active_invariant():
    sql = MIGRATION.read_text(encoding="ascii")
    table = storage.SocialMessagingActiveAliasNamespaceRow.__table__
    ddl = str(CreateTable(table).compile(dialect=postgresql.dialect()))
    index = next(item for item in table.indexes if item.name == storage._ACTIVE_INDEX)
    index_ddl = str(CreateIndex(index).compile(dialect=postgresql.dialect()))
    assert f"CREATE TABLE {storage.NAMESPACE_TABLE}" in ddl
    assert f"CREATE TABLE {storage.NAMESPACE_TABLE}" in sql
    assert "WHERE lifecycle_state = 'ACTIVE'" in index_ddl
    assert "WHERE lifecycle_state = 'ACTIVE'" in sql
    for constraint in table.constraints:
        if constraint.name:
            assert constraint.name in sql
    assert sql.count("CREATE TRIGGER") == storage._EXPECTED_TRIGGER_COUNT
    assert "INSERT INTO" not in sql
    assert "MAX(" not in sql.upper()
    assert "CURRENT_TIMESTAMP" not in sql
    assert "DROP TABLE" not in sql
    sqlite_ddl = str(CreateTable(table).compile(dialect=sqlite.dialect()))
    assert "~" not in sqlite_ddl


def test_result_is_frozen_and_repr_omits_commitment():
    result = storage.parse_stored_active_alias_namespace_v1(namespace_row())
    with pytest.raises(FrozenInstanceError):
        result.alias_version = 2
    assert repr(result).startswith("<")
    assert COMMITMENT_V1 not in repr(result)


def test_no_writer_io_runtime_composition_or_authorization_claim():
    source = inspect.getsource(storage)
    tree = ast.parse(source)
    assert not any(
        node.id in {"create_engine", "sessionmaker", "insert", "update", "delete"}
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
    )
    with (
        patch("socket.socket", side_effect=AssertionError("I/O forbidden")),
        patch("sqlalchemy.create_engine", side_effect=AssertionError("engine forbidden")),
    ):
        assert storage.RUNTIME_ENABLED is False
    assert storage.NAMESPACE_PROVISIONING == storage.NAMESPACE_ROTATION == "not_implemented"
    assert storage.CURRENT_HANDLE_RESOLUTION == "not_implemented"
    assert storage.RECIPIENT_SELF_READ_AUTHORIZATION == "not_granted"
    assert not any(
        hasattr(storage.SqlAlchemyTransactionBoundActiveAliasNamespaceReader, name)
        for name in ("begin", "commit", "rollback", "close", "provision", "rotate")
    )
    assert "social_messaging_recipient_handle_owners" not in source


def test_pr557_migration_bytes_are_unchanged():
    assert (
        hashlib.sha256(PR557_MIGRATION.read_bytes()).hexdigest()
        == "971f5e048cfd7614e04ce728caa9a422a545975df3895716bbaffb60c81bb4e9"
    )
