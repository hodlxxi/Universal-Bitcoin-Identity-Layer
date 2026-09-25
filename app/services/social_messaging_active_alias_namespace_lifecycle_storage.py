"""Dormant transaction owner for signed alias-namespace lifecycle commands.

The caller owns one already-active PostgreSQL READ COMMITTED transaction.
This owner authenticates exact offline-signed command bytes, reconciles them
with the configured successor secret commitment, serializes lifecycle writers,
and stages one complete registry/event transition.  It never owns transaction
lifecycle, loads configuration, exposes a route, or retains the alias secret.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Mapping, NoReturn, cast

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    ForeignKeyConstraint,
    Integer,
    PrimaryKeyConstraint,
    String,
    Text,
    UniqueConstraint,
    func,
    insert,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.engine import Connection, NestedTransaction, RootTransaction
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import ColumnElement
from sqlalchemy.types import UserDefinedType

from app.models import Base
from app.services import social_messaging_active_alias_namespace_lifecycle as lifecycle
from app.services import social_messaging_active_alias_namespace_storage as namespace

EVENT_TABLE = "social_messaging_active_alias_namespace_lifecycle_events"
WRITER_ADVISORY_LOCK_DOMAIN = b"HODLXXI_SOCIAL_ACTIVE_ALIAS_NAMESPACE_LIFECYCLE_WRITER_LOCK_V1"
WRITER_ADVISORY_LOCK_KEY = int.from_bytes(
    hashlib.sha256(WRITER_ADVISORY_LOCK_DOMAIN).digest()[:8],
    "big",
    signed=True,
)
RUNTIME_ENABLED = False
TRANSACTION_OWNER = "caller"
PRIVATE_KEY_CUSTODY = "external_offline_only"
UNAVAILABLE_MESSAGE = "social messaging alias namespace lifecycle storage unavailable"

_EXPECTED_NAMESPACE_TRIGGER_COUNT = 3
_EXPECTED_EVENT_TRIGGER_COUNT = 3
_EXPECTED_EVENT_UNIQUE_CONSTRAINT_COUNT = 5


class AliasNamespaceLifecycleStorageUnavailable(RuntimeError):
    """One non-sensitive failure for authorization, state, or storage denial."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


def _deny() -> NoReturn:
    raise AliasNamespaceLifecycleStorageUnavailable()


class _PostgreSQLEventCheck(ColumnElement):
    """Keep PostgreSQL-only event checks inert in shared SQLite metadata."""

    inherit_cache = False
    type = Boolean()

    def __init__(self, expression: str) -> None:
        self.postgresql_sql = expression


@compiles(_PostgreSQLEventCheck)
@compiles(_PostgreSQLEventCheck, "postgresql")
def _compile_postgresql_event_check(element, _compiler, **_kwargs):
    return element.postgresql_sql


@compiles(_PostgreSQLEventCheck, "sqlite")
def _compile_sqlite_event_check(_element, _compiler, **_kwargs):
    return "1"


class _PostgreSQLFullTransactionId(UserDefinedType):
    """PostgreSQL full transaction ID used only by the event ledger."""

    cache_ok = True

    def get_col_spec(self, **_kwargs):
        return "xid8"


class SocialMessagingActiveAliasNamespaceLifecycleEventRow(Base):
    """Immutable exact signed command evidence for one namespace generation."""

    __tablename__ = EVENT_TABLE

    command_id = Column(String(120), nullable=False)
    action = Column(String(9), nullable=False)
    key_id = Column(String(64), nullable=False)
    nonce = Column(String(43), nullable=False)
    expected_version = Column(Integer, nullable=True)
    expected_commitment = Column(String(namespace.SECRET_COMMITMENT_LENGTH), nullable=True)
    successor_version = Column(Integer, nullable=False)
    successor_commitment = Column(String(namespace.SECRET_COMMITMENT_LENGTH), nullable=False)
    issued_at_ms = Column(BigInteger, nullable=False)
    expires_at_ms = Column(BigInteger, nullable=False)
    command_wire = Column(Text, nullable=False)
    signature = Column(String(86), nullable=False)
    staged_top_level_transaction_id = Column(
        _PostgreSQLFullTransactionId(),
        nullable=False,
    )

    __table_args__ = (
        PrimaryKeyConstraint("command_id", name="pk_social_alias_lifecycle_event"),
        UniqueConstraint("nonce", name="uq_social_alias_lifecycle_event_nonce"),
        UniqueConstraint(
            "successor_version",
            name="uq_social_alias_lifecycle_event_successor_version",
        ),
        UniqueConstraint(
            "successor_commitment",
            name="uq_social_alias_lifecycle_event_successor_commitment",
        ),
        UniqueConstraint(
            "command_wire",
            name="uq_social_alias_lifecycle_event_command_wire",
        ),
        ForeignKeyConstraint(
            ("expected_version",),
            (f"{namespace.NAMESPACE_TABLE}.alias_version",),
            name="fk_social_alias_lifecycle_event_expected_version",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ("successor_version",),
            (f"{namespace.NAMESPACE_TABLE}.alias_version",),
            name="fk_social_alias_lifecycle_event_successor_version",
            deferrable=True,
            initially="DEFERRED",
        ),
        CheckConstraint(
            "action IN ('provision', 'rotate')",
            name="ck_social_alias_lifecycle_event_action",
        ),
        CheckConstraint(
            f"successor_version BETWEEN 1 AND {lifecycle.MAX_ALIAS_VERSION}",
            name="ck_social_alias_lifecycle_event_successor_version",
        ),
        CheckConstraint(
            "issued_at_ms BETWEEN 0 AND 9007199254740991 "
            "AND expires_at_ms BETWEEN 0 AND 9007199254740991 "
            "AND expires_at_ms > issued_at_ms "
            "AND expires_at_ms - issued_at_ms <= 86400000",
            name="ck_social_alias_lifecycle_event_interval",
        ),
        CheckConstraint(
            _PostgreSQLEventCheck(
                "command_id ~ " "'^hodlxxi-social-active-alias-lifecycle-command-v1-sha256:[0-9a-f]{64}$'"
            ),
            name="ck_social_alias_lifecycle_event_command_id",
        ),
        CheckConstraint(
            _PostgreSQLEventCheck("key_id ~ '^[a-z0-9][a-z0-9._:-]{0,63}$'"),
            name="ck_social_alias_lifecycle_event_key_id",
        ),
        CheckConstraint(
            _PostgreSQLEventCheck("nonce ~ '^[A-Za-z0-9_-]{43}$'"),
            name="ck_social_alias_lifecycle_event_nonce",
        ),
        CheckConstraint(
            _PostgreSQLEventCheck("signature ~ '^[A-Za-z0-9_-]{86}$'"),
            name="ck_social_alias_lifecycle_event_signature",
        ),
        CheckConstraint(
            _PostgreSQLEventCheck(
                "successor_commitment ~ " "'^hodlxxi-social-active-alias-namespace-v1-sha256:[0-9a-f]{64}$'"
            ),
            name="ck_social_alias_lifecycle_event_successor_commitment",
        ),
        CheckConstraint(
            _PostgreSQLEventCheck("octet_length(command_wire) BETWEEN 1 AND 2048 " "AND command_wire !~ '[^ -~]'"),
            name="ck_social_alias_lifecycle_event_command_wire",
        ),
    )


@dataclass(frozen=True, slots=True, repr=False)
class AliasNamespaceLifecycleResultV1:
    """Exact transition evidence without bearer or transaction authority."""

    command_id: str
    action: str
    expected_version: int | None
    expected_commitment: str | None
    successor_version: int
    successor_commitment: str
    outcome: str
    publication_status: str
    bearer_authority: str = field(default="none", init=False)
    transaction_authority: str = field(default="caller_owned", init=False)


def _command_values(
    verifier: lifecycle.PinnedOfflineAliasLifecycleVerifierV1,
    command_wire: object,
    signature: object,
    *,
    now_ms: int,
    configured_version: int,
    configured_commitment: str,
) -> dict[str, object]:
    """Authenticate raw bytes and bind their successor to startup config."""

    try:
        if type(command_wire) is not bytes or type(signature) is not str:
            _deny()
        verified = verifier.verify(command_wire, signature, now_ms=now_ms)
        values = lifecycle.parse_canonical_alias_lifecycle_command_v1(command_wire)
        inspected = verified.inspected
        if (
            verified.command_wire != command_wire
            or verified.signature != signature
            or inspected.command_id != values["commandId"]
            or inspected.action != values["action"]
            or inspected.expected_version != values["expectedVersion"]
            or inspected.expected_commitment != values["expectedCommitment"]
            or inspected.successor_version != values["successorVersion"]
            or inspected.successor_commitment != values["successorCommitment"]
            or inspected.key_id != values["keyId"]
            or values["successorVersion"] != configured_version
            or not hmac.compare_digest(
                cast(str, values["successorCommitment"]),
                configured_commitment,
            )
        ):
            _deny()
        return values
    except Exception:
        pass
    _deny()


def _event_values(
    command: Mapping[str, object],
    command_wire: bytes,
    signature: str,
) -> dict[str, object]:
    return {
        "command_id": command["commandId"],
        "action": command["action"],
        "key_id": command["keyId"],
        "nonce": command["nonce"],
        "expected_version": command["expectedVersion"],
        "expected_commitment": command["expectedCommitment"],
        "successor_version": command["successorVersion"],
        "successor_commitment": command["successorCommitment"],
        "issued_at_ms": command["issuedAtMs"],
        "expires_at_ms": command["expiresAtMs"],
        "command_wire": command_wire.decode("ascii"),
        "signature": signature,
    }


def _result(command: Mapping[str, object], *, outcome: str) -> AliasNamespaceLifecycleResultV1:
    publications = {
        "staged": "provisional_until_caller_commit",
        "committed": "committed_evidence",
        "absent": "no_committed_evidence",
    }
    if outcome not in publications:
        _deny()
    return AliasNamespaceLifecycleResultV1(
        command_id=cast(str, command["commandId"]),
        action=cast(str, command["action"]),
        expected_version=cast(int | None, command["expectedVersion"]),
        expected_commitment=cast(str | None, command["expectedCommitment"]),
        successor_version=cast(int, command["successorVersion"]),
        successor_commitment=cast(str, command["successorCommitment"]),
        outcome=outcome,
        publication_status=publications[outcome],
    )


class SqlAlchemyTransactionBoundActiveAliasNamespaceLifecycleOwner:
    """Stage or reconcile one exact signed command in the caller transaction."""

    def __init__(
        self,
        session: Session,
        *,
        pinned_public_key: bytes,
        pinned_key_id: str,
        configured_successor_alias_secret: bytes,
        configured_successor_alias_version: int,
    ) -> None:
        self._session = session
        self._failed = False
        self._used = False
        self._connection: Connection | None = None
        self._database_transaction: RootTransaction | None = None
        self._database_nested_transaction: NestedTransaction | None = None
        try:
            configured_commitment = namespace.active_alias_namespace_secret_commitment(
                alias_secret=configured_successor_alias_secret,
                alias_version=configured_successor_alias_version,
            )
            self._configured_successor_alias_version = configured_successor_alias_version
            self._configured_successor_commitment = configured_commitment
            self._verifier = lifecycle.PinnedOfflineAliasLifecycleVerifierV1(
                public_key=pinned_public_key,
                key_id=pinned_key_id,
            )
            self._transaction = session.get_transaction()
            self._nested_transaction = session.get_nested_transaction()
            self._check_transaction()
            return
        except Exception:
            self._failed = True
        _deny()

    def _check_transaction(self) -> Connection:
        try:
            session = self._session
            if (
                self._failed
                or self._transaction is None
                or not self._transaction.is_active
                or session.get_transaction() is not self._transaction
                or session.get_nested_transaction() is not self._nested_transaction
                or session.in_transaction() is not True
                or not session.is_active
                or session.new
                or session.dirty
                or session.deleted
                or session.get_bind().dialect.name != "postgresql"
            ):
                _deny()
            connection = session.connection()
            if (
                connection.closed
                or connection.invalidated
                or not connection.in_transaction()
                or getattr(connection.connection.dbapi_connection, "autocommit", None) is not False
            ):
                _deny()
            if self._connection is None:
                self._connection = connection
                self._database_transaction = connection.get_transaction()
                self._database_nested_transaction = connection.get_nested_transaction()
            if (
                connection is not self._connection
                or self._database_transaction is None
                or connection.get_transaction() is not self._database_transaction
                or connection.get_nested_transaction() is not self._database_nested_transaction
                or not self._database_transaction.is_active
            ):
                _deny()
            if connection.execute(text("SHOW transaction_isolation")).scalar_one() != "read committed":
                _deny()
            namespace_triggers = connection.execute(
                text(
                    "SELECT count(*) FROM pg_trigger "
                    "WHERE NOT tgisinternal AND tgenabled = 'O' "
                    "AND tgrelid = to_regclass(:table) "
                    "AND tgname IN ('trg_social_active_alias_namespace_guard',"
                    "'trg_social_active_alias_namespace_no_truncate',"
                    "'trg_social_alias_lifecycle_namespace_invariant')"
                ),
                {"table": namespace.NAMESPACE_TABLE},
            ).scalar_one()
            event_triggers = connection.execute(
                text(
                    "SELECT count(*) FROM pg_trigger "
                    "WHERE NOT tgisinternal AND tgenabled = 'O' "
                    "AND tgrelid = to_regclass(:table) "
                    "AND tgname IN ('trg_social_alias_lifecycle_event_guard',"
                    "'trg_social_alias_lifecycle_event_no_truncate',"
                    "'trg_social_alias_lifecycle_event_invariant')"
                ),
                {"table": EVENT_TABLE},
            ).scalar_one()
            event_uniques = connection.execute(
                text(
                    "SELECT count(*) FROM pg_constraint "
                    "WHERE conrelid = to_regclass(:table) AND contype IN ('p', 'u') "
                    "AND conname IN ('pk_social_alias_lifecycle_event',"
                    "'uq_social_alias_lifecycle_event_nonce',"
                    "'uq_social_alias_lifecycle_event_successor_version',"
                    "'uq_social_alias_lifecycle_event_successor_commitment',"
                    "'uq_social_alias_lifecycle_event_command_wire')"
                ),
                {"table": EVENT_TABLE},
            ).scalar_one()
            active_singleton_indexes = connection.execute(
                text(
                    "SELECT count(*) FROM pg_index AS i "
                    "JOIN pg_class AS index_class ON index_class.oid = i.indexrelid "
                    "WHERE i.indrelid = to_regclass(:table) "
                    "AND index_class.relname = :index_name "
                    "AND i.indisunique AND i.indisvalid AND i.indisready "
                    "AND i.indpred IS NOT NULL"
                ),
                {
                    "table": namespace.NAMESPACE_TABLE,
                    "index_name": namespace._ACTIVE_INDEX,
                },
            ).scalar_one()
            if (
                namespace_triggers != _EXPECTED_NAMESPACE_TRIGGER_COUNT
                or event_triggers != _EXPECTED_EVENT_TRIGGER_COUNT
                or event_uniques != _EXPECTED_EVENT_UNIQUE_CONSTRAINT_COUNT
                or active_singleton_indexes != 1
            ):
                _deny()
            return connection
        except Exception:
            self._failed = True
        _deny()

    def _database_now_ms(self) -> int:
        try:
            value = (
                self._check_transaction()
                .execute(text("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint"))
                .scalar_one()
            )
            if type(value) is not int or not 0 <= value <= lifecycle.MAX_SAFE_INTEGER:
                _deny()
            return value
        except Exception:
            self._failed = True
        _deny()

    def _verify_fresh(self, command_wire: object, signature: object) -> dict[str, object]:
        return _command_values(
            self._verifier,
            command_wire,
            signature,
            now_ms=self._database_now_ms(),
            configured_version=self._configured_successor_alias_version,
            configured_commitment=self._configured_successor_commitment,
        )

    def _authenticate_for_reconciliation(
        self,
        command_wire: object,
        signature: object,
    ) -> dict[str, object]:
        """Authenticate history without turning an expired command into authority."""

        try:
            parsed = lifecycle.parse_canonical_alias_lifecycle_command_v1(command_wire)
            return _command_values(
                self._verifier,
                command_wire,
                signature,
                now_ms=cast(int, parsed["issuedAtMs"]),
                configured_version=self._configured_successor_alias_version,
                configured_commitment=self._configured_successor_commitment,
            )
        except Exception:
            pass
        _deny()

    def _lock_writer(self) -> None:
        self._check_transaction().execute(
            text("SELECT pg_advisory_xact_lock(:lock_key)"),
            {"lock_key": WRITER_ADVISORY_LOCK_KEY},
        ).scalar_one()

    def _lock_active_rows(self) -> list[Mapping[str, object]]:
        table = namespace.SocialMessagingActiveAliasNamespaceRow.__table__
        rows = (
            self._check_transaction()
            .execute(
                select(table)
                .where(table.c.lifecycle_state == namespace.ACTIVE_NAMESPACE_STATE)
                .with_for_update(of=table)
                .execution_options(autoflush=False)
            )
            .mappings()
            .all()
        )
        return [cast(Mapping[str, object], row) for row in rows]

    def _namespace_row(self, version: int) -> Mapping[str, object] | None:
        table = namespace.SocialMessagingActiveAliasNamespaceRow.__table__
        rows = (
            self._check_transaction()
            .execute(select(table).where(table.c.alias_version == version).execution_options(autoflush=False))
            .mappings()
            .all()
        )
        if len(rows) > 1:
            _deny()
        return None if not rows else cast(Mapping[str, object], rows[0])

    def _event_candidates(self, command: Mapping[str, object]) -> list[Mapping[str, object]]:
        table = SocialMessagingActiveAliasNamespaceLifecycleEventRow.__table__
        event_columns = [column for column in table.c if column.name != "staged_top_level_transaction_id"]
        statement = select(
            *event_columns,
            text("staged_top_level_transaction_id::text " "AS staged_top_level_transaction_id"),
        ).where(
            or_(
                table.c.command_id == command["commandId"],
                table.c.nonce == command["nonce"],
                table.c.successor_version == command["successorVersion"],
                table.c.successor_commitment == command["successorCommitment"],
                table.c.command_wire == cast(bytes, command["wire"]).decode("ascii"),
            )
        )
        return [
            cast(Mapping[str, object], row) for row in self._check_transaction().execute(statement).mappings().all()
        ]

    def _current_transaction_id(self) -> str:
        value = self._check_transaction().execute(text("SELECT pg_current_xact_id()::text")).scalar_one()
        if type(value) is not str or not value.isdigit():
            _deny()
        return value

    @staticmethod
    def _row_matches(
        row: Mapping[str, object] | None,
        *,
        version: object,
        commitment: object,
        states: tuple[str, ...],
    ) -> bool:
        return bool(
            row is not None
            and set(row) == set(namespace.SocialMessagingActiveAliasNamespaceRow.__table__.c.keys())
            and row["alias_version"] == version
            and type(row["alias_version"]) is int
            and row["secret_commitment"] == commitment
            and type(row["secret_commitment"]) is str
            and row["lifecycle_state"] in states
            and type(row["lifecycle_state"]) is str
        )

    @staticmethod
    def _event_matches(
        row: Mapping[str, object],
        command: Mapping[str, object],
        signature: str,
    ) -> bool:
        expected = _event_values(command, cast(bytes, command["wire"]), signature)
        return all(row.get(key) == value for key, value in expected.items())

    def _classify_locked(
        self,
        command: dict[str, object],
        signature: str,
        active_rows: list[Mapping[str, object]],
    ) -> str:
        candidates = self._event_candidates(command)
        successor = self._namespace_row(cast(int, command["successorVersion"]))
        if candidates:
            if (
                len(candidates) != 1
                or not self._event_matches(candidates[0], command, signature)
                or type(candidates[0].get("staged_top_level_transaction_id")) is not str
                or not cast(
                    str,
                    candidates[0]["staged_top_level_transaction_id"],
                ).isdigit()
                or candidates[0].get("staged_top_level_transaction_id") == self._current_transaction_id()
                or not self._row_matches(
                    successor,
                    version=command["successorVersion"],
                    commitment=command["successorCommitment"],
                    states=(
                        namespace.ACTIVE_NAMESPACE_STATE,
                        namespace.RETIRED_NAMESPACE_STATE,
                    ),
                )
            ):
                _deny()
            if command["action"] == "rotate":
                predecessor = self._namespace_row(cast(int, command["expectedVersion"]))
                if not self._row_matches(
                    predecessor,
                    version=command["expectedVersion"],
                    commitment=command["expectedCommitment"],
                    states=(namespace.RETIRED_NAMESPACE_STATE,),
                ):
                    _deny()
            if len(active_rows) != 1 or cast(int, active_rows[0]["alias_version"]) < cast(
                int, command["successorVersion"]
            ):
                _deny()
            return "committed"

        if successor is not None:
            _deny()
        namespace_table = namespace.SocialMessagingActiveAliasNamespaceRow.__table__
        event_table = SocialMessagingActiveAliasNamespaceLifecycleEventRow.__table__
        if command["action"] == "provision":
            namespace_count = (
                self._check_transaction().execute(select(func.count()).select_from(namespace_table)).scalar_one()
            )
            event_count = self._check_transaction().execute(select(func.count()).select_from(event_table)).scalar_one()
            if active_rows or namespace_count or event_count:
                _deny()
            return "absent"

        if len(active_rows) != 1 or not self._row_matches(
            active_rows[0],
            version=command["expectedVersion"],
            commitment=command["expectedCommitment"],
            states=(namespace.ACTIVE_NAMESPACE_STATE,),
        ):
            _deny()
        return "absent"

    def _stage(self, command: dict[str, object], signature: str) -> None:
        namespace_table = namespace.SocialMessagingActiveAliasNamespaceRow.__table__
        event_table = SocialMessagingActiveAliasNamespaceLifecycleEventRow.__table__
        if command["action"] == "rotate":
            changed = self._check_transaction().execute(
                update(namespace_table)
                .where(
                    namespace_table.c.alias_version == command["expectedVersion"],
                    namespace_table.c.secret_commitment == command["expectedCommitment"],
                    namespace_table.c.lifecycle_state == namespace.ACTIVE_NAMESPACE_STATE,
                )
                .values(lifecycle_state=namespace.RETIRED_NAMESPACE_STATE)
            )
            if changed.rowcount != 1:
                _deny()
        self._check_transaction().execute(
            insert(namespace_table).values(
                alias_version=command["successorVersion"],
                secret_commitment=command["successorCommitment"],
                lifecycle_state=namespace.ACTIVE_NAMESPACE_STATE,
            )
        )
        self._check_transaction().execute(
            insert(event_table).values(**_event_values(command, cast(bytes, command["wire"]), signature))
        )

    def _check_staged_state(self, command: dict[str, object], signature: str) -> None:
        active_rows = self._lock_active_rows()
        if len(active_rows) != 1 or not self._row_matches(
            active_rows[0],
            version=command["successorVersion"],
            commitment=command["successorCommitment"],
            states=(namespace.ACTIVE_NAMESPACE_STATE,),
        ):
            _deny()
        if command["action"] == "rotate" and not self._row_matches(
            self._namespace_row(cast(int, command["expectedVersion"])),
            version=command["expectedVersion"],
            commitment=command["expectedCommitment"],
            states=(namespace.RETIRED_NAMESPACE_STATE,),
        ):
            _deny()
        candidates = self._event_candidates(command)
        if (
            len(candidates) != 1
            or not self._event_matches(candidates[0], command, signature)
            or candidates[0].get("staged_top_level_transaction_id") != self._current_transaction_id()
        ):
            _deny()

    def execute(
        self,
        command_wire: bytes,
        signature: str,
    ) -> AliasNamespaceLifecycleResultV1:
        """Authenticate and stage one transition, or return exact committed history."""

        try:
            if self._failed or self._used:
                _deny()
            self._used = True
            command = self._verify_fresh(command_wire, signature)
            command["wire"] = command_wire

            self._lock_writer()
            command = self._verify_fresh(command_wire, signature)
            command["wire"] = command_wire
            active_rows = self._lock_active_rows()
            command = self._verify_fresh(command_wire, signature)
            command["wire"] = command_wire

            outcome = self._classify_locked(command, signature, active_rows)
            if outcome == "committed":
                return _result(command, outcome=outcome)

            self._stage(command, signature)
            command = self._verify_fresh(command_wire, signature)
            command["wire"] = command_wire
            self._check_staged_state(command, signature)
            return _result(command, outcome="staged")
        except Exception:
            self._failed = True
        _deny()

    def reconcile_uncertain_commit(
        self,
        command_wire: bytes,
        signature: str,
    ) -> AliasNamespaceLifecycleResultV1:
        """Classify exact durable evidence without executing an absent command."""

        try:
            if self._failed or self._used:
                _deny()
            self._used = True
            command = self._authenticate_for_reconciliation(command_wire, signature)
            command["wire"] = command_wire
            self._lock_writer()
            command = self._authenticate_for_reconciliation(command_wire, signature)
            command["wire"] = command_wire
            active_rows = self._lock_active_rows()
            outcome = self._classify_locked(command, signature, active_rows)
            return _result(command, outcome=outcome)
        except Exception:
            self._failed = True
        _deny()


__all__ = [
    "AliasNamespaceLifecycleResultV1",
    "AliasNamespaceLifecycleStorageUnavailable",
    "EVENT_TABLE",
    "PRIVATE_KEY_CUSTODY",
    "RUNTIME_ENABLED",
    "SocialMessagingActiveAliasNamespaceLifecycleEventRow",
    "SqlAlchemyTransactionBoundActiveAliasNamespaceLifecycleOwner",
    "TRANSACTION_OWNER",
    "UNAVAILABLE_MESSAGE",
    "WRITER_ADVISORY_LOCK_DOMAIN",
    "WRITER_ADVISORY_LOCK_KEY",
]
