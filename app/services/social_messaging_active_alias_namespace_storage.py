"""Dormant transaction-bound reader for the configured alias namespace.

The caller supplies one already-active PostgreSQL READ COMMITTED transaction
and the alias secret/version loaded from trusted startup configuration.  The
reader stores only a domain-separated commitment in memory, locks the one
explicitly ACTIVE registry row, and requires an exact version and commitment
match.  It has no writer, lifecycle owner, handle resolver, self-read grant,
transaction lifecycle, route, factory composition, or runtime wiring.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Mapping, NoReturn, cast

from sqlalchemy import Boolean, CheckConstraint, Column, Index, Integer, String, UniqueConstraint, select, text
from sqlalchemy.engine import Connection, NestedTransaction, RootTransaction
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import ColumnElement

from app.models import Base
from app.services.privacy_safe_full_directory import (
    MAX_ALIAS_SECRET_BYTES,
    MAX_ALIAS_VERSION,
    MIN_ALIAS_SECRET_BYTES,
)

NAMESPACE_TABLE = "social_messaging_active_alias_namespaces"
ACTIVE_NAMESPACE_STATE = "ACTIVE"
RETIRED_NAMESPACE_STATE = "RETIRED"
SECRET_COMMITMENT_DOMAIN = b"HODLXXI_SOCIAL_ACTIVE_ALIAS_NAMESPACE_SECRET_COMMITMENT_V1"
SECRET_COMMITMENT_PREFIX = "hodlxxi-social-active-alias-namespace-v1-sha256:"
SECRET_COMMITMENT_LENGTH = len(SECRET_COMMITMENT_PREFIX) + 64

RUNTIME_ENABLED = False
NAMESPACE_PROVISIONING = "not_implemented"
NAMESPACE_ROTATION = "not_implemented"
CURRENT_HANDLE_RESOLUTION = "not_implemented"
RECIPIENT_SELF_READ_AUTHORIZATION = "not_granted"

_COMMITMENT = re.compile(re.escape(SECRET_COMMITMENT_PREFIX) + r"[0-9a-f]{64}\Z").fullmatch
_ACTIVE_INDEX = "uq_social_active_alias_namespace_singleton"
_EXPECTED_TRIGGER_COUNT = 2


class ActiveAliasNamespaceUnavailable(RuntimeError):
    """The configured namespace cannot be reconciled with locked state."""

    def __init__(self) -> None:
        super().__init__("social messaging active alias namespace unavailable")


def _deny() -> NoReturn:
    raise ActiveAliasNamespaceUnavailable()


class _PostgreSQLCommitmentCheck(ColumnElement):
    """Keep the PostgreSQL regex inert in shared SQLite model metadata."""

    inherit_cache = False
    type = Boolean()


@compiles(_PostgreSQLCommitmentCheck)
@compiles(_PostgreSQLCommitmentCheck, "postgresql")
def _compile_postgresql_commitment_check(_element, _compiler, **_kwargs):
    return "secret_commitment ~ " "'^hodlxxi-social-active-alias-namespace-v1-sha256:[0-9a-f]{64}$'"


@compiles(_PostgreSQLCommitmentCheck, "sqlite")
def _compile_sqlite_commitment_check(_element, _compiler, **_kwargs):
    return "1"


class SocialMessagingActiveAliasNamespaceRow(Base):
    """One configured namespace generation and its explicit lifecycle state."""

    __tablename__ = NAMESPACE_TABLE

    alias_version = Column(Integer, primary_key=True)
    secret_commitment = Column(String(SECRET_COMMITMENT_LENGTH), nullable=False)
    lifecycle_state = Column(String(7), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "secret_commitment",
            name="uq_social_active_alias_namespace_commitment",
        ),
        CheckConstraint(
            f"alias_version BETWEEN 1 AND {MAX_ALIAS_VERSION}",
            name="ck_social_active_alias_namespace_version",
        ),
        CheckConstraint(
            _PostgreSQLCommitmentCheck(),
            name="ck_social_active_alias_namespace_commitment",
        ),
        CheckConstraint(
            "lifecycle_state IN ('ACTIVE', 'RETIRED')",
            name="ck_social_active_alias_namespace_state",
        ),
        Index(
            _ACTIVE_INDEX,
            "lifecycle_state",
            unique=True,
            postgresql_where=text("lifecycle_state = 'ACTIVE'"),
            sqlite_where=text("lifecycle_state = 'ACTIVE'"),
        ),
    )


@dataclass(frozen=True, slots=True, repr=False)
class LockedActiveAliasNamespaceV1:
    """Configuration-matched row evidence valid only in its held transaction."""

    alias_version: int
    secret_commitment: str
    lifecycle_state: str


def active_alias_namespace_secret_commitment(
    *,
    alias_secret: object,
    alias_version: object,
) -> str:
    """Commit to one configured secret/version without retaining the secret."""

    try:
        if (
            type(alias_secret) is not bytes
            or not MIN_ALIAS_SECRET_BYTES <= len(alias_secret) <= MAX_ALIAS_SECRET_BYTES
            or type(alias_version) is not int
            or not 1 <= alias_version <= MAX_ALIAS_VERSION
        ):
            raise ValueError
        preimage = b"\x00".join(
            (
                SECRET_COMMITMENT_DOMAIN,
                str(alias_version).encode("ascii"),
                alias_secret,
            )
        )
        return SECRET_COMMITMENT_PREFIX + hashlib.sha256(preimage).hexdigest()
    except Exception:
        raise ValueError("invalid active alias namespace configuration") from None


def parse_stored_active_alias_namespace_v1(
    row: Mapping[str, object],
) -> LockedActiveAliasNamespaceV1:
    """Parse one exact ACTIVE row without granting lifecycle authority."""

    try:
        if set(row) != set(SocialMessagingActiveAliasNamespaceRow.__table__.columns.keys()):
            _deny()
        namespace = LockedActiveAliasNamespaceV1(
            alias_version=cast(int, row["alias_version"]),
            secret_commitment=cast(str, row["secret_commitment"]),
            lifecycle_state=cast(str, row["lifecycle_state"]),
        )
        if (
            type(namespace.alias_version) is not int
            or not 1 <= namespace.alias_version <= MAX_ALIAS_VERSION
            or type(namespace.secret_commitment) is not str
            or _COMMITMENT(namespace.secret_commitment) is None
            or type(namespace.lifecycle_state) is not str
            or namespace.lifecycle_state != ACTIVE_NAMESPACE_STATE
        ):
            _deny()
        return namespace
    except ActiveAliasNamespaceUnavailable:
        raise
    except Exception:
        pass
    _deny()


class SqlAlchemyTransactionBoundActiveAliasNamespaceReader:
    """Lock and reconcile one ACTIVE namespace in a caller-owned transaction."""

    def __init__(
        self,
        session: Session,
        *,
        configured_alias_secret: bytes,
        configured_alias_version: int,
    ) -> None:
        self._session = session
        self._failed = False
        self._connection: Connection | None = None
        self._database_transaction: RootTransaction | None = None
        self._database_nested_transaction: NestedTransaction | None = None
        try:
            configured_commitment = active_alias_namespace_secret_commitment(
                alias_secret=configured_alias_secret,
                alias_version=configured_alias_version,
            )
            self._configured_alias_version = configured_alias_version
            self._configured_secret_commitment = configured_commitment
            self._transaction = session.get_transaction()
            self._nested_transaction = session.get_nested_transaction()
            self._check_transaction()
            return
        except Exception:
            pass
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
            installed_triggers = connection.execute(
                text(
                    "SELECT count(*) FROM pg_trigger "
                    "WHERE NOT tgisinternal AND tgenabled = 'O' "
                    "AND tgrelid = to_regclass(:namespace_table) "
                    "AND tgname IN ('trg_social_active_alias_namespace_guard',"
                    "'trg_social_active_alias_namespace_no_truncate')"
                ),
                {"namespace_table": NAMESPACE_TABLE},
            ).scalar_one()
            installed_index = connection.execute(
                text(
                    "SELECT count(*) FROM pg_index AS i "
                    "JOIN pg_class AS index_class ON index_class.oid = i.indexrelid "
                    "WHERE i.indrelid = to_regclass(:namespace_table) "
                    "AND index_class.relname = :index_name "
                    "AND i.indisunique AND i.indisvalid AND i.indisready "
                    "AND i.indpred IS NOT NULL"
                ),
                {
                    "namespace_table": NAMESPACE_TABLE,
                    "index_name": _ACTIVE_INDEX,
                },
            ).scalar_one()
            if installed_triggers != _EXPECTED_TRIGGER_COUNT or installed_index != 1:
                _deny()
            return connection
        except Exception:
            self._failed = True
        _deny()

    def lock_configured_active_namespace(self) -> LockedActiveAliasNamespaceV1:
        """Lock exactly one ACTIVE row and match the startup configuration."""

        try:
            table = SocialMessagingActiveAliasNamespaceRow.__table__
            statement = (
                select(table)
                .where(table.c.lifecycle_state == ACTIVE_NAMESPACE_STATE)
                .with_for_update(of=table)
                .execution_options(autoflush=False)
            )
            rows = self._check_transaction().execute(statement).mappings().all()
            if len(rows) != 1:
                _deny()
            namespace = parse_stored_active_alias_namespace_v1(cast(Mapping[str, object], rows[0]))
            if namespace.alias_version != self._configured_alias_version or not hmac.compare_digest(
                namespace.secret_commitment,
                self._configured_secret_commitment,
            ):
                _deny()
            self._check_transaction()
            return namespace
        except Exception:
            self._failed = True
        _deny()


__all__ = [
    "ACTIVE_NAMESPACE_STATE",
    "CURRENT_HANDLE_RESOLUTION",
    "LockedActiveAliasNamespaceV1",
    "NAMESPACE_PROVISIONING",
    "NAMESPACE_ROTATION",
    "NAMESPACE_TABLE",
    "RECIPIENT_SELF_READ_AUTHORIZATION",
    "RETIRED_NAMESPACE_STATE",
    "RUNTIME_ENABLED",
    "SECRET_COMMITMENT_DOMAIN",
    "SECRET_COMMITMENT_PREFIX",
    "ActiveAliasNamespaceUnavailable",
    "SocialMessagingActiveAliasNamespaceRow",
    "SqlAlchemyTransactionBoundActiveAliasNamespaceReader",
    "active_alias_namespace_secret_commitment",
    "parse_stored_active_alias_namespace_v1",
]
