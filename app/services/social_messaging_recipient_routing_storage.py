"""Dormant PostgreSQL owner for confidential recipient-routing evidence.

The caller supplies one already-active READ COMMITTED transaction.  This
adapter implements the existing ``RecipientRoutingRepository`` protocol and
retains the exact canonical snapshot and decision bytes.  It has no session
factory, URL, clock, network call, transaction lifecycle, request admission,
ciphertext store, self-read grant, route, or runtime wiring.

Future request composition must acquire the challenge and current-admission
authority locks before calling this adapter.  Its local order is sorted handle
owners, snapshot, then message ID.  Handle owners are immutable historical
routing evidence only.  This adapter has no active alias-namespace authority,
current-handle resolver, or self-read authority.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Mapping, NoReturn, Sequence, cast

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    ForeignKeyConstraint,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    insert,
    select,
    text,
)
from sqlalchemy.engine import Connection, NestedTransaction, RootTransaction
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import ColumnElement

from app.models import Base, _CanonicalLowerHex
from app.services import social_messaging_recipient_routing as routing
from app.services.privacy_safe_full_directory import MAX_ALIAS_VERSION
from app.services.social_messaging_device_contract import MAX_ACTIVE_DEVICES, MAX_BINDING_VERSION

HANDLE_TABLE = "social_messaging_recipient_handle_owners"
SNAPSHOT_TABLE = "social_messaging_recipient_routing_snapshots"
SNAPSHOT_ROUTE_TABLE = "social_messaging_recipient_routing_snapshot_routes"
DECISION_TABLE = "social_messaging_recipient_routing_decisions"
DECISION_ROUTE_TABLE = "social_messaging_recipient_routing_decision_routes"

RUNTIME_ENABLED = False
CIPHERTEXT_PERSISTENCE = "not_implemented"
RECIPIENT_SELF_READ = "not_granted"
REQUEST_ADMISSION = "not_implemented"
RECEIPT_ISSUANCE = "not_implemented"
CHALLENGE_CONSUMPTION = "not_implemented"

_HANDLE_LOCK_SEED = 7_143_011_001
_SNAPSHOT_LOCK_SEED = 7_143_011_002
_MESSAGE_LOCK_SEED = 7_143_011_003
_EXPECTED_TRIGGER_COUNT = 15


def _deny() -> NoReturn:
    raise routing.RecipientMessagingRoutingUnavailable()


class _PostgreSQLRoutingCheck(ColumnElement):
    """Keep PostgreSQL byte/regex checks inert in shared SQLite metadata."""

    inherit_cache = False
    type = Boolean()

    def __init__(self, expression: str) -> None:
        self.postgresql_sql = expression


@compiles(_PostgreSQLRoutingCheck)
@compiles(_PostgreSQLRoutingCheck, "postgresql")
def _compile_postgresql_routing_check(element, _compiler, **_kwargs):
    return element.postgresql_sql


@compiles(_PostgreSQLRoutingCheck, "sqlite")
def _compile_sqlite_routing_metadata_check(_element, _compiler, **_kwargs):
    return "1"


class RecipientRoutingHandleOwnerRow(Base):
    """Immutable owner of one globally unambiguous pairwise handle."""

    __tablename__ = HANDLE_TABLE

    device_handle = Column(String(24), primary_key=True)
    viewer_subject = Column(String(64), nullable=False)
    recipient_subject = Column(String(64), nullable=False)
    alias_version = Column(Integer, nullable=False)
    device_id = Column(String(64), nullable=False)
    binding_id = Column(String(64), nullable=False)
    binding_version = Column(Integer, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "alias_version",
            "viewer_subject",
            "recipient_subject",
            "device_id",
            "binding_id",
            "binding_version",
            name="uq_social_routing_handle_owner_namespace",
        ),
        CheckConstraint(
            _PostgreSQLRoutingCheck("device_handle ~ '^d_[A-Za-z0-9_-]{21}[AQgw]$'"),
            name="ck_social_routing_handle_value",
        ),
        CheckConstraint(_CanonicalLowerHex("viewer_subject", 64), name="ck_social_routing_handle_viewer"),
        CheckConstraint(
            _CanonicalLowerHex("recipient_subject", 64),
            name="ck_social_routing_handle_recipient",
        ),
        CheckConstraint("viewer_subject <> recipient_subject", name="ck_social_routing_handle_pair"),
        CheckConstraint(
            f"alias_version BETWEEN 1 AND {MAX_ALIAS_VERSION}",
            name="ck_social_routing_handle_alias_version",
        ),
        CheckConstraint(_CanonicalLowerHex("device_id", 64), name="ck_social_routing_handle_device"),
        CheckConstraint(_CanonicalLowerHex("binding_id", 64), name="ck_social_routing_handle_binding"),
        CheckConstraint(
            f"binding_version BETWEEN 1 AND {MAX_BINDING_VERSION}",
            name="ck_social_routing_handle_binding_version",
        ),
    )


class RecipientRoutingSnapshotRow(Base):
    """Exact immutable canonical snapshot bytes plus indexed owner facts."""

    __tablename__ = SNAPSHOT_TABLE

    snapshot_id = Column(String(71), primary_key=True)
    viewer_subject = Column(String(64), nullable=False)
    recipient_subject = Column(String(64), nullable=False)
    alias_version = Column(Integer, nullable=False)
    issued_at = Column(BigInteger, nullable=False)
    expires_at = Column(BigInteger, nullable=False)
    route_count = Column(SmallInteger, nullable=False)
    snapshot_wire = Column(Text, nullable=False)

    __table_args__ = (
        CheckConstraint(
            _PostgreSQLRoutingCheck("snapshot_id ~ '^sha256:[0-9a-f]{64}$'"),
            name="ck_social_routing_snapshot_id",
        ),
        CheckConstraint(_CanonicalLowerHex("viewer_subject", 64), name="ck_social_routing_snapshot_viewer"),
        CheckConstraint(
            _CanonicalLowerHex("recipient_subject", 64),
            name="ck_social_routing_snapshot_recipient",
        ),
        CheckConstraint("viewer_subject <> recipient_subject", name="ck_social_routing_snapshot_pair"),
        CheckConstraint(
            f"alias_version BETWEEN 1 AND {MAX_ALIAS_VERSION}",
            name="ck_social_routing_snapshot_alias_version",
        ),
        CheckConstraint(
            "issued_at BETWEEN 0 AND 9007199254740991",
            name="ck_social_routing_snapshot_issued_at",
        ),
        CheckConstraint(
            "expires_at BETWEEN 1 AND 9007199254740991 AND "
            "issued_at < expires_at AND expires_at - issued_at <= 300000",
            name="ck_social_routing_snapshot_expires_at",
        ),
        CheckConstraint(
            f"route_count BETWEEN 1 AND {MAX_ACTIVE_DEVICES}",
            name="ck_social_routing_snapshot_route_count",
        ),
        CheckConstraint(
            _PostgreSQLRoutingCheck("octet_length(snapshot_wire) BETWEEN 1 AND 16384 AND snapshot_wire !~ '[^ -~]'"),
            name="ck_social_routing_snapshot_wire",
        ),
    )


class RecipientRoutingSnapshotRouteRow(Base):
    """Complete ordered route membership for one immutable snapshot."""

    __tablename__ = SNAPSHOT_ROUTE_TABLE

    snapshot_id = Column(String(71), primary_key=True)
    route_ordinal = Column(SmallInteger, primary_key=True)
    device_handle = Column(String(24), nullable=False)
    device_id = Column(String(64), nullable=False)
    binding_id = Column(String(64), nullable=False)
    binding_version = Column(Integer, nullable=False)
    authorization_proof_id = Column(String(111), nullable=False)
    authorization_valid_from = Column(BigInteger, nullable=False)
    authorization_expires_at = Column(BigInteger, nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ("snapshot_id",),
            (f"{SNAPSHOT_TABLE}.snapshot_id",),
            name="fk_social_routing_snapshot_route_snapshot",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ("device_handle",),
            (f"{HANDLE_TABLE}.device_handle",),
            name="fk_social_routing_snapshot_route_handle",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint("snapshot_id", "device_handle", name="uq_social_routing_snapshot_route_handle"),
        UniqueConstraint("snapshot_id", "device_id", name="uq_social_routing_snapshot_route_device"),
        UniqueConstraint("snapshot_id", "binding_id", name="uq_social_routing_snapshot_route_binding"),
        UniqueConstraint(
            "snapshot_id",
            "authorization_proof_id",
            name="uq_social_routing_snapshot_route_proof",
        ),
        CheckConstraint(
            f"route_ordinal BETWEEN 1 AND {MAX_ACTIVE_DEVICES}",
            name="ck_social_routing_snapshot_route_ordinal",
        ),
        CheckConstraint(
            _PostgreSQLRoutingCheck("device_handle ~ '^d_[A-Za-z0-9_-]{21}[AQgw]$'"),
            name="ck_social_routing_snapshot_route_handle",
        ),
        CheckConstraint(_CanonicalLowerHex("device_id", 64), name="ck_social_routing_snapshot_route_device"),
        CheckConstraint(_CanonicalLowerHex("binding_id", 64), name="ck_social_routing_snapshot_route_binding"),
        CheckConstraint(
            f"binding_version BETWEEN 1 AND {MAX_BINDING_VERSION}",
            name="ck_social_routing_snapshot_route_binding_version",
        ),
        CheckConstraint(
            _PostgreSQLRoutingCheck(
                "authorization_proof_id ~ " "'^hodlxxi-(mobile-)?binding-authorization-v1-sha256:[0-9a-f]{64}$'"
            ),
            name="ck_social_routing_snapshot_route_proof",
        ),
        CheckConstraint(
            "authorization_valid_from BETWEEN 0 AND 9007199254740991",
            name="ck_social_routing_snapshot_route_valid_from",
        ),
        CheckConstraint(
            "authorization_expires_at BETWEEN 1 AND 9007199254740991 AND "
            "authorization_valid_from < authorization_expires_at",
            name="ck_social_routing_snapshot_route_expires_at",
        ),
    )


class RecipientRoutingDecisionRow(Base):
    """Immutable global message-ID decision ledger row."""

    __tablename__ = DECISION_TABLE

    message_id = Column(String(45), primary_key=True)
    envelope_digest = Column(String(106), nullable=False)
    snapshot_id = Column(String(71), nullable=False)
    viewer_subject = Column(String(64), nullable=False)
    recipient_subject = Column(String(64), nullable=False)
    expires_at = Column(BigInteger, nullable=False)
    route_count = Column(SmallInteger, nullable=False)
    decision_wire = Column(Text, nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ("snapshot_id",),
            (f"{SNAPSHOT_TABLE}.snapshot_id",),
            name="fk_social_routing_decision_snapshot",
            deferrable=True,
            initially="DEFERRED",
        ),
        CheckConstraint(
            _PostgreSQLRoutingCheck("message_id ~ '^m_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$'"),
            name="ck_social_routing_decision_message",
        ),
        CheckConstraint(
            _PostgreSQLRoutingCheck("envelope_digest ~ " "'^hodlxxi-social-message-envelope-v1-sha256:[0-9a-f]{64}$'"),
            name="ck_social_routing_decision_envelope",
        ),
        CheckConstraint(
            _PostgreSQLRoutingCheck("snapshot_id ~ '^sha256:[0-9a-f]{64}$'"),
            name="ck_social_routing_decision_snapshot",
        ),
        CheckConstraint(_CanonicalLowerHex("viewer_subject", 64), name="ck_social_routing_decision_viewer"),
        CheckConstraint(
            _CanonicalLowerHex("recipient_subject", 64),
            name="ck_social_routing_decision_recipient",
        ),
        CheckConstraint("viewer_subject <> recipient_subject", name="ck_social_routing_decision_pair"),
        CheckConstraint(
            "expires_at BETWEEN 1 AND 9007199254740991",
            name="ck_social_routing_decision_expires_at",
        ),
        CheckConstraint(
            f"route_count BETWEEN 1 AND {MAX_ACTIVE_DEVICES}",
            name="ck_social_routing_decision_route_count",
        ),
        CheckConstraint(
            _PostgreSQLRoutingCheck("octet_length(decision_wire) BETWEEN 1 AND 8192 AND decision_wire !~ '[^ -~]'"),
            name="ck_social_routing_decision_wire",
        ),
    )


class RecipientRoutingDecisionRouteRow(Base):
    """Complete ordered route membership copied into one decision."""

    __tablename__ = DECISION_ROUTE_TABLE

    message_id = Column(String(45), primary_key=True)
    route_ordinal = Column(SmallInteger, primary_key=True)
    device_handle = Column(String(24), nullable=False)
    device_id = Column(String(64), nullable=False)
    binding_id = Column(String(64), nullable=False)
    binding_version = Column(Integer, nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ("message_id",),
            (f"{DECISION_TABLE}.message_id",),
            name="fk_social_routing_decision_route_decision",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ("device_handle",),
            (f"{HANDLE_TABLE}.device_handle",),
            name="fk_social_routing_decision_route_handle",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint("message_id", "device_handle", name="uq_social_routing_decision_route_handle"),
        UniqueConstraint("message_id", "device_id", name="uq_social_routing_decision_route_device"),
        UniqueConstraint("message_id", "binding_id", name="uq_social_routing_decision_route_binding"),
        CheckConstraint(
            f"route_ordinal BETWEEN 1 AND {MAX_ACTIVE_DEVICES}",
            name="ck_social_routing_decision_route_ordinal",
        ),
        CheckConstraint(
            _PostgreSQLRoutingCheck("device_handle ~ '^d_[A-Za-z0-9_-]{21}[AQgw]$'"),
            name="ck_social_routing_decision_route_handle",
        ),
        CheckConstraint(_CanonicalLowerHex("device_id", 64), name="ck_social_routing_decision_route_device"),
        CheckConstraint(_CanonicalLowerHex("binding_id", 64), name="ck_social_routing_decision_route_binding"),
        CheckConstraint(
            f"binding_version BETWEEN 1 AND {MAX_BINDING_VERSION}",
            name="ck_social_routing_decision_route_binding_version",
        ),
    )


@dataclass(frozen=True, slots=True, repr=False)
class _RecipientHandleOwnerV1:
    device_handle: str
    viewer_subject: str
    recipient_subject: str
    alias_version: int
    device_id: str
    binding_id: str
    binding_version: int


def _closed_ascii_json(value: object, *, maximum: int) -> dict[str, object]:
    if type(value) is not str or not 1 <= len(value) <= maximum:
        _deny()
    wire = cast(str, value)
    if any(not 0x20 <= ord(character) <= 0x7E for character in wire):
        _deny()

    def pairs(items):
        result = {}
        for key, item in items:
            if type(key) is not str or key in result:
                _deny()
            result[key] = item
        return result

    try:
        parsed = json.loads(wire, object_pairs_hook=pairs)
    except Exception:
        _deny()
    if type(parsed) is not dict:
        _deny()
    return cast(dict[str, object], parsed)


def _parse_snapshot_wire(value: object) -> routing.RecipientRoutingSnapshot:
    try:
        data = _closed_ascii_json(value, maximum=routing.MAX_INTERNAL_SNAPSHOT_BYTES)
        if set(data) != {
            "aliasVersion",
            "complete",
            "expiresAt",
            "issuedAt",
            "recipientPackageSnapshotId",
            "recipientSubject",
            "routes",
            "schema",
            "source",
            "version",
            "viewerSubject",
        }:
            _deny()
        raw_routes = data["routes"]
        if type(raw_routes) is not list:
            _deny()
        routes = []
        for raw in raw_routes:
            if type(raw) is not dict or set(raw) != {
                "authorizationExpiresAt",
                "authorizationProofId",
                "authorizationValidFrom",
                "bindingId",
                "bindingVersion",
                "deviceHandle",
                "deviceId",
            }:
                _deny()
            routes.append(
                routing.RecipientRoutingSnapshotRoute(
                    device_handle=raw["deviceHandle"],
                    device_id=raw["deviceId"],
                    binding_id=raw["bindingId"],
                    binding_version=raw["bindingVersion"],
                    authorization_proof_id=raw["authorizationProofId"],
                    authorization_valid_from=raw["authorizationValidFrom"],
                    authorization_expires_at=raw["authorizationExpiresAt"],
                )
            )
        snapshot = routing.RecipientRoutingSnapshot(
            schema=cast(str, data["schema"]),
            version=cast(int, data["version"]),
            source=cast(str, data["source"]),
            viewer_subject=cast(str, data["viewerSubject"]),
            recipient_subject=cast(str, data["recipientSubject"]),
            alias_version=cast(int, data["aliasVersion"]),
            recipient_package_snapshot_id=cast(str, data["recipientPackageSnapshotId"]),
            issued_at=cast(int, data["issuedAt"]),
            expires_at=cast(int, data["expiresAt"]),
            complete=cast(bool, data["complete"]),
            routes=tuple(routes),
        )
        if routing.canonical_routing_snapshot_bytes(snapshot).decode("ascii") != value:
            _deny()
        return snapshot
    except Exception:
        pass
    _deny()


def _parse_decision_wire(value: object) -> routing.RecipientRoutingDecision:
    try:
        data = _closed_ascii_json(value, maximum=routing.MAX_INTERNAL_DECISION_BYTES)
        if set(data) != {
            "complete",
            "envelopeDigest",
            "expiresAt",
            "messageId",
            "recipientPackageSnapshotId",
            "recipientSubject",
            "routes",
            "schema",
            "source",
            "version",
            "viewerSubject",
        }:
            _deny()
        raw_routes = data["routes"]
        if type(raw_routes) is not list:
            _deny()
        routes = []
        for raw in raw_routes:
            if type(raw) is not dict or set(raw) != {
                "bindingId",
                "bindingVersion",
                "deviceHandle",
                "deviceId",
            }:
                _deny()
            routes.append(
                routing.RecipientRoutingDecisionRoute(
                    device_handle=raw["deviceHandle"],
                    device_id=raw["deviceId"],
                    binding_id=raw["bindingId"],
                    binding_version=raw["bindingVersion"],
                )
            )
        decision = routing.RecipientRoutingDecision(
            schema=cast(str, data["schema"]),
            version=cast(int, data["version"]),
            source=cast(str, data["source"]),
            message_id=cast(str, data["messageId"]),
            envelope_digest=cast(str, data["envelopeDigest"]),
            recipient_package_snapshot_id=cast(str, data["recipientPackageSnapshotId"]),
            viewer_subject=cast(str, data["viewerSubject"]),
            recipient_subject=cast(str, data["recipientSubject"]),
            complete=cast(bool, data["complete"]),
            expires_at=cast(int, data["expiresAt"]),
            routes=tuple(routes),
        )
        if routing.canonical_routing_decision_bytes(decision).decode("ascii") != value:
            _deny()
        return decision
    except Exception:
        pass
    _deny()


def _parse_owner(row: Mapping[str, object]) -> _RecipientHandleOwnerV1:
    try:
        if set(row) != set(RecipientRoutingHandleOwnerRow.__table__.columns.keys()):
            _deny()
        owner = _RecipientHandleOwnerV1(
            device_handle=routing._canonical_token(row["device_handle"], prefix="d_", characters=22, decoded=16),
            viewer_subject=routing._canonical_subject(row["viewer_subject"]),
            recipient_subject=routing._canonical_subject(row["recipient_subject"]),
            alias_version=cast(int, row["alias_version"]),
            device_id=routing._hex64(row["device_id"]),
            binding_id=routing._hex64(row["binding_id"]),
            binding_version=cast(int, row["binding_version"]),
        )
        if (
            owner.viewer_subject == owner.recipient_subject
            or type(owner.alias_version) is not int
            or not 1 <= owner.alias_version <= MAX_ALIAS_VERSION
            or type(owner.binding_version) is not int
            or not 1 <= owner.binding_version <= MAX_BINDING_VERSION
        ):
            _deny()
        return owner
    except Exception:
        pass
    _deny()


def _expected_owner(
    snapshot: routing.RecipientRoutingSnapshot,
    route: routing.RecipientRoutingSnapshotRoute,
) -> _RecipientHandleOwnerV1:
    return _RecipientHandleOwnerV1(
        device_handle=route.device_handle,
        viewer_subject=snapshot.viewer_subject,
        recipient_subject=snapshot.recipient_subject,
        alias_version=snapshot.alias_version,
        device_id=route.device_id,
        binding_id=route.binding_id,
        binding_version=route.binding_version,
    )


def parse_stored_routing_snapshot_v1(
    row: Mapping[str, object], route_rows: Sequence[Mapping[str, object]]
) -> routing.RecipientRoutingSnapshot:
    """Reparse exact snapshot bytes and reject incomplete or divergent rows."""

    try:
        if set(row) != set(RecipientRoutingSnapshotRow.__table__.columns.keys()):
            _deny()
        snapshot = _parse_snapshot_wire(row["snapshot_wire"])
        if (
            row["snapshot_id"] != snapshot.recipient_package_snapshot_id
            or row["viewer_subject"] != snapshot.viewer_subject
            or row["recipient_subject"] != snapshot.recipient_subject
            or row["alias_version"] != snapshot.alias_version
            or row["issued_at"] != snapshot.issued_at
            or row["expires_at"] != snapshot.expires_at
            or row["route_count"] != len(snapshot.routes)
            or len(route_rows) != len(snapshot.routes)
        ):
            _deny()
        expected_columns = set(RecipientRoutingSnapshotRouteRow.__table__.columns.keys())
        for ordinal, (stored, route) in enumerate(zip(route_rows, snapshot.routes), start=1):
            if set(stored) != expected_columns or stored != {
                "snapshot_id": snapshot.recipient_package_snapshot_id,
                "route_ordinal": ordinal,
                "device_handle": route.device_handle,
                "device_id": route.device_id,
                "binding_id": route.binding_id,
                "binding_version": route.binding_version,
                "authorization_proof_id": route.authorization_proof_id,
                "authorization_valid_from": route.authorization_valid_from,
                "authorization_expires_at": route.authorization_expires_at,
            }:
                _deny()
        return snapshot
    except Exception:
        pass
    _deny()


def parse_stored_routing_decision_v1(
    row: Mapping[str, object], route_rows: Sequence[Mapping[str, object]]
) -> routing.RecipientRoutingDecision:
    """Reparse exact decision bytes and reject incomplete or divergent rows."""

    try:
        if set(row) != set(RecipientRoutingDecisionRow.__table__.columns.keys()):
            _deny()
        decision = _parse_decision_wire(row["decision_wire"])
        if (
            row["message_id"] != decision.message_id
            or row["envelope_digest"] != decision.envelope_digest
            or row["snapshot_id"] != decision.recipient_package_snapshot_id
            or row["viewer_subject"] != decision.viewer_subject
            or row["recipient_subject"] != decision.recipient_subject
            or row["expires_at"] != decision.expires_at
            or row["route_count"] != len(decision.routes)
            or len(route_rows) != len(decision.routes)
        ):
            _deny()
        expected_columns = set(RecipientRoutingDecisionRouteRow.__table__.columns.keys())
        for ordinal, (stored, route) in enumerate(zip(route_rows, decision.routes), start=1):
            if set(stored) != expected_columns or stored != {
                "message_id": decision.message_id,
                "route_ordinal": ordinal,
                "device_handle": route.device_handle,
                "device_id": route.device_id,
                "binding_id": route.binding_id,
                "binding_version": route.binding_version,
            }:
                _deny()
        return decision
    except Exception:
        pass
    _deny()


def _decision_matches_snapshot(
    decision: routing.RecipientRoutingDecision,
    snapshot: routing.RecipientRoutingSnapshot,
) -> bool:
    return (
        decision.recipient_package_snapshot_id == snapshot.recipient_package_snapshot_id
        and decision.viewer_subject == snapshot.viewer_subject
        and decision.recipient_subject == snapshot.recipient_subject
        and decision.expires_at == snapshot.expires_at
        and decision.routes
        == tuple(
            routing.RecipientRoutingDecisionRoute(
                device_handle=route.device_handle,
                device_id=route.device_id,
                binding_id=route.binding_id,
                binding_version=route.binding_version,
            )
            for route in snapshot.routes
        )
    )


class SqlAlchemyRecipientRoutingRepository:
    """Protocol adapter pinned to one caller-owned PostgreSQL transaction."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._failed = False
        self._connection: Connection | None = None
        self._database_transaction: RootTransaction | None = None
        self._database_nested_transaction: NestedTransaction | None = None
        try:
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
            installed = connection.execute(
                text(
                    "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled = 'O' AND ("
                    "(tgrelid = to_regclass(:handles) AND tgname IN "
                    "('trg_social_routing_handle_guard','trg_social_routing_handle_no_truncate',"
                    "'trg_social_routing_handle_atomic')) OR "
                    "(tgrelid = to_regclass(:snapshots) AND tgname IN "
                    "('trg_social_routing_snapshot_guard','trg_social_routing_snapshot_no_truncate',"
                    "'trg_social_routing_snapshot_atomic')) OR "
                    "(tgrelid = to_regclass(:snapshot_routes) AND tgname IN "
                    "('trg_social_routing_snapshot_route_guard',"
                    "'trg_social_routing_snapshot_route_no_truncate',"
                    "'trg_social_routing_snapshot_route_atomic')) OR "
                    "(tgrelid = to_regclass(:decisions) AND tgname IN "
                    "('trg_social_routing_decision_guard','trg_social_routing_decision_no_truncate',"
                    "'trg_social_routing_decision_atomic')) OR "
                    "(tgrelid = to_regclass(:decision_routes) AND tgname IN "
                    "('trg_social_routing_decision_route_guard',"
                    "'trg_social_routing_decision_route_no_truncate',"
                    "'trg_social_routing_decision_route_atomic')))"
                ),
                {
                    "handles": HANDLE_TABLE,
                    "snapshots": SNAPSHOT_TABLE,
                    "snapshot_routes": SNAPSHOT_ROUTE_TABLE,
                    "decisions": DECISION_TABLE,
                    "decision_routes": DECISION_ROUTE_TABLE,
                },
            ).scalar_one()
            if installed != _EXPECTED_TRIGGER_COUNT:
                _deny()
            return connection
        except Exception:
            self._failed = True
        _deny()

    def _advisory_lock(self, seed: int, value: str) -> None:
        connection = self._check_transaction()
        connection.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_value, :lock_seed))"),
            {"lock_value": value, "lock_seed": seed},
        )

    def _select_owner(self, device_handle: str, *, lock: bool) -> _RecipientHandleOwnerV1 | None:
        table = RecipientRoutingHandleOwnerRow.__table__
        statement = select(table).where(table.c.device_handle == device_handle).execution_options(autoflush=False)
        if lock:
            statement = statement.with_for_update(of=table)
        rows = self._check_transaction().execute(statement).mappings().all()
        if len(rows) > 1:
            _deny()
        return None if not rows else _parse_owner(cast(Mapping[str, object], rows[0]))

    def _load_snapshot(self, snapshot_id: str, *, lock: bool) -> routing.RecipientRoutingSnapshot | None:
        snapshot_table = RecipientRoutingSnapshotRow.__table__
        statement = (
            select(snapshot_table).where(snapshot_table.c.snapshot_id == snapshot_id).execution_options(autoflush=False)
        )
        if lock:
            statement = statement.with_for_update(of=snapshot_table)
        rows = self._check_transaction().execute(statement).mappings().all()
        if len(rows) > 1:
            _deny()
        if not rows:
            return None
        route_table = RecipientRoutingSnapshotRouteRow.__table__
        route_rows = (
            self._check_transaction()
            .execute(
                select(route_table)
                .where(route_table.c.snapshot_id == snapshot_id)
                .order_by(route_table.c.route_ordinal)
                .execution_options(autoflush=False)
            )
            .mappings()
            .all()
        )
        snapshot = parse_stored_routing_snapshot_v1(
            cast(Mapping[str, object], rows[0]),
            cast(Sequence[Mapping[str, object]], route_rows),
        )
        for route in snapshot.routes:
            owner = self._select_owner(route.device_handle, lock=False)
            if owner != _expected_owner(snapshot, route):
                _deny()
        return snapshot

    def _load_decision(self, message_id: str, *, lock: bool) -> routing.RecipientRoutingDecision | None:
        decision_table = RecipientRoutingDecisionRow.__table__
        statement = (
            select(decision_table).where(decision_table.c.message_id == message_id).execution_options(autoflush=False)
        )
        if lock:
            statement = statement.with_for_update(of=decision_table)
        rows = self._check_transaction().execute(statement).mappings().all()
        if len(rows) > 1:
            _deny()
        if not rows:
            return None
        route_table = RecipientRoutingDecisionRouteRow.__table__
        route_rows = (
            self._check_transaction()
            .execute(
                select(route_table)
                .where(route_table.c.message_id == message_id)
                .order_by(route_table.c.route_ordinal)
                .execution_options(autoflush=False)
            )
            .mappings()
            .all()
        )
        return parse_stored_routing_decision_v1(
            cast(Mapping[str, object], rows[0]),
            cast(Sequence[Mapping[str, object]], route_rows),
        )

    def retain_snapshot(self, snapshot: routing.RecipientRoutingSnapshot) -> routing.RecipientRoutingSnapshot:
        """Retain exact bytes and permanent handle owners, idempotently."""

        try:
            snapshot_wire = routing.canonical_routing_snapshot_bytes(snapshot).decode("ascii")
            snapshot = _parse_snapshot_wire(snapshot_wire)
            expected_owners = sorted(
                (_expected_owner(snapshot, route) for route in snapshot.routes),
                key=lambda owner: owner.device_handle,
            )
            owner_table = RecipientRoutingHandleOwnerRow.__table__
            for expected in expected_owners:
                self._advisory_lock(_HANDLE_LOCK_SEED, expected.device_handle)
                owner = self._select_owner(expected.device_handle, lock=True)
                if owner is None:
                    row = (
                        self._check_transaction()
                        .execute(
                            insert(owner_table)
                            .values(
                                device_handle=expected.device_handle,
                                viewer_subject=expected.viewer_subject,
                                recipient_subject=expected.recipient_subject,
                                alias_version=expected.alias_version,
                                device_id=expected.device_id,
                                binding_id=expected.binding_id,
                                binding_version=expected.binding_version,
                            )
                            .returning(*owner_table.c)
                            .execution_options(autoflush=False)
                        )
                        .mappings()
                        .one()
                    )
                    owner = _parse_owner(cast(Mapping[str, object], row))
                if owner != expected:
                    _deny()

            snapshot_id = snapshot.recipient_package_snapshot_id
            self._advisory_lock(_SNAPSHOT_LOCK_SEED, snapshot_id)
            existing = self._load_snapshot(snapshot_id, lock=True)
            if existing is not None:
                if existing != snapshot:
                    _deny()
                return existing

            snapshot_table = RecipientRoutingSnapshotRow.__table__
            self._check_transaction().execute(
                insert(snapshot_table)
                .values(
                    snapshot_id=snapshot_id,
                    viewer_subject=snapshot.viewer_subject,
                    recipient_subject=snapshot.recipient_subject,
                    alias_version=snapshot.alias_version,
                    issued_at=snapshot.issued_at,
                    expires_at=snapshot.expires_at,
                    route_count=len(snapshot.routes),
                    snapshot_wire=snapshot_wire,
                )
                .execution_options(autoflush=False)
            )
            route_table = RecipientRoutingSnapshotRouteRow.__table__
            for ordinal, route in enumerate(snapshot.routes, start=1):
                self._check_transaction().execute(
                    insert(route_table)
                    .values(
                        snapshot_id=snapshot_id,
                        route_ordinal=ordinal,
                        device_handle=route.device_handle,
                        device_id=route.device_id,
                        binding_id=route.binding_id,
                        binding_version=route.binding_version,
                        authorization_proof_id=route.authorization_proof_id,
                        authorization_valid_from=route.authorization_valid_from,
                        authorization_expires_at=route.authorization_expires_at,
                    )
                    .execution_options(autoflush=False)
                )
            retained = self._load_snapshot(snapshot_id, lock=True)
            if retained != snapshot:
                _deny()
            return cast(routing.RecipientRoutingSnapshot, retained)
        except Exception:
            self._failed = True
        _deny()

    def read_snapshot(self, snapshot_id: str) -> routing.RecipientRoutingSnapshot | None:
        """Read exact immutable history; unknown IDs return ``None``."""

        try:
            key = routing._SNAPSHOT_ID(snapshot_id) and snapshot_id
            if type(key) is not str:
                _deny()
            return self._load_snapshot(key, lock=False)
        except Exception:
            self._failed = True
        _deny()

    def record_decision(self, decision: routing.RecipientRoutingDecision) -> routing.RecipientRoutingDecision:
        """Record one exact global message-ID/digest decision idempotently."""

        try:
            decision_wire = routing.canonical_routing_decision_bytes(decision).decode("ascii")
            decision = _parse_decision_wire(decision_wire)
            snapshot_id = decision.recipient_package_snapshot_id
            self._advisory_lock(_SNAPSHOT_LOCK_SEED, snapshot_id)
            snapshot = self._load_snapshot(snapshot_id, lock=True)
            if snapshot is None or not _decision_matches_snapshot(decision, snapshot):
                _deny()

            self._advisory_lock(_MESSAGE_LOCK_SEED, decision.message_id)
            existing = self._load_decision(decision.message_id, lock=True)
            if existing is not None:
                if existing.envelope_digest != decision.envelope_digest or existing != decision:
                    _deny()
                return existing

            decision_table = RecipientRoutingDecisionRow.__table__
            self._check_transaction().execute(
                insert(decision_table)
                .values(
                    message_id=decision.message_id,
                    envelope_digest=decision.envelope_digest,
                    snapshot_id=snapshot_id,
                    viewer_subject=decision.viewer_subject,
                    recipient_subject=decision.recipient_subject,
                    expires_at=decision.expires_at,
                    route_count=len(decision.routes),
                    decision_wire=decision_wire,
                )
                .execution_options(autoflush=False)
            )
            route_table = RecipientRoutingDecisionRouteRow.__table__
            for ordinal, route in enumerate(decision.routes, start=1):
                self._check_transaction().execute(
                    insert(route_table)
                    .values(
                        message_id=decision.message_id,
                        route_ordinal=ordinal,
                        device_handle=route.device_handle,
                        device_id=route.device_id,
                        binding_id=route.binding_id,
                        binding_version=route.binding_version,
                    )
                    .execution_options(autoflush=False)
                )
            recorded = self._load_decision(decision.message_id, lock=True)
            if recorded != decision:
                _deny()
            return cast(routing.RecipientRoutingDecision, recorded)
        except Exception:
            self._failed = True
        _deny()


__all__ = [
    "CHALLENGE_CONSUMPTION",
    "CIPHERTEXT_PERSISTENCE",
    "DECISION_ROUTE_TABLE",
    "DECISION_TABLE",
    "HANDLE_TABLE",
    "RECIPIENT_SELF_READ",
    "RECEIPT_ISSUANCE",
    "REQUEST_ADMISSION",
    "RUNTIME_ENABLED",
    "SNAPSHOT_ROUTE_TABLE",
    "SNAPSHOT_TABLE",
    "RecipientRoutingDecisionRouteRow",
    "RecipientRoutingDecisionRow",
    "RecipientRoutingHandleOwnerRow",
    "RecipientRoutingSnapshotRouteRow",
    "RecipientRoutingSnapshotRow",
    "SqlAlchemyRecipientRoutingRepository",
    "parse_stored_routing_decision_v1",
    "parse_stored_routing_snapshot_v1",
]
