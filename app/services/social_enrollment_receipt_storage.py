"""Dormant PostgreSQL enrollment receipt evidence in a caller transaction.

The adapter derives one deterministic receipt from an exact typed pre-effect
authority.  It stores history but never executes an association effect,
consumes a challenge, owns transaction lifecycle, or grants admission.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Mapping, NoReturn, cast

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    ForeignKeyConstraint,
    String,
    Text,
    UniqueConstraint,
    insert,
    select,
    text,
)
from sqlalchemy.engine import Connection
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import ColumnElement

from app.models import Base, _CanonicalLowerHex
from app.services import social_enrollment_transition_authority as transition
from app.services import social_messaging_device_admission_contract as admission
from app.services.social_device_challenge_store import SocialDeviceAdmissionChallengeRow
from app.services.social_messaging_device_proof_profile import MAX_SAFE_INTEGER

TABLE = "social_device_enrollment_admission_receipts"
VERSION = 1
OPERATION = "enrollment-activate"
RECEIPT_ID_PREIMAGE_SCHEMA = "hodlxxi.social_enrollment_receipt_id_preimage.v1"
RECEIPT_ID_DOMAIN = "HODLXXI_SOCIAL_ENROLLMENT_RECEIPT_ID_V1"
RUNTIME_ENABLED = False
EFFECT_EXECUTION = "not_implemented_as_atomic_owner"
CHALLENGE_CONSUMPTION = "separate_transaction_bound_primitive"
FINAL_ADMISSION = "denied"
UNAVAILABLE_MESSAGE = "social enrollment receipt storage unavailable"


class SocialEnrollmentReceiptStorageUnavailable(ValueError):
    """One non-sensitive failure for malformed evidence and storage denial."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


def _deny() -> NoReturn:
    raise SocialEnrollmentReceiptStorageUnavailable()


def _canonical(value: Mapping[str, object]) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _integer(value: object) -> int:
    if type(value) is not int or value < 0 or value > MAX_SAFE_INTEGER:
        _deny()
    return cast(int, value)


def _exact_authority(value: object) -> transition.EnrollmentTransitionAuthorityV1:
    try:
        if type(value) is not transition.EnrollmentTransitionAuthorityV1:
            _deny()
        authority = cast(transition.EnrollmentTransitionAuthorityV1, value)
        if transition._exact_authority(authority) is not authority:
            _deny()
        return authority
    except Exception:
        pass
    _deny()


def canonical_enrollment_receipt_id_preimage_v1_bytes(authority: object) -> bytes:
    """Freeze identity independently of decision time and database state."""

    value = _exact_authority(authority)
    effect = transition.prepared_enrollment_effect_v1(value)
    return _canonical(
        {
            "challengeId": value.challenge_id,
            "effectDigest": effect.effect_digest,
            "effectId": effect.effect_id,
            "operation": OPERATION,
            "schema": RECEIPT_ID_PREIMAGE_SCHEMA,
            "version": VERSION,
        }
    ).encode("ascii")


def enrollment_receipt_id_v1(authority: object) -> str:
    preimage = canonical_enrollment_receipt_id_preimage_v1_bytes(authority)
    return hashlib.sha256(RECEIPT_ID_DOMAIN.encode("ascii") + b"\0" + preimage).hexdigest()


class _PostgreSQLReceiptCheck(ColumnElement):
    """Keep PostgreSQL JSON/byte checks inert in shared SQLite metadata."""

    inherit_cache = False
    type = Boolean()

    def __init__(self, expression: str) -> None:
        self.postgresql_sql = expression


@compiles(_PostgreSQLReceiptCheck)
@compiles(_PostgreSQLReceiptCheck, "postgresql")
def _compile_postgresql_receipt_check(element, _compiler, **_kwargs):
    return element.postgresql_sql


@compiles(_PostgreSQLReceiptCheck, "sqlite")
def _compile_sqlite_receipt_metadata_check(_element, _compiler, **_kwargs):
    return "1"


class SocialEnrollmentAdmissionReceiptRow(Base):
    """Immutable committed receipt and exact pre-effect authority evidence."""

    __tablename__ = TABLE

    receipt_id = Column(String(64), primary_key=True)
    challenge_id = Column(String(64), nullable=False)
    operation = Column(String(19), nullable=False)
    decided_at = Column(BigInteger, nullable=False)
    effect_id = Column(String(64), nullable=False)
    effect_digest = Column(String(64), nullable=False)
    proposed_association_id = Column(String(64), nullable=False)
    authority_wire = Column(Text, nullable=False)
    receipt_wire = Column(Text, nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ("challenge_id",),
            (f"{SocialDeviceAdmissionChallengeRow.__tablename__}.challenge_id",),
            name="fk_social_enrollment_receipt_challenge",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint("challenge_id", name="uq_social_enrollment_receipt_challenge"),
        UniqueConstraint("effect_id", name="uq_social_enrollment_receipt_effect"),
        CheckConstraint(_CanonicalLowerHex("receipt_id", 64), name="ck_social_enrollment_receipt_id"),
        CheckConstraint(_CanonicalLowerHex("challenge_id", 64), name="ck_social_enrollment_receipt_challenge"),
        CheckConstraint(_CanonicalLowerHex("effect_id", 64), name="ck_social_enrollment_receipt_effect_id"),
        CheckConstraint(
            _CanonicalLowerHex("effect_digest", 64),
            name="ck_social_enrollment_receipt_effect_digest",
        ),
        CheckConstraint(
            _CanonicalLowerHex("proposed_association_id", 64),
            name="ck_social_enrollment_receipt_association",
        ),
        CheckConstraint("operation = 'enrollment-activate'", name="ck_social_enrollment_receipt_operation"),
        CheckConstraint(
            "decided_at BETWEEN 0 AND 9007199254740991",
            name="ck_social_enrollment_receipt_decided_at",
        ),
        CheckConstraint(
            _PostgreSQLReceiptCheck("octet_length(authority_wire) BETWEEN 1 AND 8192 AND authority_wire !~ '[^ -~]'"),
            name="ck_social_enrollment_receipt_authority_wire",
        ),
        CheckConstraint(
            _PostgreSQLReceiptCheck("octet_length(receipt_wire) BETWEEN 1 AND 2048 AND receipt_wire !~ '[^ -~]'"),
            name="ck_social_enrollment_receipt_wire",
        ),
    )


@dataclass(frozen=True, slots=True, repr=False)
class StoredEnrollmentAdmissionReceiptV1:
    """Read-only history; never bearer or effect re-execution authority."""

    receipt: admission.AdmissionReceiptV1
    receipt_wire: str
    effect_id: str
    effect_digest: str
    proposed_association_id: str

    bearer_authority: str = field(default="none", init=False)
    reexecution_authority: str = field(default="none", init=False)


def parse_stored_enrollment_receipt_v1(
    row: Mapping[str, object],
) -> StoredEnrollmentAdmissionReceiptV1:
    """Reparse exact durable bytes and cross-check every duplicated identity."""

    try:
        if set(row) != set(SocialEnrollmentAdmissionReceiptRow.__table__.columns.keys()):
            _deny()
        authority_wire = row["authority_wire"]
        transition.validate_enrollment_transition_authority_v1_bytes(authority_wire)
        authority = transition._parse_enrollment_transition_authority_v1(authority_wire)
        prepared = transition.prepared_enrollment_effect_v1(authority)
        receipt = admission.parse_admission_receipt_v1(row["receipt_wire"])
        proposed = admission._hex64(row["proposed_association_id"])
        if (
            receipt.receipt_id != row["receipt_id"]
            or receipt.challenge_id != row["challenge_id"]
            or receipt.operation != row["operation"]
            or receipt.decided_at != row["decided_at"]
            or receipt.receipt_id != enrollment_receipt_id_v1(authority)
            or receipt.challenge_id != authority.challenge_id
            or prepared.operation != receipt.operation
            or prepared.effect_id != row["effect_id"]
            or prepared.effect_digest != row["effect_digest"]
            or proposed != authority.proposed_association_id
        ):
            _deny()
        return StoredEnrollmentAdmissionReceiptV1(
            receipt=receipt,
            receipt_wire=cast(str, row["receipt_wire"]),
            effect_id=prepared.effect_id,
            effect_digest=prepared.effect_digest,
            proposed_association_id=proposed,
        )
    except Exception:
        pass
    _deny()


class SqlAlchemyEnrollmentAdmissionReceiptStore:
    """Insert/read through exactly one injected active PostgreSQL transaction."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._transaction = session.get_transaction()
        self._nested_transaction = session.get_nested_transaction()
        self._connection: Connection | None = None
        self._database_transaction = None
        self._database_nested_transaction = None
        self._failed = False
        self._check_transaction()

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
                    "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled = 'O' "
                    "AND ((tgrelid = to_regclass(:receipt) AND tgname IN "
                    "('trg_social_enrollment_receipt_guard',"
                    "'trg_social_enrollment_receipt_no_truncate',"
                    "'trg_social_enrollment_receipt_atomic')) OR "
                    "(tgrelid = to_regclass(:challenge) AND "
                    "tgname = 'trg_social_enrollment_challenge_atomic') OR "
                    "(tgrelid = to_regclass(:event) AND "
                    "tgname = 'trg_social_enrollment_event_atomic'))"
                ),
                {
                    "receipt": TABLE,
                    "challenge": "social_device_admission_challenges",
                    "event": "social_device_ed25519_association_events",
                },
            ).scalar_one()
            if installed != 5:
                _deny()
            return connection
        except Exception:
            self._failed = True
            _deny()

    def store_committed(
        self,
        authority: transition.EnrollmentTransitionAuthorityV1,
        *,
        proposed_association_id: object,
        decided_at: object,
    ) -> StoredEnrollmentAdmissionReceiptV1:
        """Insert provisional receipt evidence; only caller commit publishes it."""

        try:
            authority = _exact_authority(authority)
            proposed = admission._hex64(proposed_association_id)
            decided = _integer(decided_at)
            if proposed != authority.proposed_association_id:
                _deny()
            prepared = transition.prepared_enrollment_effect_v1(authority)
            receipt_id = enrollment_receipt_id_v1(authority)
            receipt_wire = admission.canonical_admission_receipt_v1_bytes(
                receipt_id=receipt_id,
                challenge_id=authority.challenge_id,
                operation=prepared.operation,
                decided_at=decided,
            ).decode("ascii")
            connection = self._check_transaction()
            table = SocialEnrollmentAdmissionReceiptRow.__table__
            row = (
                connection.execute(
                    insert(table)
                    .values(
                        receipt_id=receipt_id,
                        challenge_id=authority.challenge_id,
                        operation=prepared.operation,
                        decided_at=decided,
                        effect_id=prepared.effect_id,
                        effect_digest=prepared.effect_digest,
                        proposed_association_id=proposed,
                        authority_wire=authority.wire,
                        receipt_wire=receipt_wire,
                    )
                    .returning(*table.c)
                    .execution_options(autoflush=False)
                )
                .mappings()
                .one()
            )
            return parse_stored_enrollment_receipt_v1(row)
        except Exception:
            self._failed = True
        _deny()

    def read_by_challenge_id(self, challenge_id: object) -> StoredEnrollmentAdmissionReceiptV1 | None:
        """Load immutable history without granting bearer or execution rights."""

        try:
            key = admission._hex64(challenge_id)
            connection = self._check_transaction()
            table = SocialEnrollmentAdmissionReceiptRow.__table__
            row = (
                connection.execute(select(table).where(table.c.challenge_id == key).execution_options(autoflush=False))
                .mappings()
                .one_or_none()
            )
            return None if row is None else parse_stored_enrollment_receipt_v1(row)
        except Exception:
            self._failed = True
        _deny()


__all__ = [
    "CHALLENGE_CONSUMPTION",
    "EFFECT_EXECUTION",
    "FINAL_ADMISSION",
    "OPERATION",
    "RECEIPT_ID_DOMAIN",
    "RECEIPT_ID_PREIMAGE_SCHEMA",
    "RUNTIME_ENABLED",
    "SocialEnrollmentAdmissionReceiptRow",
    "SocialEnrollmentReceiptStorageUnavailable",
    "SqlAlchemyEnrollmentAdmissionReceiptStore",
    "StoredEnrollmentAdmissionReceiptV1",
    "canonical_enrollment_receipt_id_preimage_v1_bytes",
    "enrollment_receipt_id_v1",
    "parse_stored_enrollment_receipt_v1",
]
