"""Dormant PostgreSQL authority for one Social Ed25519 association chain.

The caller owns the transaction and must obtain authenticated Social enrollment
evidence and independently check session, Full, binding, and challenge state.
No method grants admission or commits a transaction. The migration, including
its append-only triggers, is required before this adapter may be used.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NoReturn

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    ForeignKeyConstraint,
    Index,
    PrimaryKeyConstraint,
    String,
    Text,
    insert,
    select,
    text,
)
from sqlalchemy.engine import Connection
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import ColumnElement

from app.models import Base, _CanonicalLowerHex
from app.services import social_messaging_device_admission_contract as admission
from app.services import social_messaging_device_ed25519_association_lifecycle as lifecycle
from app.services.social_device_verification_statement import AuthenticatedSocialDeviceVerificationStatementV1
from app.services.social_messaging_device_proof_profile import MAX_SAFE_INTEGER, parse_enrollment_v2

CHAIN_TABLE = "social_device_ed25519_association_chains"
EVENT_TABLE = "social_device_ed25519_association_events"
UNAVAILABLE_MESSAGE = "social device ed25519 association storage unavailable"


class SocialDeviceEd25519AssociationStorageUnavailable(ValueError):
    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


def _deny() -> NoReturn:
    raise SocialDeviceEd25519AssociationStorageUnavailable()


class _PgCheck(ColumnElement):
    inherit_cache = False
    type = Boolean()

    def __init__(self, expression: str) -> None:
        self.postgresql_sql = expression


@compiles(_PgCheck, "postgresql")
def _compile_pg_check(element, _compiler, **_kwargs):
    return element.postgresql_sql


@compiles(_PgCheck, "sqlite")
def _compile_sqlite_check(_element, _compiler, **_kwargs):
    return "1"


class SocialDeviceEd25519AssociationChain(Base):
    """One durable row to serialize every operation for an exact pair."""

    __tablename__ = CHAIN_TABLE

    subject = Column(String(64), nullable=False)
    device_id = Column(String(64), nullable=False)
    authority_epoch = Column(BigInteger, nullable=False)
    last_association_id = Column(String(64))
    last_association_version = Column(BigInteger)
    current_association_id = Column(String(64))
    state = Column(String(7), nullable=False)

    __table_args__ = (
        PrimaryKeyConstraint("subject", "device_id", name="pk_social_ed25519_chain"),
        CheckConstraint(_CanonicalLowerHex("subject", 64), name="ck_social_ed25519_chain_subject"),
        CheckConstraint(_CanonicalLowerHex("device_id", 64), name="ck_social_ed25519_chain_device"),
        CheckConstraint(
            "(state = 'empty' AND authority_epoch = 0 AND last_association_id IS NULL "
            "AND last_association_version IS NULL AND current_association_id IS NULL) OR "
            "(state = 'active' AND authority_epoch >= 1 AND last_association_id IS NOT NULL "
            "AND last_association_version >= 1 AND current_association_id = last_association_id) OR "
            "(state = 'revoked' AND authority_epoch >= 2 AND last_association_id IS NOT NULL "
            "AND last_association_version >= 1 AND current_association_id IS NULL)",
            name="ck_social_ed25519_chain_state",
        ),
    )


class SocialDeviceEd25519AssociationEvent(Base):
    """Canonical event wire plus indexed immutable identity evidence."""

    __tablename__ = EVENT_TABLE

    subject = Column(String(64), nullable=False)
    device_id = Column(String(64), nullable=False)
    authority_epoch = Column(BigInteger, nullable=False)
    kind = Column(String(10), nullable=False)
    association_id = Column(String(64), nullable=False)
    association_version = Column(BigInteger, nullable=False)
    predecessor_association_id = Column(String(64))
    ed25519_public_key = Column(String(64))
    enrollment_challenge_id = Column(String(64))
    event_wire = Column(Text, nullable=False)

    __table_args__ = (
        PrimaryKeyConstraint("subject", "device_id", "authority_epoch", name="pk_social_ed25519_event"),
        ForeignKeyConstraint(
            ("subject", "device_id"),
            (f"{CHAIN_TABLE}.subject", f"{CHAIN_TABLE}.device_id"),
            name="fk_social_ed25519_event_chain",
        ),
        CheckConstraint(_CanonicalLowerHex("subject", 64), name="ck_social_ed25519_event_subject"),
        CheckConstraint(_CanonicalLowerHex("device_id", 64), name="ck_social_ed25519_event_device"),
        CheckConstraint(_CanonicalLowerHex("association_id", 64), name="ck_social_ed25519_event_id"),
        CheckConstraint(
            _PgCheck("predecessor_association_id IS NULL OR predecessor_association_id ~ '^[0-9a-f]{64}$'"),
            name="ck_social_ed25519_event_predecessor",
        ),
        CheckConstraint(
            _PgCheck("ed25519_public_key IS NULL OR ed25519_public_key ~ '^[0-9a-f]{64}$'"),
            name="ck_social_ed25519_event_key",
        ),
        CheckConstraint(
            _PgCheck("enrollment_challenge_id IS NULL OR enrollment_challenge_id ~ '^[0-9a-f]{64}$'"),
            name="ck_social_ed25519_event_challenge",
        ),
        CheckConstraint(
            "authority_epoch BETWEEN 1 AND 9007199254740991 AND " "association_version BETWEEN 1 AND 9007199254740991",
            name="ck_social_ed25519_event_bounds",
        ),
        CheckConstraint(
            "kind IN ('initial','rotate','invalidate','revoke','reenroll') AND "
            "((kind IN ('initial','rotate','reenroll') AND ed25519_public_key IS NOT NULL "
            "AND enrollment_challenge_id IS NOT NULL) OR "
            "(kind IN ('invalidate','revoke') AND ed25519_public_key IS NULL "
            "AND enrollment_challenge_id IS NULL))",
            name="ck_social_ed25519_event_kind",
        ),
        Index(
            "uq_social_ed25519_creation_id",
            "association_id",
            unique=True,
            postgresql_where=text("kind IN ('initial','rotate','reenroll')"),
            sqlite_where=text("kind IN ('initial','rotate','reenroll')"),
        ),
        Index(
            "uq_social_ed25519_creation_version",
            "subject",
            "device_id",
            "association_version",
            unique=True,
            postgresql_where=text("kind IN ('initial','rotate','reenroll')"),
            sqlite_where=text("kind IN ('initial','rotate','reenroll')"),
        ),
        Index(
            "uq_social_ed25519_creation_predecessor",
            "predecessor_association_id",
            unique=True,
            postgresql_where=text("kind IN ('rotate','reenroll')"),
            sqlite_where=text("kind IN ('rotate','reenroll')"),
        ),
        Index(
            "uq_social_ed25519_creation_key",
            "subject",
            "device_id",
            "ed25519_public_key",
            unique=True,
            postgresql_where=text("kind IN ('initial','rotate','reenroll')"),
            sqlite_where=text("kind IN ('initial','rotate','reenroll')"),
        ),
        Index(
            "uq_social_ed25519_creation_challenge",
            "enrollment_challenge_id",
            unique=True,
            postgresql_where=text("kind IN ('initial','rotate','reenroll')"),
            sqlite_where=text("kind IN ('initial','rotate','reenroll')"),
        ),
    )


@dataclass(frozen=True, slots=True, repr=False)
class CurrentEd25519AssociationV1:
    subject: str
    device_id: str
    ed25519_public_key: str
    association_id: str
    association_version: int
    predecessor_association_id: str | None
    authority_epoch: int
    state: str


class SqlAlchemyEd25519AssociationStore:
    """Use only within the injected, active, read-committed PostgreSQL transaction.

    Lock order is pair advisory lock, chain row, then immutable events in epoch
    order. The advisory lock also protects the absence of a chain row. A hash
    collision can only serialize unrelated pairs; exact identities are checked
    after acquiring the lock. Results are provisional until caller commit.
    """

    def __init__(self, session: Session) -> None:
        self._session = session
        self._transaction = session.get_transaction()
        self._nested_transaction = session.get_nested_transaction()
        self._connection: Connection | None = None
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
            if connection.closed or connection.invalidated or not connection.in_transaction():
                _deny()
            if getattr(connection.connection.dbapi_connection, "autocommit", None) is not False:
                _deny()
            if self._connection is None:
                self._connection = connection
            elif connection is not self._connection:
                _deny()
            if connection.execute(text("SHOW transaction_isolation")).scalar_one() != "read committed":
                _deny()
            installed = connection.execute(
                text(
                    "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled = 'O' "
                    "AND ((tgrelid = to_regclass(:chain) AND tgname IN "
                    "('trg_social_ed25519_chain_guard','trg_social_ed25519_chain_truncate',"
                    "'trg_social_ed25519_chain_initialized')) OR "
                    "(tgrelid = to_regclass(:event) AND tgname IN "
                    "('trg_social_ed25519_event_guard','trg_social_ed25519_event_truncate',"
                    "'trg_social_ed25519_event_advance')))"
                ),
                {"chain": CHAIN_TABLE, "event": EVENT_TABLE},
            ).scalar_one()
            if installed != 6:
                _deny()
            return connection
        except Exception:
            self._failed = True
            _deny()

    @staticmethod
    def _identity(subject: object, device_id: object) -> tuple[str, str]:
        try:
            return admission._hex64(subject), admission._hex64(device_id)
        except Exception:
            _deny()

    def _locked(self, subject: object, device_id: object):
        connection = self._check_transaction()
        subject, device_id = self._identity(subject, device_id)
        connection.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:pair, 0))"),
            {"pair": subject + ":" + device_id},
        )
        chain = (
            connection.execute(
                select(SocialDeviceEd25519AssociationChain.__table__)
                .where(
                    SocialDeviceEd25519AssociationChain.subject == subject,
                    SocialDeviceEd25519AssociationChain.device_id == device_id,
                )
                .with_for_update()
            )
            .mappings()
            .one_or_none()
        )
        event_rows = (
            connection.execute(
                select(SocialDeviceEd25519AssociationEvent.__table__)
                .where(
                    SocialDeviceEd25519AssociationEvent.subject == subject,
                    SocialDeviceEd25519AssociationEvent.device_id == device_id,
                )
                .order_by(SocialDeviceEd25519AssociationEvent.authority_epoch)
            )
            .mappings()
            .all()
        )
        if chain is None and event_rows:
            _deny()
        if chain is not None and (chain["state"] == "empty" or not event_rows):
            _deny()
        events = []
        for position, row in enumerate(event_rows, 1):
            event = lifecycle.parse_association_event_v1(row["event_wire"])
            enrollment = parse_enrollment_v2(event.enrollment_wire) if event.enrollment_wire is not None else None
            if (
                row["subject"] != subject
                or row["device_id"] != device_id
                or row["authority_epoch"] != position
                or row["authority_epoch"] != event.authority_epoch
                or row["kind"] != event.kind
                or row["association_id"] != event.association_id
                or row["association_version"] != event.association_version
                or row["predecessor_association_id"] != event.predecessor_association_id
                or row["ed25519_public_key"] != (enrollment.ed25519_public_key if enrollment else None)
                or row["enrollment_challenge_id"] != (enrollment.enrollment_challenge_id if enrollment else None)
                or enrollment is not None
                and (enrollment.subject != subject or enrollment.device_id != device_id)
            ):
                _deny()
            events.append(event)
        state = lifecycle.AssociationLifecycleV1(tuple(events))
        snapshot = lifecycle.association_snapshot_v1(state)
        if chain is not None:
            last = snapshot.history[-1]
            if (
                chain["subject"] != subject
                or chain["device_id"] != device_id
                or chain["authority_epoch"] != snapshot.authority_epoch
                or chain["last_association_id"] != last.association_id
                or chain["last_association_version"] != last.association_version
                or chain["current_association_id"] != (snapshot.current.association_id if snapshot.current else None)
                or chain["state"] != ("active" if snapshot.current else "revoked")
            ):
                _deny()
        return connection, chain, state, snapshot

    def lock_current_association(self, subject: object, device_id: object) -> CurrentEd25519AssociationV1 | None:
        """Lock and derive current authority; never authorize an operation."""
        try:
            _, _, _, snapshot = self._locked(subject, device_id)
            current = snapshot.current
            if current is None:
                return None
            return CurrentEd25519AssociationV1(
                current.subject,
                current.device_id,
                current.ed25519_public_key,
                current.association_id,
                current.association_version,
                current.predecessor_association_id,
                snapshot.authority_epoch,
                current.state,
            )
        except Exception:
            self._failed = True
            _deny()

    def load_current_association(self, subject: object, device_id: object) -> CurrentEd25519AssociationV1 | None:
        return self.lock_current_association(subject, device_id)

    def lock_history(self, subject: object, device_id: object) -> lifecycle.AssociationSnapshotV1:
        """Return replayed immutable evidence under the same pair lock."""
        try:
            return self._locked(subject, device_id)[3]
        except Exception:
            self._failed = True
            _deny()

    def lock_lifecycle(self, subject: object, device_id: object) -> lifecycle.AssociationLifecycleV1:
        """Return complete replayable event evidence under the history lock."""
        try:
            return self._locked(subject, device_id)[2]
        except Exception:
            self._failed = True
            _deny()

    @staticmethod
    def _authenticated_enrollment(
        input_wire: object,
        statement: object,
        now: object,
        expected: lifecycle.AssociationSnapshotV1,
    ) -> str:
        try:
            value = admission.parse_verification_input_v1(input_wire)
            context = value.context
            enrollment = parse_enrollment_v2(value.challenge_wire)
            current = expected.current
            if (
                type(statement) is not AuthenticatedSocialDeviceVerificationStatementV1
                or value.operation != "enrollment-activate"
                or context.challenge_kind != "enrollment-v2"
                or statement.result != admission.ENROLLMENT_V2_RESULT
                or statement.purpose != admission.STATEMENT_PURPOSE
                or statement.issuer != context.audience
                or statement.challenge_kind != context.challenge_kind
                or statement.challenge_id != context.challenge_id
                or statement.attempt_id != context.attempt_id
                or statement.context_digest != admission.verification_context_digest_v1(context.wire)
                or statement.input_digest != admission.verification_input_digest_v1(value.wire)
                or type(now) is not int
                or not 0 <= now <= MAX_SAFE_INTEGER
                or not enrollment.issued_at <= now < enrollment.expires_at
                or not statement.issued_at <= now < statement.expires_at
                or statement.issued_at < enrollment.issued_at
                or statement.expires_at > enrollment.expires_at
                or current is None
                or (
                    context.subject != current.subject
                    or context.device_id != current.device_id
                    or context.ed25519_public_key != current.ed25519_public_key
                    or context.association_id != current.association_id
                    or context.association_version != current.association_version
                    or context.predecessor_association_id != current.predecessor_association_id
                    or context.authority_epoch != expected.authority_epoch
                )
            ):
                _deny()
            return value.challenge_wire
        except Exception:
            _deny()

    def _append(self, subject: str, device_id: str, chain, updated) -> CurrentEd25519AssociationV1 | None:
        connection = self._check_transaction()
        event = updated.events[-1]
        enrollment = parse_enrollment_v2(event.enrollment_wire) if event.enrollment_wire is not None else None
        if chain is None:
            connection.execute(
                insert(SocialDeviceEd25519AssociationChain.__table__).values(
                    subject=subject,
                    device_id=device_id,
                    authority_epoch=0,
                    last_association_id=None,
                    last_association_version=None,
                    current_association_id=None,
                    state="empty",
                )
            )
        connection.execute(
            insert(SocialDeviceEd25519AssociationEvent.__table__).values(
                subject=subject,
                device_id=device_id,
                authority_epoch=event.authority_epoch,
                kind=event.kind,
                association_id=event.association_id,
                association_version=event.association_version,
                predecessor_association_id=event.predecessor_association_id,
                ed25519_public_key=enrollment.ed25519_public_key if enrollment else None,
                enrollment_challenge_id=enrollment.enrollment_challenge_id if enrollment else None,
                event_wire=lifecycle.canonical_association_event_v1_bytes(event).decode("ascii"),
            )
        )
        return self.lock_current_association(subject, device_id)

    def _create(self, operation: str, input_wire: object, statement: object, now: object, predecessor, epoch):
        try:
            value = admission.parse_verification_input_v1(input_wire)
            subject, device_id = self._identity(value.context.subject, value.context.device_id)
            _, chain, prior, _ = self._locked(subject, device_id)
            enrollment_wire = value.challenge_wire
            if operation == "initial":
                updated = lifecycle.initial_association_v1(prior, enrollment_wire)
            elif operation == "rotate":
                updated = lifecycle.rotate_association_v1(
                    prior,
                    enrollment_wire,
                    expected_predecessor_association_id=predecessor,
                    expected_authority_epoch=epoch,
                )
            else:
                updated = lifecycle.reenroll_association_v1(
                    prior,
                    enrollment_wire,
                    expected_predecessor_association_id=predecessor,
                    expected_authority_epoch=epoch,
                )
            snapshot = lifecycle.association_snapshot_v1(updated)
            self._authenticated_enrollment(input_wire, statement, now, snapshot)
            return self._append(subject, device_id, chain, updated)
        except Exception:
            self._failed = True
            _deny()

    def establish_initial(self, input_wire: object, statement: object, *, now: object):
        return self._create("initial", input_wire, statement, now, None, None)

    def rotate(
        self, input_wire: object, statement: object, *, now: object, expected_predecessor: str, expected_epoch: int
    ):
        return self._create("rotate", input_wire, statement, now, expected_predecessor, expected_epoch)

    def reenroll(
        self, input_wire: object, statement: object, *, now: object, expected_predecessor: str, expected_epoch: int
    ):
        return self._create("reenroll", input_wire, statement, now, expected_predecessor, expected_epoch)

    def _terminal(
        self, kind: str, subject: object, device_id: object, expected_association_id: str, expected_epoch: int
    ):
        try:
            subject, device_id = self._identity(subject, device_id)
            _, chain, prior, _ = self._locked(subject, device_id)
            if kind == "revoke":
                updated = lifecycle.revoke_association_v1(
                    prior, expected_association_id=expected_association_id, expected_authority_epoch=expected_epoch
                )
            else:
                updated = lifecycle.invalidate_association_authority_v1(
                    prior, expected_association_id=expected_association_id, expected_authority_epoch=expected_epoch
                )
            return self._append(subject, device_id, chain, updated)
        except Exception:
            self._failed = True
            _deny()

    def revoke(self, subject: object, device_id: object, *, expected_association_id: str, expected_epoch: int):
        return self._terminal("revoke", subject, device_id, expected_association_id, expected_epoch)

    def invalidate_authority(
        self, subject: object, device_id: object, *, expected_association_id: str, expected_epoch: int
    ):
        return self._terminal("invalidate", subject, device_id, expected_association_id, expected_epoch)
