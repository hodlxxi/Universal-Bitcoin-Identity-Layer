"""Dormant immutable challenge evidence in a caller-owned PostgreSQL transaction.

No session factory, clock, authority check, consumption, receipt or operation
effect lives here. Importing the model does not connect to a database. Apply
the dedicated SQL migration separately; metadata.create_all is insufficient.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, NoReturn, cast

from sqlalchemy import CheckConstraint, Column, String, Text, insert, select, text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session

from app.models import Base, _CanonicalLowerHex
from app.services import social_messaging_device_admission_contract as contract

TABLE = "social_device_admission_challenges"
RUNTIME_ENABLED = False
CHALLENGE_CONSUMPTION = "not_implemented"
OPERATION_EFFECT = "not_implemented"
RECEIPT_ISSUANCE = "not_implemented"
CURRENT_AUTHORITY = "not_evaluated"
FINAL_ADMISSION = "denied"
UNAVAILABLE_MESSAGE = "social device challenge storage unavailable"


class SocialDeviceChallengeStorageUnavailable(ValueError):
    """One non-sensitive failure, including unknown IDs and transaction errors."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


def _deny() -> NoReturn:
    raise SocialDeviceChallengeStorageUnavailable()


class SocialDeviceAdmissionChallengeRow(Base):
    """Only the locking key duplicates canonical evidence; state is separate."""

    __tablename__ = TABLE

    challenge_id = Column(String(64), primary_key=True)
    context_wire = Column(Text, nullable=False)
    challenge_wire = Column(Text, nullable=False)
    routing_request_wire = Column(Text, nullable=True)
    state = Column(String(11), nullable=False)

    __table_args__ = (
        CheckConstraint(_CanonicalLowerHex("challenge_id", 64), name="ck_social_challenge_id"),
        CheckConstraint(
            "state IN ('issued','consumed','expired','invalidated','cancelled')",
            name="ck_social_challenge_state",
        ),
        CheckConstraint(
            "octet_length(context_wire) BETWEEN 1 AND 4096 AND context_wire !~ '[^ -~]'",
            name="ck_social_challenge_context_wire",
        ),
        CheckConstraint(
            "octet_length(challenge_wire) BETWEEN 1 AND 4096 AND challenge_wire !~ '[^ -~]'",
            name="ck_social_challenge_wire",
        ),
        CheckConstraint(
            "routing_request_wire IS NULL OR (octet_length(routing_request_wire) BETWEEN 1 AND 2048 "
            "AND routing_request_wire !~ '[^ -~]')",
            name="ck_social_challenge_routing_wire",
        ),
        CheckConstraint(
            "(context_wire::json ->> 'challengeId' = challenge_id AND "
            "COALESCE(challenge_wire::json ->> 'challengeId', "
            "challenge_wire::json ->> 'enrollmentChallengeId') = challenge_id) IS TRUE",
            name="ck_social_challenge_wire_id",
        ),
    )


@dataclass(frozen=True, slots=True, repr=False)
class DeviceAdmissionChallengeV1:
    """Parsed immutable history, never an authorization or bearer credential.

    All context identities (including attempt/Full/approver/association/epoch)
    come from context.wire. Request bytes and deadlines come from challenge_wire.
    These derived fields are not additional database columns.
    """

    context: contract.VerificationContextV1
    challenge_wire: str
    actual_request_wire: str | None
    routing_request_wire: str | None
    operation: str
    issued_at: int
    expires_at: int
    state: str

    def inspect_deadline(self, *, now: object) -> contract.ExclusiveDeadlineInspectionV1:
        try:
            return contract.inspect_exclusive_deadline_v1(
                issued_at=self.issued_at, expires_at=self.expires_at, observed_at=now
            )
        except Exception:
            pass
        _deny()


def _parse_evidence(
    *, context_wire: object, challenge_wire: object, routing_request_wire: object, state: object
) -> DeviceAdmissionChallengeV1:
    context = contract.parse_verification_context_v1(context_wire)
    challenge = contract._ascii_string(challenge_wire, maximum=contract.MAX_CHALLENGE_BYTES)
    routing = contract._ascii_string(routing_request_wire, maximum=contract.MAX_ROUTING_REQUEST_BYTES, nullable=True)
    if type(state) is not str or state not in contract.CHALLENGE_STATES:
        _deny()
    actual = None
    if context.challenge_kind == "enrollment-v2":
        enrollment = contract._validate_enrollment_challenge_context_binding(challenge, context)
        if routing is not None:
            _deny()
        operation = "enrollment-activate"
        issued_at, expires_at = enrollment.issued_at, enrollment.expires_at
    else:
        parsed, request = contract._validate_request_challenge_context_binding(challenge, context)
        actual = cast(str, parsed["request"])
        operation = cast(str, request["operation"])
        issued_at, expires_at = cast(int, parsed["issuedAt"]), cast(int, parsed["expiresAt"])
        if operation == "ciphertext-submit":
            contract._parse_routing_request(routing)
        elif routing is not None:
            _deny()
    return DeviceAdmissionChallengeV1(
        context, cast(str, challenge), actual, routing, operation, issued_at, expires_at, state
    )


def parse_stored_device_challenge_v1(row: Mapping[str, object]) -> DeviceAdmissionChallengeV1:
    """Reparse exact persisted strings; reject corrupt or mismatched metadata.

    Exposed as a pure decoder so storage corruption has the same closed failure
    as an adapter read. A decoded record conveys no current authority.
    """
    try:
        if set(row) != set(SocialDeviceAdmissionChallengeRow.__table__.columns.keys()):
            _deny()
        evidence = _parse_evidence(
            context_wire=row["context_wire"],
            challenge_wire=row["challenge_wire"],
            routing_request_wire=row["routing_request_wire"],
            state=row["state"],
        )
        if contract._hex64(row["challenge_id"]) != evidence.context.challenge_id:
            _deny()
        return evidence
    except Exception:
        pass
    _deny()


class SqlAlchemyDeviceChallengeStore:
    """Create/read/lock within exactly one injected active transaction.

    The caller must propagate failures and roll back its entire unit of work.
    This adapter never starts, completes or replaces a transaction. Results from
    create_issued are provisional until the caller commits. A failed adapter
    cannot be reused, nor can it be moved across transaction/savepoint boundaries.
    Flush pending ORM work explicitly before calling. Core reads bypass cached
    ORM objects, including after a PostgreSQL row-lock wait.
    """

    def __init__(self, session: Session) -> None:
        self._session = session
        self._failed = False
        self._connection: Connection | None = None
        self._database_transaction = None
        self._database_nested_transaction = None
        try:
            self._transaction = session.get_transaction()
            self._nested_transaction = session.get_nested_transaction()
            self._check_transaction()
            return
        except Exception:
            pass
        _deny()

    def _check_transaction(self) -> None:
        session = self._session
        if (
            self._failed
            or not session.is_active
            or self._transaction is None
            or session.get_transaction() is not self._transaction
            or session.get_nested_transaction() is not self._nested_transaction
            or not self._transaction.is_active
            or session.in_transaction() is not True
            or session.get_bind().dialect.name != "postgresql"
            or session.new
            or session.dirty
            or session.deleted
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
        # Refuse a table provisioned with create_all but without immutable guards.
        installed = connection.execute(
            text(
                "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled = 'O' "
                "AND tgrelid = to_regclass('social_device_admission_challenges') "
                "AND tgname IN ('trg_social_challenge_guard', 'trg_social_challenge_no_truncate')"
            )
        ).scalar_one()
        if installed != 2:
            _deny()

    def create_issued(
        self,
        *,
        context_wire: object,
        challenge_wire: object,
        actual_request_wire: object = None,
        routing_request_wire: object = None,
    ) -> DeviceAdmissionChallengeV1:
        """Insert once. Even a byte-identical existing challenge ID is denied.

        actual_request_wire must exactly equal the challenge's embedded request;
        only that embedded string is stored. No proof or statement is required
        to store evidence, and storing it does not authenticate any participant.
        """
        try:
            evidence = _parse_evidence(
                context_wire=context_wire,
                challenge_wire=challenge_wire,
                routing_request_wire=routing_request_wire,
                state="issued",
            )
            if actual_request_wire is not None and type(actual_request_wire) is not str:
                _deny()
            if actual_request_wire != evidence.actual_request_wire:
                _deny()
            self._check_transaction()
            table = SocialDeviceAdmissionChallengeRow.__table__
            row = (
                self._connection.execute(
                    insert(table)
                    .values(
                        challenge_id=evidence.context.challenge_id,
                        context_wire=evidence.context.wire,
                        challenge_wire=evidence.challenge_wire,
                        routing_request_wire=evidence.routing_request_wire,
                        state="issued",
                    )
                    .returning(*table.c)
                    .execution_options(autoflush=False)
                )
                .mappings()
                .one()
            )
            stored = parse_stored_device_challenge_v1(row)
            if stored != evidence:
                _deny()
            return stored
        except Exception:
            self._failed = True
        _deny()

    def read(self, challenge_id: object) -> DeviceAdmissionChallengeV1:
        """Read immutable history, including expired and terminal evidence."""
        return self._read(challenge_id, lock=False)

    def read_for_update(self, challenge_id: object) -> DeviceAdmissionChallengeV1:
        """Lock the authoritative row until the caller completes its transaction.

        Returns history in any state. The future atomic owner must separately
        require issued, recheck deadlines AFTER waits and recheck all current
        authority in this same transaction. A row lock is not consumption.
        """
        return self._read(challenge_id, lock=True)

    def _read(self, challenge_id: object, *, lock: bool) -> DeviceAdmissionChallengeV1:
        try:
            key = contract._hex64(challenge_id)
            self._check_transaction()
            table = SocialDeviceAdmissionChallengeRow.__table__
            statement = select(table).where(table.c.challenge_id == key).execution_options(autoflush=False)
            if lock:
                statement = statement.with_for_update(of=table)
            row = self._connection.execute(statement).mappings().one()
            evidence = parse_stored_device_challenge_v1(row)
            if evidence.context.challenge_id != key:
                _deny()
            return evidence
        except Exception:
            self._failed = True
        _deny()


__all__ = [
    "DeviceAdmissionChallengeV1",
    "SocialDeviceAdmissionChallengeRow",
    "SocialDeviceChallengeStorageUnavailable",
    "SqlAlchemyDeviceChallengeStore",
    "parse_stored_device_challenge_v1",
]
