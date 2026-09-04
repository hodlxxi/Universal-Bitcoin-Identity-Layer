"""Atomic SQLAlchemy storage for Social messaging device bindings."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select, text, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.models import SocialMessagingDeviceBinding
from app.services.social_messaging_device_binding_registry import (
    DeviceBindingRegistryUnavailable,
    DeviceBindingStatement,
    MAX_ACTIVE_DEVICES,
    SIGNATURE_FORMAT,
    STATEMENT_SCHEMA,
    _parse_and_verify_dict,
)


def _aware(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def _from_row(row: SocialMessagingDeviceBinding) -> DeviceBindingStatement:
    return DeviceBindingStatement(
        row.contract_version,
        row.subject_pubkey,
        row.device_id,
        row.algorithm,
        row.public_key,
        row.binding_version,
        _aware(row.valid_from),
        _aware(row.expires_at),
        row.operation,
        row.prior_binding_id,
        row.nonce,
        row.statement_sha256,
        row.signature_format,
        row.identity_signature,
    )


def _row(
    statement: DeviceBindingStatement,
    now: datetime,
) -> SocialMessagingDeviceBinding:
    active = statement.operation != "revoke"

    return SocialMessagingDeviceBinding(
        binding_id=statement.binding_id,
        contract_version=STATEMENT_SCHEMA,
        subject_pubkey=statement.subject,
        device_id=statement.device_id,
        algorithm=statement.algorithm,
        public_key=statement.public_key,
        binding_version=statement.binding_version,
        valid_from=statement.valid_from,
        expires_at=statement.expires_at,
        operation=statement.operation,
        prior_binding_id=statement.prior_binding_id,
        nonce=statement.nonce,
        statement_sha256=statement.digest,
        signature_format=SIGNATURE_FORMAT,
        identity_signature=statement.signature,
        active=active,
        retired_at=None if active else now,
        created_at=now,
    )


def _verify_persisted_row(
    row: SocialMessagingDeviceBinding,
) -> DeviceBindingStatement:
    statement = _from_row(row)

    verified = _parse_and_verify_dict(
        statement.public_dict(),
        authenticated_subject=row.subject_pubkey,
    )

    if (
        verified != statement
        or row.binding_id != verified.binding_id
        or row.statement_sha256 != verified.digest
    ):
        raise DeviceBindingRegistryUnavailable()

    return verified


def _locked_row(
    session,
    binding_id: str | None,
) -> SocialMessagingDeviceBinding:
    if not isinstance(binding_id, str):
        raise DeviceBindingRegistryUnavailable()

    row = session.execute(
        select(SocialMessagingDeviceBinding)
        .where(
            SocialMessagingDeviceBinding.binding_id
            == binding_id
        )
        .with_for_update()
    ).scalar_one_or_none()

    if row is None:
        raise DeviceBindingRegistryUnavailable()

    return row


def _subject_lock_key(subject: str) -> int:
    digest = hashlib.sha256(
        b"hodlxxi:social-messaging-device-subject-lock:v1:"
        + bytes.fromhex(subject)
    ).digest()

    value = int.from_bytes(
        digest[:8],
        "big",
        signed=False,
    )

    if value >= 2**63:
        value -= 2**64

    return value


def _lock_subject(session, subject: str) -> None:
    """
    Serialize per-subject active-device count transitions on PostgreSQL.

    Device/public-key uniqueness is independently protected by database
    unique indexes.
    """

    bind = session.get_bind()

    if bind is not None and bind.dialect.name == "postgresql":
        session.execute(
            text("SELECT pg_advisory_xact_lock(:key)"),
            {"key": _subject_lock_key(subject)},
        )


@dataclass(frozen=True)
class _ValidatedDeviceChain:
    head: DeviceBindingStatement
    expires_at: datetime


def _validate_successor_chain(
    statements: list[DeviceBindingStatement],
) -> datetime:
    ordered = list(reversed(statements))

    if not ordered or ordered[0].operation != "register":
        raise DeviceBindingRegistryUnavailable()

    root = ordered[0]

    if root.binding_version != 1 or root.prior_binding_id is not None:
        raise DeviceBindingRegistryUnavailable()

    predecessor = root
    chain_expires = root.expires_at

    for successor in ordered[1:]:
        if (
            successor.operation != "rotate"
            or successor.subject != predecessor.subject
            or successor.device_id != predecessor.device_id
            or successor.binding_version
            != predecessor.binding_version + 1
            or successor.prior_binding_id
            != predecessor.binding_id
            or successor.public_key == predecessor.public_key
            or successor.expires_at > chain_expires
        ):
            raise DeviceBindingRegistryUnavailable()

        chain_expires = min(
            chain_expires,
            successor.expires_at,
        )

        predecessor = successor

    return chain_expires


def _valid_device_chain(
    session,
    head: SocialMessagingDeviceBinding,
    *,
    expected_subject: str,
    expected_device: str,
    head_active: bool,
    valid_at: datetime | None = None,
) -> _ValidatedDeviceChain:
    seen: set[str] = set()
    statements: list[DeviceBindingStatement] = []

    row = head
    successor: DeviceBindingStatement | None = None

    first = True
    depth = 0
    max_depth: int | None = None

    timestamp = (
        _aware(valid_at)
        if valid_at is not None
        else None
    )

    head_statement = None

    while True:
        if row.binding_id in seen:
            raise DeviceBindingRegistryUnavailable()

        seen.add(row.binding_id)

        depth += 1

        if max_depth is not None and depth > max_depth:
            raise DeviceBindingRegistryUnavailable()

        statement = _verify_persisted_row(row)
        statements.append(statement)

        if first:
            head_statement = statement
            max_depth = statement.binding_version

        if (
            statement.subject != expected_subject
            or statement.device_id != expected_device
            or statement.operation
            not in {"register", "rotate"}
        ):
            raise DeviceBindingRegistryUnavailable()

        if timestamp is not None and (
            statement.valid_from > timestamp
            or statement.expires_at <= timestamp
        ):
            raise DeviceBindingRegistryUnavailable()

        if first:
            if head_active:
                if (
                    row.active is not True
                    or row.retired_at is not None
                ):
                    raise DeviceBindingRegistryUnavailable()
            else:
                if (
                    row.active is not False
                    or row.retired_at is None
                ):
                    raise DeviceBindingRegistryUnavailable()
        else:
            if (
                row.active is not False
                or row.retired_at is None
            ):
                raise DeviceBindingRegistryUnavailable()

        if successor is not None and (
            successor.subject != statement.subject
            or successor.device_id != statement.device_id
            or successor.prior_binding_id
            != statement.binding_id
            or successor.binding_version
            != statement.binding_version + 1
        ):
            raise DeviceBindingRegistryUnavailable()

        if statement.operation == "register":
            if (
                statement.binding_version != 1
                or statement.prior_binding_id is not None
                or head_statement is None
            ):
                raise DeviceBindingRegistryUnavailable()

            expires_at = _validate_successor_chain(
                statements
            )

            return _ValidatedDeviceChain(
                head_statement,
                expires_at,
            )

        if (
            statement.binding_version <= 1
            or statement.prior_binding_id is None
        ):
            raise DeviceBindingRegistryUnavailable()

        successor = statement
        first = False

        row = _locked_row(
            session,
            statement.prior_binding_id,
        )


def _locked_active_device(
    session,
    subject: str,
    device_id: str,
) -> SocialMessagingDeviceBinding | None:
    return session.execute(
        select(SocialMessagingDeviceBinding)
        .where(
            SocialMessagingDeviceBinding.subject_pubkey
            == subject,
            SocialMessagingDeviceBinding.device_id
            == device_id,
            SocialMessagingDeviceBinding.active.is_(True),
        )
        .with_for_update()
    ).scalar_one_or_none()


def _locked_active_subject_rows(
    session,
    subject: str,
) -> list[SocialMessagingDeviceBinding]:
    return list(
        session.execute(
            select(SocialMessagingDeviceBinding)
            .where(
                SocialMessagingDeviceBinding.subject_pubkey
                == subject,
                SocialMessagingDeviceBinding.active.is_(True),
            )
            .order_by(
                SocialMessagingDeviceBinding.device_id,
                SocialMessagingDeviceBinding.binding_version,
            )
            .with_for_update()
        )
        .scalars()
        .all()
    )


def _locked_active_public_key_rows(
    session,
    public_key: str,
) -> list[SocialMessagingDeviceBinding]:
    return list(
        session.execute(
            select(SocialMessagingDeviceBinding)
            .where(
                SocialMessagingDeviceBinding.public_key
                == public_key,
                SocialMessagingDeviceBinding.active.is_(True),
            )
            .with_for_update()
        )
        .scalars()
        .all()
    )


def _retire(
    row: SocialMessagingDeviceBinding,
    timestamp: datetime,
):
    return (
        update(SocialMessagingDeviceBinding)
        .where(
            SocialMessagingDeviceBinding.binding_id
            == row.binding_id,
            SocialMessagingDeviceBinding.active.is_(True),
            SocialMessagingDeviceBinding.retired_at.is_(None),
        )
        .values(
            active=False,
            retired_at=timestamp,
        )
    )


def _cleanup_expired_subject_heads(
    session,
    subject: str,
    now: datetime,
) -> list[_ValidatedDeviceChain]:
    """
    Return current live devices and retire stale expired active heads.

    The retirement is lifecycle housekeeping only; no device becomes valid
    through this path.
    """

    live: list[_ValidatedDeviceChain] = []

    rows = _locked_active_subject_rows(
        session,
        subject,
    )

    if len(rows) > MAX_ACTIVE_DEVICES + 1:
        raise DeviceBindingRegistryUnavailable()

    for row in rows:
        try:
            chain = _valid_device_chain(
                session,
                row,
                expected_subject=subject,
                expected_device=row.device_id,
                head_active=True,
                valid_at=now,
            )

            live.append(chain)

        except DeviceBindingRegistryUnavailable:
            chain = _valid_device_chain(
                session,
                row,
                expected_subject=subject,
                expected_device=row.device_id,
                head_active=True,
            )

            if chain.expires_at > now:
                raise

            retired = session.execute(
                _retire(
                    row,
                    min(
                        _aware(row.expires_at),
                        chain.expires_at,
                    ),
                )
            )

            if retired.rowcount != 1:
                raise DeviceBindingRegistryUnavailable()

    return live


def _prepare_public_key(
    session,
    statement: DeviceBindingStatement,
    now: datetime,
) -> None:
    conflicts = _locked_active_public_key_rows(
        session,
        statement.public_key,
    )

    if len(conflicts) > 1:
        raise DeviceBindingRegistryUnavailable()

    for row in conflicts:
        try:
            chain = _valid_device_chain(
                session,
                row,
                expected_subject=row.subject_pubkey,
                expected_device=row.device_id,
                head_active=True,
                valid_at=now,
            )
        except DeviceBindingRegistryUnavailable:
            chain = _valid_device_chain(
                session,
                row,
                expected_subject=row.subject_pubkey,
                expected_device=row.device_id,
                head_active=True,
            )

            if chain.expires_at > now:
                raise

            retired = session.execute(
                _retire(
                    row,
                    min(
                        _aware(row.expires_at),
                        chain.expires_at,
                    ),
                )
            )

            if retired.rowcount != 1:
                raise DeviceBindingRegistryUnavailable()

            continue

        if (
            chain.head.subject != statement.subject
            or chain.head.device_id != statement.device_id
        ):
            raise DeviceBindingRegistryUnavailable()

        raise DeviceBindingRegistryUnavailable()


class SqlAlchemySocialMessagingDeviceBindingRepository:
    """
    Atomic multi-device lifecycle storage.

    One subject may own multiple current devices.
    Each exact (subject, deviceId) has one current lifecycle head.
    """

    def __init__(self, session_factory):
        self._session_factory = session_factory

    def apply(
        self,
        statement: DeviceBindingStatement,
        now: datetime,
    ) -> DeviceBindingStatement:
        try:
            timestamp = _aware(now)

            with self._session_factory() as session:
                _lock_subject(
                    session,
                    statement.subject,
                )

                replay = session.execute(
                    select(SocialMessagingDeviceBinding)
                    .where(
                        SocialMessagingDeviceBinding.binding_id
                        == statement.binding_id
                    )
                    .with_for_update()
                ).scalar_one_or_none()

                if replay is not None:
                    result = _verify_persisted_row(replay)

                    if (
                        result != statement
                        or statement.operation != "revoke"
                        or replay.active is not False
                        or replay.retired_at is None
                        or result.valid_from > timestamp
                        or result.expires_at <= timestamp
                    ):
                        raise DeviceBindingRegistryUnavailable()

                    prior_chain = _valid_device_chain(
                        session,
                        _locked_row(
                            session,
                            replay.prior_binding_id,
                        ),
                        expected_subject=result.subject,
                        expected_device=result.device_id,
                        head_active=False,
                        valid_at=timestamp,
                    )

                    prior = prior_chain.head

                    current = _locked_active_device(
                        session,
                        result.subject,
                        result.device_id,
                    )

                    if current is not None:
                        raise DeviceBindingRegistryUnavailable()

                    if (
                        result.prior_binding_id
                        != prior.binding_id
                        or result.binding_version
                        != prior.binding_version + 1
                        or result.public_key
                        != prior.public_key
                        or result.expires_at
                        > prior_chain.expires_at
                    ):
                        raise DeviceBindingRegistryUnavailable()

                    return result

                if (
                    statement.valid_from > timestamp
                    or statement.expires_at <= timestamp
                ):
                    raise DeviceBindingRegistryUnavailable()

                live_subject_devices = (
                    _cleanup_expired_subject_heads(
                        session,
                        statement.subject,
                        timestamp,
                    )
                )

                current_row = _locked_active_device(
                    session,
                    statement.subject,
                    statement.device_id,
                )

                current_chain = (
                    _valid_device_chain(
                        session,
                        current_row,
                        expected_subject=statement.subject,
                        expected_device=statement.device_id,
                        head_active=True,
                        valid_at=timestamp,
                    )
                    if current_row is not None
                    else None
                )

                current = (
                    current_chain.head
                    if current_chain is not None
                    else None
                )

                if statement.operation == "register":
                    any_history = session.execute(
                        select(
                            SocialMessagingDeviceBinding.binding_id
                        )
                        .where(
                            SocialMessagingDeviceBinding.subject_pubkey
                            == statement.subject,
                            SocialMessagingDeviceBinding.device_id
                            == statement.device_id,
                        )
                        .limit(1)
                    ).scalar_one_or_none()

                    if (
                        current is not None
                        or any_history is not None
                        or len(live_subject_devices)
                        >= MAX_ACTIVE_DEVICES
                    ):
                        raise DeviceBindingRegistryUnavailable()

                else:
                    if (
                        current is None
                        or current_chain is None
                    ):
                        raise DeviceBindingRegistryUnavailable()

                    if (
                        statement.prior_binding_id
                        != current.binding_id
                        or statement.binding_version
                        != current.binding_version + 1
                        or statement.expires_at
                        > current_chain.expires_at
                    ):
                        raise DeviceBindingRegistryUnavailable()

                    if (
                        statement.operation == "rotate"
                        and statement.public_key
                        == current.public_key
                    ):
                        raise DeviceBindingRegistryUnavailable()

                    if (
                        statement.operation == "revoke"
                        and statement.public_key
                        != current.public_key
                    ):
                        raise DeviceBindingRegistryUnavailable()

                if statement.operation != "revoke":
                    _prepare_public_key(
                        session,
                        statement,
                        timestamp,
                    )

                if current_row is not None:
                    retired = session.execute(
                        _retire(
                            current_row,
                            timestamp,
                        )
                    )

                    if retired.rowcount != 1:
                        raise DeviceBindingRegistryUnavailable()

                session.add(
                    _row(
                        statement,
                        timestamp,
                    )
                )

                session.flush()
                session.commit()

                return statement

        except DeviceBindingRegistryUnavailable:
            raise

        except (
            IntegrityError,
            SQLAlchemyError,
            TypeError,
            ValueError,
        ):
            raise DeviceBindingRegistryUnavailable() from None

        except Exception:
            raise DeviceBindingRegistryUnavailable() from None

    def current_for_subject(
        self,
        subject: str,
        now: datetime,
        maximum: int,
    ) -> list[DeviceBindingStatement]:
        try:
            timestamp = _aware(now)

            if (
                type(maximum) is not int
                or maximum < 0
                or maximum > MAX_ACTIVE_DEVICES
            ):
                raise DeviceBindingRegistryUnavailable()

            with self._session_factory() as session:
                rows = (
                    session.execute(
                        select(SocialMessagingDeviceBinding)
                        .where(
                            SocialMessagingDeviceBinding.subject_pubkey
                            == subject,
                            SocialMessagingDeviceBinding.active.is_(True),
                        )
                        .order_by(
                            SocialMessagingDeviceBinding.device_id,
                            SocialMessagingDeviceBinding.binding_version,
                        )
                        .limit(maximum + 1)
                        .with_for_update()
                    )
                    .scalars()
                    .all()
                )

                result = []

                for row in rows:
                    try:
                        chain = _valid_device_chain(
                            session,
                            row,
                            expected_subject=subject,
                            expected_device=row.device_id,
                            head_active=True,
                            valid_at=timestamp,
                        )
                    except DeviceBindingRegistryUnavailable:
                        chain = _valid_device_chain(
                            session,
                            row,
                            expected_subject=subject,
                            expected_device=row.device_id,
                            head_active=True,
                        )

                        if chain.expires_at > timestamp:
                            raise

                        continue

                    result.append(chain.head)

                if len(result) > maximum:
                    raise DeviceBindingRegistryUnavailable()

                session.rollback()

                return result

        except DeviceBindingRegistryUnavailable:
            raise

        except Exception:
            raise DeviceBindingRegistryUnavailable() from None


__all__ = [
    "SqlAlchemySocialMessagingDeviceBindingRepository",
]
