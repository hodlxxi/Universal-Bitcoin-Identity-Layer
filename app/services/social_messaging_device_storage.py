"""Durable SQLAlchemy storage for Social multi-device X25519 bindings.

This module is intentionally private to the messaging-device authority. It does
not register routes, validate OAuth tokens, or decide whether a subject is
currently Full. The caller must provide a canonical server-derived subject.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    select,
    text,
    update,
)
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.auth_api_core import canonical_xonly_pubkey
from app.models import Base, User, _CanonicalLowerHex
from app.services.full_recipient_directory_provider import validate_x25519_public_key
from app.services.social_messaging_device_contract import (
    ALGORITHM,
    MAX_ACTIVE_DEVICES,
    MAX_BINDING_VERSION,
    MessagingDeviceAuthorityUnavailable,
    MessagingDeviceBinding,
    MessagingDeviceCommand,
)

RECORD_SCHEMA = "hodlxxi.social_messaging_device_binding_record.v1"
MIN_BINDING_LIFETIME_SECONDS = 300
MAX_BINDING_LIFETIME_SECONDS = 31_536_000


class SocialMessagingDeviceBindingRow(Base):
    """Append-only lifecycle evidence for one Social messaging device."""

    __tablename__ = "social_messaging_device_bindings"

    binding_id = Column(String(64), primary_key=True)
    record_schema = Column(String(64), nullable=False)
    subject_pubkey = Column(String(64), nullable=False)
    device_id = Column(String(64), nullable=False)
    algorithm = Column(String(16), nullable=False)
    public_key = Column(String(64), nullable=False)
    binding_version = Column(BigInteger, nullable=False)
    valid_from = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    operation = Column(String(8), nullable=False)
    prior_binding_id = Column(
        String(64),
        ForeignKey(
            "social_messaging_device_bindings.binding_id",
            name="fk_social_messaging_device_prior",
        ),
    )
    request_id = Column(String(64), nullable=False)
    active = Column(Boolean, nullable=False)
    retired_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "subject_pubkey",
            "device_id",
            "binding_version",
            name="uq_social_messaging_device_subject_device_version",
        ),
        UniqueConstraint(
            "subject_pubkey",
            "request_id",
            name="uq_social_messaging_device_subject_request",
        ),
        CheckConstraint(
            "record_schema = 'hodlxxi.social_messaging_device_binding_record.v1'",
            name="ck_social_messaging_device_schema",
        ),
        CheckConstraint(
            "algorithm = 'x25519-v1'",
            name="ck_social_messaging_device_algorithm",
        ),
        CheckConstraint(
            _CanonicalLowerHex("binding_id", 64),
            name="ck_social_messaging_device_binding_id",
        ),
        CheckConstraint(
            _CanonicalLowerHex("subject_pubkey", 64),
            name="ck_social_messaging_device_subject",
        ),
        CheckConstraint(
            _CanonicalLowerHex("device_id", 64),
            name="ck_social_messaging_device_device_id",
        ),
        CheckConstraint(
            _CanonicalLowerHex("public_key", 64),
            name="ck_social_messaging_device_public_key",
        ),
        CheckConstraint(
            _CanonicalLowerHex("request_id", 64),
            name="ck_social_messaging_device_request_id",
        ),
        CheckConstraint(
            "binding_version BETWEEN 1 AND 1024",
            name="ck_social_messaging_device_version",
        ),
        CheckConstraint(
            "valid_from < expires_at",
            name="ck_social_messaging_device_validity",
        ),
        CheckConstraint(
            "operation IN ('register','rotate','revoke')",
            name="ck_social_messaging_device_operation",
        ),
        CheckConstraint(
            "(operation = 'register' AND prior_binding_id IS NULL AND binding_version = 1) OR "
            "(operation IN ('rotate','revoke') AND prior_binding_id IS NOT NULL AND binding_version >= 2)",
            name="ck_social_messaging_device_prior",
        ),
        CheckConstraint(
            "(active = true AND operation IN ('register','rotate') AND retired_at IS NULL) OR "
            "(active = false AND retired_at IS NOT NULL)",
            name="ck_social_messaging_device_active_state",
        ),
        Index(
            "uq_social_messaging_device_active_device",
            "subject_pubkey",
            "device_id",
            unique=True,
            postgresql_where=text("active = true"),
            sqlite_where=text("active = true"),
        ),
        Index(
            "uq_social_messaging_device_active_public_key",
            "public_key",
            unique=True,
            postgresql_where=text("active = true"),
            sqlite_where=text("active = true"),
        ),
        Index(
            "idx_social_messaging_device_current_subject",
            "subject_pubkey",
            "active",
            "device_id",
        ),
        Index(
            "idx_social_messaging_device_expires_at",
            "expires_at",
        ),
    )


def _canonical_subject(value: object) -> str:
    try:
        if type(value) is not str:
            raise ValueError
        canonical = canonical_xonly_pubkey(value)
        if canonical != value:
            raise ValueError
        return canonical
    except Exception:
        raise MessagingDeviceAuthorityUnavailable() from None


def _hex64(value: object) -> str:
    if type(value) is not str or len(value) != 64:
        raise MessagingDeviceAuthorityUnavailable()
    try:
        if bytes.fromhex(value).hex() != value:
            raise ValueError
    except Exception:
        raise MessagingDeviceAuthorityUnavailable() from None
    return value


def _trusted_utc_second(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise MessagingDeviceAuthorityUnavailable()
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        raise MessagingDeviceAuthorityUnavailable()
    return normalized


def _db_utc_second(value: object) -> datetime:
    if not isinstance(value, datetime):
        raise MessagingDeviceAuthorityUnavailable()
    normalized = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    if normalized.microsecond:
        raise MessagingDeviceAuthorityUnavailable()
    return normalized


def _timestamp(value: datetime) -> str:
    return _db_utc_second(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def _record_core(
    *,
    subject: str,
    device_id: str,
    public_key: str,
    version: int,
    valid_from: datetime,
    expires_at: datetime,
    operation: str,
    prior_binding_id: str | None,
    request_id: str,
) -> dict[str, object]:
    return {
        "schema": RECORD_SCHEMA,
        "version": 1,
        "subject": subject,
        "deviceId": device_id,
        "algorithm": ALGORITHM,
        "publicKey": public_key,
        "bindingVersion": version,
        "validFrom": _timestamp(valid_from),
        "expiresAt": _timestamp(expires_at),
        "operation": operation,
        "priorBindingId": prior_binding_id,
        "requestId": request_id,
    }


def _binding_id(**values) -> str:
    canonical = json.dumps(
        _record_core(**values),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _validated_command(command: object) -> MessagingDeviceCommand:
    try:
        if type(command) is not MessagingDeviceCommand:
            raise ValueError
        if command.operation not in {"register", "rotate", "revoke"}:
            raise ValueError
        device_id = _hex64(command.device_id)
        request_id = _hex64(command.request_id)
        expected = command.expected_binding_id
        public_key = command.public_key
        if command.operation == "register":
            if expected is not None:
                raise ValueError
        else:
            expected = _hex64(expected)
        if command.operation == "revoke":
            if public_key is not None:
                raise ValueError
            normalized_key = None
        else:
            normalized_key = validate_x25519_public_key(public_key)
        return MessagingDeviceCommand(
            command.operation,
            device_id,
            normalized_key,
            expected,
            request_id,
        )
    except MessagingDeviceAuthorityUnavailable:
        raise
    except Exception:
        raise MessagingDeviceAuthorityUnavailable() from None


def _from_row(row: SocialMessagingDeviceBindingRow) -> MessagingDeviceBinding:
    try:
        if not isinstance(row, SocialMessagingDeviceBindingRow):
            raise ValueError
        subject = _canonical_subject(row.subject_pubkey)
        device_id = _hex64(row.device_id)
        binding_id = _hex64(row.binding_id)
        public_key = validate_x25519_public_key(row.public_key)
        request_id = _hex64(row.request_id)
        version = row.binding_version
        if type(version) is not int or not 1 <= version <= MAX_BINDING_VERSION:
            raise ValueError
        valid_from = _db_utc_second(row.valid_from)
        expires_at = _db_utc_second(row.expires_at)
        if valid_from >= expires_at:
            raise ValueError
        if row.record_schema != RECORD_SCHEMA or row.algorithm != ALGORITHM:
            raise ValueError
        operation = row.operation
        if operation not in {"register", "rotate", "revoke"}:
            raise ValueError
        prior = row.prior_binding_id
        if operation == "register":
            if prior is not None or version != 1:
                raise ValueError
        else:
            prior = _hex64(prior)
            if version <= 1 or prior == binding_id:
                raise ValueError
        if type(row.active) is not bool:
            raise ValueError
        retired_at = None if row.retired_at is None else _db_utc_second(row.retired_at)
        if row.active:
            if operation == "revoke" or retired_at is not None:
                raise ValueError
        else:
            if retired_at is None or retired_at < valid_from or retired_at > expires_at:
                raise ValueError
        expected = _binding_id(
            subject=subject,
            device_id=device_id,
            public_key=public_key,
            version=version,
            valid_from=valid_from,
            expires_at=expires_at,
            operation=operation,
            prior_binding_id=prior,
            request_id=request_id,
        )
        if binding_id != expected:
            raise ValueError
        return MessagingDeviceBinding(
            subject=subject,
            device_id=device_id,
            binding_id=binding_id,
            public_key=public_key,
            binding_version=version,
            valid_from=valid_from,
            expires_at=expires_at,
            operation=operation,
            prior_binding_id=prior,
            request_id=request_id,
            active=row.active,
        )
    except MessagingDeviceAuthorityUnavailable:
        raise
    except Exception:
        raise MessagingDeviceAuthorityUnavailable() from None


def _lock_subject_user(session, subject: str) -> None:
    user_id = session.execute(select(User.id).where(User.pubkey == subject).with_for_update()).scalar_one_or_none()
    if user_id is None:
        raise MessagingDeviceAuthorityUnavailable()


def _retire(row: SocialMessagingDeviceBindingRow, timestamp: datetime):
    return (
        update(SocialMessagingDeviceBindingRow)
        .where(
            SocialMessagingDeviceBindingRow.binding_id == row.binding_id,
            SocialMessagingDeviceBindingRow.active.is_(True),
            SocialMessagingDeviceBindingRow.retired_at.is_(None),
        )
        .values(active=False, retired_at=timestamp)
    )


def _retire_expired_subject_rows(session, subject: str, now: datetime) -> None:
    rows = list(
        session.execute(
            select(SocialMessagingDeviceBindingRow)
            .where(
                SocialMessagingDeviceBindingRow.subject_pubkey == subject,
                SocialMessagingDeviceBindingRow.active.is_(True),
            )
            .order_by(SocialMessagingDeviceBindingRow.device_id)
            .limit(MAX_ACTIVE_DEVICES + 1)
            .with_for_update()
        )
        .scalars()
        .all()
    )
    if len(rows) > MAX_ACTIVE_DEVICES:
        raise MessagingDeviceAuthorityUnavailable()
    for row in rows:
        binding = _from_row(row)
        if binding.valid_from > now:
            raise MessagingDeviceAuthorityUnavailable()
        if binding.expires_at <= now:
            retired = session.execute(_retire(row, binding.expires_at))
            if retired.rowcount != 1:
                raise MessagingDeviceAuthorityUnavailable()


def _active_device_row(session, subject: str, device_id: str):
    return session.execute(
        select(SocialMessagingDeviceBindingRow)
        .where(
            SocialMessagingDeviceBindingRow.subject_pubkey == subject,
            SocialMessagingDeviceBindingRow.device_id == device_id,
            SocialMessagingDeviceBindingRow.active.is_(True),
        )
        .with_for_update()
    ).scalar_one_or_none()


def _request_row(session, subject: str, request_id: str):
    return session.execute(
        select(SocialMessagingDeviceBindingRow)
        .where(
            SocialMessagingDeviceBindingRow.subject_pubkey == subject,
            SocialMessagingDeviceBindingRow.request_id == request_id,
        )
        .with_for_update()
    ).scalar_one_or_none()


def _device_has_history(session, subject: str, device_id: str) -> bool:
    return (
        session.execute(
            select(SocialMessagingDeviceBindingRow.binding_id)
            .where(
                SocialMessagingDeviceBindingRow.subject_pubkey == subject,
                SocialMessagingDeviceBindingRow.device_id == device_id,
            )
            .limit(1)
        ).scalar_one_or_none()
        is not None
    )


def _public_key_was_used(session, public_key: str) -> bool:
    return (
        session.execute(
            select(SocialMessagingDeviceBindingRow.binding_id)
            .where(
                SocialMessagingDeviceBindingRow.public_key == public_key,
                SocialMessagingDeviceBindingRow.operation.in_(("register", "rotate")),
            )
            .limit(1)
        ).scalar_one_or_none()
        is not None
    )


def _active_count(session, subject: str, now: datetime) -> int:
    rows = list(
        session.execute(
            select(SocialMessagingDeviceBindingRow.binding_id)
            .where(
                SocialMessagingDeviceBindingRow.subject_pubkey == subject,
                SocialMessagingDeviceBindingRow.active.is_(True),
                SocialMessagingDeviceBindingRow.valid_from <= now,
                SocialMessagingDeviceBindingRow.expires_at > now,
            )
            .limit(MAX_ACTIVE_DEVICES + 1)
        ).scalars()
    )
    if len(rows) > MAX_ACTIVE_DEVICES:
        raise MessagingDeviceAuthorityUnavailable()
    return len(rows)


def _replay_matches(
    binding: MessagingDeviceBinding,
    command: MessagingDeviceCommand,
) -> bool:
    return (
        binding.device_id == command.device_id
        and binding.operation == command.operation
        and binding.prior_binding_id == command.expected_binding_id
        and binding.request_id == command.request_id
        and (command.operation == "revoke" or binding.public_key == command.public_key)
        and (command.operation == "revoke" or binding.active is True)
    )


class SqlAlchemySocialMessagingDeviceRepository:
    """Atomic multi-device lifecycle storage with per-subject serialization."""

    def __init__(
        self,
        session_factory,
        *,
        binding_lifetime_seconds: int,
    ) -> None:
        if (
            not callable(session_factory)
            or type(binding_lifetime_seconds) is not int
            or not MIN_BINDING_LIFETIME_SECONDS <= binding_lifetime_seconds <= MAX_BINDING_LIFETIME_SECONDS
        ):
            raise ValueError("invalid messaging device storage configuration")
        self._session_factory = session_factory
        self._binding_lifetime = timedelta(seconds=binding_lifetime_seconds)

    def apply(
        self,
        command: MessagingDeviceCommand,
        *,
        subject: str,
        now: datetime,
    ) -> MessagingDeviceBinding:
        try:
            canonical_subject = _canonical_subject(subject)
            normalized_command = _validated_command(command)
            timestamp = _trusted_utc_second(now)

            with self._session_factory() as session:
                _lock_subject_user(session, canonical_subject)

                replay = _request_row(
                    session,
                    canonical_subject,
                    normalized_command.request_id,
                )
                if replay is not None:
                    result = _from_row(replay)
                    if not _replay_matches(result, normalized_command):
                        raise MessagingDeviceAuthorityUnavailable()
                    return result

                _retire_expired_subject_rows(session, canonical_subject, timestamp)
                current_row = _active_device_row(
                    session,
                    canonical_subject,
                    normalized_command.device_id,
                )
                current = None if current_row is None else _from_row(current_row)

                if normalized_command.operation == "register":
                    if current is not None or _device_has_history(
                        session,
                        canonical_subject,
                        normalized_command.device_id,
                    ):
                        raise MessagingDeviceAuthorityUnavailable()
                    if normalized_command.public_key is None:
                        raise MessagingDeviceAuthorityUnavailable()
                    if _public_key_was_used(session, normalized_command.public_key):
                        raise MessagingDeviceAuthorityUnavailable()
                    if _active_count(session, canonical_subject, timestamp) >= MAX_ACTIVE_DEVICES:
                        raise MessagingDeviceAuthorityUnavailable()
                    version = 1
                    prior = None
                    public_key = normalized_command.public_key
                    expires_at = timestamp + self._binding_lifetime
                    active = True
                else:
                    if (
                        current is None
                        or current_row is None
                        or current.active is not True
                        or current.valid_from > timestamp
                        or current.expires_at <= timestamp
                        or current.binding_id != normalized_command.expected_binding_id
                    ):
                        raise MessagingDeviceAuthorityUnavailable()
                    version = current.binding_version + 1
                    if version > MAX_BINDING_VERSION:
                        raise MessagingDeviceAuthorityUnavailable()
                    prior = current.binding_id
                    if normalized_command.operation == "rotate":
                        if (
                            normalized_command.public_key is None
                            or normalized_command.public_key == current.public_key
                            or _public_key_was_used(session, normalized_command.public_key)
                        ):
                            raise MessagingDeviceAuthorityUnavailable()
                        public_key = normalized_command.public_key
                        expires_at = timestamp + self._binding_lifetime
                        active = True
                    else:
                        public_key = current.public_key
                        expires_at = current.expires_at
                        active = False

                    retired = session.execute(_retire(current_row, timestamp))
                    if retired.rowcount != 1:
                        raise MessagingDeviceAuthorityUnavailable()

                binding_id = _binding_id(
                    subject=canonical_subject,
                    device_id=normalized_command.device_id,
                    public_key=public_key,
                    version=version,
                    valid_from=timestamp,
                    expires_at=expires_at,
                    operation=normalized_command.operation,
                    prior_binding_id=prior,
                    request_id=normalized_command.request_id,
                )
                row = SocialMessagingDeviceBindingRow(
                    binding_id=binding_id,
                    record_schema=RECORD_SCHEMA,
                    subject_pubkey=canonical_subject,
                    device_id=normalized_command.device_id,
                    algorithm=ALGORITHM,
                    public_key=public_key,
                    binding_version=version,
                    valid_from=timestamp,
                    expires_at=expires_at,
                    operation=normalized_command.operation,
                    prior_binding_id=prior,
                    request_id=normalized_command.request_id,
                    active=active,
                    retired_at=None if active else timestamp,
                    created_at=timestamp,
                )
                session.add(row)
                session.flush()
                result = _from_row(row)
                session.commit()
                return result
        except MessagingDeviceAuthorityUnavailable:
            raise
        except (IntegrityError, SQLAlchemyError, TypeError, ValueError):
            raise MessagingDeviceAuthorityUnavailable() from None
        except Exception:
            raise MessagingDeviceAuthorityUnavailable() from None

    def current_for_subject(
        self,
        subject: str,
        *,
        now: datetime,
        maximum: int,
    ) -> list[MessagingDeviceBinding]:
        try:
            canonical_subject = _canonical_subject(subject)
            timestamp = _trusted_utc_second(now)
            if type(maximum) is not int or not 0 <= maximum <= MAX_ACTIVE_DEVICES:
                raise MessagingDeviceAuthorityUnavailable()

            with self._session_factory() as session:
                rows = list(
                    session.execute(
                        select(SocialMessagingDeviceBindingRow)
                        .where(
                            SocialMessagingDeviceBindingRow.subject_pubkey == canonical_subject,
                            SocialMessagingDeviceBindingRow.active.is_(True),
                            SocialMessagingDeviceBindingRow.valid_from <= timestamp,
                            SocialMessagingDeviceBindingRow.expires_at > timestamp,
                        )
                        .order_by(SocialMessagingDeviceBindingRow.device_id)
                        .limit(maximum + 1)
                    )
                    .scalars()
                    .all()
                )
                if len(rows) > maximum:
                    raise MessagingDeviceAuthorityUnavailable()
                bindings = [_from_row(row) for row in rows]
                if any(
                    binding.subject != canonical_subject
                    or binding.active is not True
                    or binding.operation not in {"register", "rotate"}
                    or binding.valid_from > timestamp
                    or binding.expires_at <= timestamp
                    for binding in bindings
                ):
                    raise MessagingDeviceAuthorityUnavailable()
                return bindings
        except MessagingDeviceAuthorityUnavailable:
            raise
        except Exception:
            raise MessagingDeviceAuthorityUnavailable() from None


__all__ = [
    "MAX_BINDING_LIFETIME_SECONDS",
    "MIN_BINDING_LIFETIME_SECONDS",
    "RECORD_SCHEMA",
    "SocialMessagingDeviceBindingRow",
    "SqlAlchemySocialMessagingDeviceRepository",
]
