"""Atomic SQLAlchemy storage for X25519 identity-binding evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.models import X25519IdentityBinding
from app.services.x25519_identity_binding_registry import (
    BindingRegistryUnavailable,
    BindingStatement,
    SIGNATURE_FORMAT,
    STATEMENT_SCHEMA,
    SnapshotBinding,
    _parse_and_verify_dict,
)


def _aware(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _from_row(row: X25519IdentityBinding) -> BindingStatement:
    return BindingStatement(
        row.contract_version,
        row.subject_pubkey,
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


def _row(statement: BindingStatement, now: datetime) -> X25519IdentityBinding:
    active = statement.operation != "revoke"
    return X25519IdentityBinding(
        binding_id=statement.binding_id,
        contract_version=STATEMENT_SCHEMA,
        subject_pubkey=statement.subject,
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


def _verify_persisted_row(row: X25519IdentityBinding) -> BindingStatement:
    statement = _from_row(row)
    verified = _parse_and_verify_dict(statement.public_dict(), authenticated_subject=row.subject_pubkey)
    if verified != statement or row.binding_id != verified.digest or row.statement_sha256 != verified.digest:
        raise BindingRegistryUnavailable()
    return verified


def _locked_row(session, binding_id: str | None) -> X25519IdentityBinding:
    if not isinstance(binding_id, str):
        raise BindingRegistryUnavailable()
    row = session.execute(
        select(X25519IdentityBinding).where(X25519IdentityBinding.binding_id == binding_id).with_for_update()
    ).scalar_one_or_none()
    if row is None:
        raise BindingRegistryUnavailable()
    return row


@dataclass(frozen=True)
class _ValidatedAuthorityChain:
    head: BindingStatement
    expires_at: datetime


def _validate_successor_chain_contract(statements: list[BindingStatement]) -> datetime:
    ordered = list(reversed(statements))
    if not ordered or ordered[0].operation != "register":
        raise BindingRegistryUnavailable()

    predecessor = ordered[0]
    chain_expires_at = predecessor.expires_at
    for successor in ordered[1:]:
        if successor.operation != "rotate":
            raise BindingRegistryUnavailable()
        if successor.public_key == predecessor.public_key:
            raise BindingRegistryUnavailable()
        if successor.expires_at > chain_expires_at:
            raise BindingRegistryUnavailable()
        chain_expires_at = min(chain_expires_at, successor.expires_at)
        predecessor = successor
    return chain_expires_at


def _valid_authority_chain(
    session,
    head: X25519IdentityBinding,
    *,
    expected_subject: str,
    head_active: bool,
    valid_at: datetime | None = None,
) -> _ValidatedAuthorityChain:
    seen: set[str] = set()
    row = head
    successor: BindingStatement | None = None
    head_statement: BindingStatement | None = None
    chain_expires_at: datetime | None = None
    first = True
    depth = 0
    max_depth: int | None = None
    timestamp = _aware(valid_at) if valid_at is not None else None
    statements: list[BindingStatement] = []

    while True:
        if row.binding_id in seen:
            raise BindingRegistryUnavailable()
        seen.add(row.binding_id)

        depth += 1
        if max_depth is not None and depth > max_depth:
            raise BindingRegistryUnavailable()

        statement = _verify_persisted_row(row)
        statements.append(statement)
        chain_expires_at = (
            statement.expires_at if chain_expires_at is None else min(chain_expires_at, statement.expires_at)
        )
        if first:
            head_statement = statement
            max_depth = statement.binding_version
        if statement.subject != expected_subject or statement.operation not in {"register", "rotate"}:
            raise BindingRegistryUnavailable()
        if timestamp is not None and (statement.valid_from > timestamp or statement.expires_at <= timestamp):
            raise BindingRegistryUnavailable()
        if first:
            if head_active:
                if row.active is not True or row.retired_at is not None:
                    raise BindingRegistryUnavailable()
            elif row.active is not False or row.retired_at is None:
                raise BindingRegistryUnavailable()
        elif row.active is not False or row.retired_at is None:
            raise BindingRegistryUnavailable()

        if successor is not None and (
            successor.subject != statement.subject
            or successor.prior_binding_id != row.binding_id
            or successor.prior_binding_id != statement.binding_id
            or successor.binding_version != statement.binding_version + 1
        ):
            raise BindingRegistryUnavailable()

        if statement.operation == "register":
            if statement.binding_version != 1 or statement.prior_binding_id is not None:
                raise BindingRegistryUnavailable()
            if head_statement is None or chain_expires_at is None:
                raise BindingRegistryUnavailable()
            return _ValidatedAuthorityChain(
                head_statement,
                _validate_successor_chain_contract(statements),
            )

        if statement.binding_version <= 1 or statement.prior_binding_id is None:
            raise BindingRegistryUnavailable()

        successor = statement
        first = False
        row = _locked_row(session, statement.prior_binding_id)


def _locked_active_subject(session, subject: str) -> X25519IdentityBinding | None:
    return session.execute(
        select(X25519IdentityBinding)
        .where(
            X25519IdentityBinding.subject_pubkey == subject,
            X25519IdentityBinding.active.is_(True),
        )
        .with_for_update()
    ).scalar_one_or_none()


def _locked_active_public_key_rows(session, public_key: str) -> list[X25519IdentityBinding]:
    return list(
        session.execute(
            select(X25519IdentityBinding)
            .where(
                X25519IdentityBinding.public_key == public_key,
                X25519IdentityBinding.active.is_(True),
            )
            .with_for_update()
        )
        .scalars()
        .all()
    )


def _expired_key_conflicts_to_retire(
    session,
    statement: BindingStatement,
    timestamp: datetime,
) -> list[X25519IdentityBinding]:
    expired = []
    active_key_rows = _locked_active_public_key_rows(session, statement.public_key)
    if len(active_key_rows) > 1:
        raise BindingRegistryUnavailable()
    for row in active_key_rows:
        chain = _valid_authority_chain(session, row, expected_subject=row.subject_pubkey, head_active=True)
        if chain.expires_at > timestamp:
            raise BindingRegistryUnavailable()
        expired.append(row)
    return expired


def _retire(row: X25519IdentityBinding, timestamp: datetime):
    return (
        update(X25519IdentityBinding)
        .where(
            X25519IdentityBinding.binding_id == row.binding_id,
            X25519IdentityBinding.active.is_(True),
            X25519IdentityBinding.retired_at.is_(None),
        )
        .values(active=False, retired_at=timestamp)
    )


def _validate_all_active_rows(session, valid_at: datetime) -> None:
    timestamp = _aware(valid_at)
    rows = (
        session.execute(
            select(X25519IdentityBinding)
            .where(X25519IdentityBinding.active.is_(True))
            .order_by(X25519IdentityBinding.subject_pubkey, X25519IdentityBinding.binding_version)
            .with_for_update()
        )
        .scalars()
        .all()
    )
    for row in rows:
        _valid_authority_chain(
            session,
            row,
            expected_subject=row.subject_pubkey,
            head_active=True,
            valid_at=timestamp,
        )


class SqlAlchemyX25519IdentityBindingRepository:
    """Preserve the lifecycle chain and current-state transition atomically."""

    def __init__(self, session_factory):
        self._session_factory = session_factory

    def apply(self, statement: BindingStatement, now: datetime) -> BindingStatement:
        try:
            timestamp = _aware(now)
            with self._session_factory() as session:
                replay = session.execute(
                    select(X25519IdentityBinding)
                    .where(X25519IdentityBinding.binding_id == statement.binding_id)
                    .with_for_update()
                ).scalar_one_or_none()
                if replay is not None:
                    result = _verify_persisted_row(replay)
                    if (
                        result != statement
                        or statement.operation != "revoke"
                        or replay.active is not False
                        or replay.retired_at is None
                    ):
                        raise BindingRegistryUnavailable()
                    if result.valid_from > timestamp or result.expires_at <= timestamp:
                        raise BindingRegistryUnavailable()
                    prior_chain = _valid_authority_chain(
                        session,
                        _locked_row(session, replay.prior_binding_id),
                        expected_subject=result.subject,
                        head_active=False,
                        valid_at=timestamp,
                    )
                    prior = prior_chain.head
                    conflicting_current = _locked_active_subject(session, result.subject)
                    if conflicting_current is not None:
                        _valid_authority_chain(
                            session,
                            conflicting_current,
                            expected_subject=result.subject,
                            head_active=True,
                            valid_at=timestamp,
                        )
                        raise BindingRegistryUnavailable()
                    if (
                        result.prior_binding_id != prior.binding_id
                        or result.public_key != prior.public_key
                        or result.binding_version != prior.binding_version + 1
                        or result.expires_at > prior_chain.expires_at
                    ):
                        raise BindingRegistryUnavailable()
                    return result

                if statement.valid_from > timestamp or statement.expires_at <= timestamp:
                    raise BindingRegistryUnavailable()

                current_row = _locked_active_subject(session, statement.subject)
                current_chain = (
                    _valid_authority_chain(
                        session,
                        current_row,
                        expected_subject=statement.subject,
                        head_active=True,
                        valid_at=timestamp,
                    )
                    if current_row is not None
                    else None
                )
                current = current_chain.head if current_chain is not None else None

                if statement.operation == "register":
                    any_history = session.execute(
                        select(X25519IdentityBinding.binding_id)
                        .where(X25519IdentityBinding.subject_pubkey == statement.subject)
                        .limit(1)
                    ).scalar_one_or_none()
                    if current is not None or any_history is not None:
                        raise BindingRegistryUnavailable()
                else:
                    if current is None or current_chain is None:
                        raise BindingRegistryUnavailable()
                    if (
                        current.valid_from > timestamp
                        or current.expires_at <= timestamp
                        or statement.prior_binding_id != current.binding_id
                        or statement.binding_version != current.binding_version + 1
                        or statement.expires_at > current_chain.expires_at
                    ):
                        raise BindingRegistryUnavailable()
                    if statement.operation == "revoke" and statement.public_key != current.public_key:
                        raise BindingRegistryUnavailable()
                    if statement.operation == "rotate" and statement.public_key == current.public_key:
                        raise BindingRegistryUnavailable()

                expired_key_conflicts = (
                    _expired_key_conflicts_to_retire(session, statement, timestamp)
                    if statement.operation != "revoke"
                    else []
                )

                for conflict in expired_key_conflicts:
                    retired = session.execute(_retire(conflict, conflict.expires_at))
                    if retired.rowcount != 1:
                        raise BindingRegistryUnavailable()
                if current_row is not None:
                    retired = session.execute(_retire(current_row, timestamp))
                    if retired.rowcount != 1:
                        raise BindingRegistryUnavailable()

                session.add(_row(statement, timestamp))
                session.flush()
                session.commit()
                return statement
        except BindingRegistryUnavailable:
            raise
        except (IntegrityError, SQLAlchemyError, TypeError, ValueError):
            raise BindingRegistryUnavailable() from None
        except Exception:
            raise BindingRegistryUnavailable() from None

    def current_snapshot(self, now: datetime, maximum: int) -> list[SnapshotBinding]:
        try:
            timestamp = _aware(now)
            with self._session_factory() as session:
                transaction = session.begin()
                try:
                    # The explicit read transaction starts before candidate
                    # selection and also contains predecessor-chain validation.
                    _validate_all_active_rows(session, timestamp)
                    rows = (
                        session.execute(
                            select(X25519IdentityBinding)
                            .where(
                                X25519IdentityBinding.active.is_(True),
                                X25519IdentityBinding.operation.in_(("register", "rotate")),
                                X25519IdentityBinding.valid_from <= timestamp,
                                X25519IdentityBinding.expires_at > timestamp,
                            )
                            .order_by(X25519IdentityBinding.subject_pubkey)
                            .limit(maximum + 1)
                            .with_for_update()
                        )
                        .scalars()
                        .all()
                    )
                    if len(rows) > maximum:
                        raise BindingRegistryUnavailable()
                    result = []
                    for row in rows:
                        chain = _valid_authority_chain(
                            session,
                            row,
                            expected_subject=row.subject_pubkey,
                            head_active=True,
                            valid_at=timestamp,
                        )
                        result.append(SnapshotBinding(chain.head, chain.expires_at))
                except Exception:
                    if transaction.is_active:
                        transaction.rollback()
                    raise
                if transaction.is_active:
                    transaction.rollback()
                return result
        except BindingRegistryUnavailable:
            raise
        except Exception:
            raise BindingRegistryUnavailable() from None
