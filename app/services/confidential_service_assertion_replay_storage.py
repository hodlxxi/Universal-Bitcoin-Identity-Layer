"""Durable PostgreSQL replay markers for confidential client assertions."""

from __future__ import annotations

import hashlib

from sqlalchemy import text

from app.services.confidential_service_credentials import MAX_JTI_LENGTH

MAX_POSTGRES_BIGINT = 9_223_372_036_854_775_807

_CONSUME_SQL = text("""
    INSERT INTO confidential_service_assertion_replay_markers (
        jti_sha256,
        retention_deadline_exclusive
    )
    SELECT
        :jti_sha256,
        :retention_deadline_exclusive
    WHERE :retention_deadline_exclusive >
        CAST(FLOOR(EXTRACT(EPOCH FROM clock_timestamp())) AS BIGINT)
    ON CONFLICT (jti_sha256) DO NOTHING
    RETURNING jti_sha256
    """)

_CLEANUP_SQL = text("""
    DELETE FROM confidential_service_assertion_replay_markers
    WHERE retention_deadline_exclusive <=
        CAST(FLOOR(EXTRACT(EPOCH FROM clock_timestamp())) AS BIGINT)
    """)


def _digest_jti(jti: object) -> str | None:
    if not isinstance(jti, str) or not jti or len(jti) > MAX_JTI_LENGTH or jti.strip() != jti:
        return None
    try:
        return hashlib.sha256(jti.encode("utf-8", errors="strict")).hexdigest()
    except (UnicodeEncodeError, UnicodeError):
        return None


def _deadline(value: object) -> int | None:
    if type(value) is not int or not 0 < value <= MAX_POSTGRES_BIGINT:
        return None
    return value


class PostgresConfidentialServiceAssertionReplayStore:
    """Injectable, fail-closed replay_consumer(jti, deadline) adapter."""

    def __init__(self, session_factory) -> None:
        if not callable(session_factory):
            raise ValueError("invalid replay store session factory")
        self._session_factory = session_factory

    def __call__(self, jti: str, retention_deadline_exclusive: int) -> bool:
        digest = _digest_jti(jti)
        deadline = _deadline(retention_deadline_exclusive)
        if digest is None or deadline is None:
            return False

        try:
            with self._session_factory() as session:
                result = session.execute(
                    _CONSUME_SQL,
                    {
                        "jti_sha256": digest,
                        "retention_deadline_exclusive": deadline,
                    },
                )
                inserted = result.scalar_one_or_none()
                if inserted != digest:
                    session.rollback()
                    return False
                session.commit()
                return True
        except Exception:
            return False

    def cleanup_expired(self) -> int:
        """Delete only markers whose exclusive deadline has arrived."""

        try:
            with self._session_factory() as session:
                result = session.execute(_CLEANUP_SQL)
                deleted = result.rowcount
                if type(deleted) is not int or deleted < 0:
                    session.rollback()
                    return 0
                session.commit()
                return deleted
        except Exception:
            return 0


__all__ = ["PostgresConfidentialServiceAssertionReplayStore"]
