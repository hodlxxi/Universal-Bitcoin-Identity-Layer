"""Transaction-bound PostgreSQL storage for device-binding authorization.

The caller owns the active ``Session`` and its transaction.  This module never
begins, commits, rolls back, closes, or replaces either one.  It deliberately
contains no runtime composition or route registration.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
    select,
    text,
)
from sqlalchemy.exc import SQLAlchemyError

from app.models import Base, _CanonicalLowerHex
from app.services.current_entitlement_evidence_storage import (
    SqlAlchemyTransactionBoundCurrentFullVerifier,
    _lock_subject_for_evidence_change,
)
from app.services.social_messaging_device_binding_authorization import (
    MAX_STATE_RECORDS,
    PROOF_ID_PREFIX,
    STATE_SCHEMA,
    VERSION,
    AdoptedDeviceBindingAuthorization,
    AdoptionReplayRecord,
    AuthorizationReplayRecord,
    AuthorizedDeviceBinding,
    BindingAuthorizationEvidence,
    BindingAuthorizationEvidenceState,
    Bip340IdentitySignatureVerifier,
    CurrentDeviceBindingState,
    CurrentLegacyDeviceBindingState,
    CurrentPublicKeyBindingState,
    CurrentSubjectBindingState,
    DeviceBindingAuthorizationUnavailable,
    IdentitySignatureVerifier,
    IdentitySignedDeviceBindingAdoption,
    IdentitySignedDeviceBindingAuthorization,
    SocialMessagingDeviceBindingAuthorizationV1,
    SocialMessagingLegacyBindingAdoptionV1,
    _validated_adoption_replay,
    _validated_replay,
    canonical_adoption_json,
    canonical_authorization_json,
    canonical_authorization_result_bytes,
    parse_and_verify_device_binding_adoption,
    parse_and_verify_device_binding_authorization,
)
from app.services.social_messaging_device_binding_authorization_intent import (
    TrustedAuthorizationIntent,
    derive_trusted_authorization_intent,
    parse_authorization_intent_proposal,
)
from app.services.social_messaging_device_contract import MAX_ACTIVE_DEVICES, MessagingDeviceBinding
from app.services.social_messaging_device_storage import (
    SocialMessagingDeviceBindingRow,
    SqlAlchemyTransactionBoundSocialMessagingDeviceStorage,
    _from_row,
    _lock_subject_user,
)
from app.services.social_messaging_recipient_routing import VerifiedBindingAuthorization

EVIDENCE_TABLE = "social_messaging_device_binding_authorization_evidence"
REPLAY_TABLE = "social_messaging_device_binding_authorization_replay"
MAX_PERSISTED_PAYLOAD_BYTES = 8_192

_REQUEST_LOCK_DOMAIN = b"HODLXXI_SOCIAL_DEVICE_AUTHORIZATION_REQUEST_LOCK_V1\x00"
_DEVICE_LOCK_DOMAIN = b"HODLXXI_SOCIAL_DEVICE_AUTHORIZATION_DEVICE_LOCK_V1\x00"
_PUBLIC_KEY_LOCK_DOMAIN = b"HODLXXI_SOCIAL_DEVICE_AUTHORIZATION_PUBLIC_KEY_LOCK_V1\x00"
_PUBLIC_KEY_GUARD_DOMAIN = b"HODLXXI_SOCIAL_DEVICE_AUTHORIZATION_PUBLIC_KEY_GUARD_V1\x00"


class _ExpiredUnacceptedAuthorization(RuntimeError):
    """An authenticated, locked request has no replay winner and is expired."""


class SocialMessagingDeviceBindingAuthorizationEvidenceRow(Base):
    """The one immutable identity authorization for a binding."""

    __tablename__ = EVIDENCE_TABLE

    binding_id = Column(String(64), primary_key=True)
    evidence_type = Column(String(9), nullable=False)
    action = Column(String(8), nullable=False)
    request_id = Column(String(64), nullable=False)
    digest = Column(String(64), nullable=False)
    canonical_payload = Column(Text, nullable=False)
    subject_pubkey = Column(String(64), nullable=False)
    device_id = Column(String(64), nullable=False)
    public_key = Column(String(64), nullable=False)
    binding_version = Column(BigInteger, nullable=False)
    binding_operation = Column(String(8), nullable=False)
    binding_valid_from = Column(DateTime(timezone=True), nullable=False)
    binding_expires_at = Column(DateTime(timezone=True), nullable=False)
    evidence_valid_from = Column(DateTime(timezone=True), nullable=False)
    evidence_expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            (
                "binding_id",
                "subject_pubkey",
                "device_id",
                "public_key",
                "binding_version",
                "binding_operation",
                "binding_valid_from",
                "binding_expires_at",
            ),
            (
                "social_messaging_device_bindings.binding_id",
                "social_messaging_device_bindings.subject_pubkey",
                "social_messaging_device_bindings.device_id",
                "social_messaging_device_bindings.public_key",
                "social_messaging_device_bindings.binding_version",
                "social_messaging_device_bindings.operation",
                "social_messaging_device_bindings.valid_from",
                "social_messaging_device_bindings.expires_at",
            ),
            name="fk_social_device_authorization_evidence_binding",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "request_id",
            name="uq_social_device_authorization_evidence_request",
        ),
        UniqueConstraint(
            "digest",
            name="uq_social_device_authorization_evidence_digest",
        ),
        UniqueConstraint(
            "binding_id",
            "request_id",
            "digest",
            "evidence_type",
            "action",
            name="uq_social_device_authorization_evidence_replay_identity",
        ),
        CheckConstraint(
            "evidence_type IN ('lifecycle','adoption')",
            name="ck_social_device_authorization_evidence_type",
        ),
        CheckConstraint(
            "(evidence_type = 'lifecycle' AND action IN ('register','rotate','revoke') "
            "AND action = binding_operation) OR "
            "(evidence_type = 'adoption' AND action = 'adopt' "
            "AND binding_operation IN ('register','rotate'))",
            name="ck_social_device_authorization_evidence_action",
        ),
        CheckConstraint(
            _CanonicalLowerHex("binding_id", 64),
            name="ck_social_device_authorization_evidence_binding_id",
        ),
        CheckConstraint(
            _CanonicalLowerHex("request_id", 64),
            name="ck_social_device_authorization_evidence_request_id",
        ),
        CheckConstraint(
            _CanonicalLowerHex("digest", 64),
            name="ck_social_device_authorization_evidence_digest",
        ),
        CheckConstraint(
            _CanonicalLowerHex("subject_pubkey", 64),
            name="ck_social_device_authorization_evidence_subject",
        ),
        CheckConstraint(
            _CanonicalLowerHex("device_id", 64),
            name="ck_social_device_authorization_evidence_device",
        ),
        CheckConstraint(
            _CanonicalLowerHex("public_key", 64),
            name="ck_social_device_authorization_evidence_public_key",
        ),
        CheckConstraint(
            "binding_version BETWEEN 1 AND 1024",
            name="ck_social_device_authorization_evidence_version",
        ),
        CheckConstraint(
            "binding_valid_from < binding_expires_at",
            name="ck_social_device_authorization_evidence_binding_validity",
        ),
        CheckConstraint(
            "binding_valid_from <= evidence_valid_from "
            "AND evidence_valid_from < evidence_expires_at "
            "AND evidence_expires_at <= binding_expires_at",
            name="ck_social_device_authorization_evidence_validity",
        ),
        CheckConstraint(
            "octet_length(canonical_payload) BETWEEN 1 AND 8192",
            name="ck_social_device_authorization_evidence_payload",
        ),
        Index(
            "idx_social_device_authorization_evidence_subject_device",
            "subject_pubkey",
            "device_id",
            "binding_version",
        ),
        Index(
            "idx_social_device_authorization_evidence_public_key",
            "public_key",
        ),
        Index(
            "idx_social_device_authorization_evidence_window",
            "evidence_valid_from",
            "evidence_expires_at",
        ),
    )


class SocialMessagingDeviceBindingAuthorizationReplayRow(Base):
    """One immutable result in the global lifecycle-and-adoption namespace."""

    __tablename__ = REPLAY_TABLE

    request_id = Column(String(64), primary_key=True)
    record_type = Column(String(9), nullable=False)
    action = Column(String(8), nullable=False)
    digest = Column(String(64), nullable=False)
    result_binding_id = Column(String(64), nullable=False)
    result_proof_id = Column(String(112), nullable=False)
    result_payload = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            (
                "result_binding_id",
                "request_id",
                "digest",
                "record_type",
                "action",
            ),
            (
                f"{EVIDENCE_TABLE}.binding_id",
                f"{EVIDENCE_TABLE}.request_id",
                f"{EVIDENCE_TABLE}.digest",
                f"{EVIDENCE_TABLE}.evidence_type",
                f"{EVIDENCE_TABLE}.action",
            ),
            name="fk_social_device_authorization_replay_evidence",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        CheckConstraint(
            "record_type IN ('lifecycle','adoption')",
            name="ck_social_device_authorization_replay_type",
        ),
        CheckConstraint(
            "(record_type = 'lifecycle' AND action IN ('register','rotate','revoke')) "
            "OR (record_type = 'adoption' AND action = 'adopt')",
            name="ck_social_device_authorization_replay_action",
        ),
        CheckConstraint(
            _CanonicalLowerHex("request_id", 64),
            name="ck_social_device_authorization_replay_request_id",
        ),
        CheckConstraint(
            _CanonicalLowerHex("digest", 64),
            name="ck_social_device_authorization_replay_digest",
        ),
        CheckConstraint(
            _CanonicalLowerHex("result_binding_id", 64),
            name="ck_social_device_authorization_replay_binding_id",
        ),
        CheckConstraint(
            "result_proof_id = 'hodlxxi-binding-authorization-v1-sha256:' || digest",
            name="ck_social_device_authorization_replay_proof_id",
        ),
        CheckConstraint(
            "octet_length(result_payload) BETWEEN 1 AND 8192",
            name="ck_social_device_authorization_replay_payload",
        ),
    )


def _signed_int32(value: bytes) -> int:
    unsigned = int.from_bytes(value, "big", signed=False)
    return unsigned - (1 << 32) if value[0] & 0x80 else unsigned


def _lock_keys(domain: bytes, value: str) -> tuple[int, int]:
    digest = hashlib.sha256(domain + value.encode("ascii")).digest()
    return _signed_int32(digest[:4]), _signed_int32(digest[4:8])


def _advisory_lock(session, domain: bytes, value: str) -> None:
    first, second = _lock_keys(domain, value)
    session.execute(select(func.pg_advisory_xact_lock(first, second)))


def _utc_second(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        raise ValueError
    return normalized


def _db_utc_second(value: object) -> datetime:
    if type(value) is not datetime:
        raise ValueError
    normalized = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    if normalized.microsecond:
        raise ValueError
    return normalized


def _authorized_from(
    authorization: IdentitySignedDeviceBindingAuthorization,
) -> AuthorizedDeviceBinding:
    claim = authorization.claim
    binding = MessagingDeviceBinding(
        subject=claim.subject,
        device_id=claim.device_id,
        binding_id=authorization.binding_id,
        public_key=claim.public_key,
        binding_version=claim.binding_version,
        valid_from=claim.binding_valid_from,
        expires_at=claim.binding_expires_at,
        operation=claim.operation,
        prior_binding_id=claim.prior_binding_id,
        request_id=claim.request_id,
        active=claim.operation != "revoke",
    )
    verification = VerifiedBindingAuthorization(
        proof_id=PROOF_ID_PREFIX + authorization.digest,
        subject=claim.subject,
        device_id=claim.device_id,
        binding_id=authorization.binding_id,
        binding_version=claim.binding_version,
        public_key=claim.public_key,
        valid_from=claim.binding_valid_from,
        expires_at=claim.binding_expires_at,
        evidence_valid_from=claim.issued_at,
        evidence_expires_at=claim.binding_expires_at,
    )
    return AuthorizedDeviceBinding(authorization, binding, verification)


def _adopted_from(
    adoption: IdentitySignedDeviceBindingAdoption,
) -> AdoptedDeviceBindingAuthorization:
    binding = adoption.claim.binding
    verification = VerifiedBindingAuthorization(
        proof_id=PROOF_ID_PREFIX + adoption.digest,
        subject=binding.subject,
        device_id=binding.device_id,
        binding_id=binding.binding_id,
        binding_version=binding.binding_version,
        public_key=binding.public_key,
        valid_from=binding.valid_from,
        expires_at=binding.expires_at,
        evidence_valid_from=adoption.claim.issued_at,
        evidence_expires_at=binding.expires_at,
    )
    return AdoptedDeviceBindingAuthorization(adoption, binding, verification)


def _same_binding_identity(first: MessagingDeviceBinding, second: MessagingDeviceBinding) -> bool:
    return (
        first.subject == second.subject
        and first.device_id == second.device_id
        and first.binding_id == second.binding_id
        and first.public_key == second.public_key
        and first.binding_version == second.binding_version
        and first.valid_from == second.valid_from
        and first.expires_at == second.expires_at
        and first.operation == second.operation
        and first.prior_binding_id == second.prior_binding_id
        and first.request_id == second.request_id
    )


class _TransactionPorts:
    def __init__(
        self,
        session,
        *,
        signature_verifier: IdentitySignatureVerifier,
    ) -> None:
        self._session = session
        self._signature_verifier = signature_verifier
        self._binding_storage = SqlAlchemyTransactionBoundSocialMessagingDeviceStorage(session)
        self._pending_replay: AuthorizationReplayRecord | AdoptionReplayRecord | None = None

    def _evidence_from_row(
        self,
        row: SocialMessagingDeviceBindingAuthorizationEvidenceRow,
    ) -> BindingAuthorizationEvidence:
        payload = row.canonical_payload
        if type(payload) is not str or not 1 <= len(payload.encode("ascii")) <= MAX_PERSISTED_PAYLOAD_BYTES:
            raise ValueError
        if row.evidence_type == "lifecycle":
            authorization = parse_and_verify_device_binding_authorization(
                payload,
                authenticated_subject=row.subject_pubkey,
                signature_verifier=self._signature_verifier,
            )
            evidence: BindingAuthorizationEvidence = _authorized_from(authorization)
            request_id = authorization.claim.request_id
            digest = authorization.digest
            action = authorization.claim.operation
        elif row.evidence_type == "adoption":
            adoption = parse_and_verify_device_binding_adoption(
                payload,
                authenticated_subject=row.subject_pubkey,
                signature_verifier=self._signature_verifier,
            )
            evidence = _adopted_from(adoption)
            request_id = adoption.claim.request_id
            digest = adoption.digest
            action = "adopt"
        else:
            raise ValueError
        binding = evidence.binding
        verification = evidence.verification
        if type(evidence) is AuthorizedDeviceBinding:
            expected_payload = canonical_authorization_json(evidence.authorization)
        elif type(evidence) is AdoptedDeviceBindingAuthorization:
            expected_payload = canonical_adoption_json(evidence.adoption)
        else:
            raise ValueError
        if (
            row.binding_id != binding.binding_id
            or row.request_id != request_id
            or row.digest != digest
            or row.action != action
            or row.subject_pubkey != binding.subject
            or row.device_id != binding.device_id
            or row.public_key != binding.public_key
            or row.binding_version != binding.binding_version
            or row.binding_operation != binding.operation
            or _db_utc_second(row.binding_valid_from) != binding.valid_from
            or _db_utc_second(row.binding_expires_at) != binding.expires_at
            or _db_utc_second(row.evidence_valid_from) != verification.evidence_valid_from
            or _db_utc_second(row.evidence_expires_at) != verification.evidence_expires_at
            or expected_payload != payload
        ):
            raise ValueError
        _db_utc_second(row.created_at)
        return evidence

    def _evidence_rows(self, statement, maximum: int):
        if type(maximum) is not int or maximum < 0:
            raise ValueError
        rows = self._session.execute(statement.limit(maximum + 1).with_for_update()).scalars().all()
        return rows[:maximum], len(rows) > maximum

    def authorization_for_binding(
        self,
        binding_id: str,
        *,
        now: datetime,
        maximum: int,
    ) -> BindingAuthorizationEvidenceState:
        _utc_second(now)
        rows, truncated = self._evidence_rows(
            select(SocialMessagingDeviceBindingAuthorizationEvidenceRow)
            .where(SocialMessagingDeviceBindingAuthorizationEvidenceRow.binding_id == binding_id)
            .order_by(SocialMessagingDeviceBindingAuthorizationEvidenceRow.binding_id),
            maximum,
        )
        return BindingAuthorizationEvidenceState(
            STATE_SCHEMA,
            VERSION,
            binding_id,
            True,
            truncated,
            tuple(self._evidence_from_row(row) for row in rows),
        )

    def _current_evidence(
        self,
        *,
        now: datetime,
        maximum: int,
        subject: str | None = None,
        device_id: str | None = None,
        public_key: str | None = None,
    ) -> tuple[tuple[BindingAuthorizationEvidence, ...], bool]:
        statement = (
            select(
                SocialMessagingDeviceBindingAuthorizationEvidenceRow,
                SocialMessagingDeviceBindingRow,
            )
            .join(
                SocialMessagingDeviceBindingRow,
                SocialMessagingDeviceBindingRow.binding_id
                == SocialMessagingDeviceBindingAuthorizationEvidenceRow.binding_id,
            )
            .where(
                SocialMessagingDeviceBindingRow.active.is_(True),
                SocialMessagingDeviceBindingRow.valid_from <= now,
                SocialMessagingDeviceBindingRow.expires_at > now,
                SocialMessagingDeviceBindingAuthorizationEvidenceRow.evidence_valid_from <= now,
                SocialMessagingDeviceBindingAuthorizationEvidenceRow.evidence_expires_at > now,
            )
            .order_by(
                SocialMessagingDeviceBindingRow.subject_pubkey,
                SocialMessagingDeviceBindingRow.device_id,
                SocialMessagingDeviceBindingRow.binding_id,
            )
            .limit(maximum + 1)
            .with_for_update(of=SocialMessagingDeviceBindingRow)
        )
        if subject is not None:
            statement = statement.where(SocialMessagingDeviceBindingRow.subject_pubkey == subject)
        if device_id is not None:
            statement = statement.where(SocialMessagingDeviceBindingRow.device_id == device_id)
        if public_key is not None:
            statement = statement.where(SocialMessagingDeviceBindingRow.public_key == public_key)
        rows = self._session.execute(statement).all()
        truncated = len(rows) > maximum
        result = []
        for evidence_row, binding_row in rows[:maximum]:
            evidence = self._evidence_from_row(evidence_row)
            stored = _from_row(binding_row)
            if not _same_binding_identity(evidence.binding, stored):
                raise ValueError
            result.append(evidence)
        return tuple(result), truncated

    def current_for_subject(
        self,
        subject: str,
        *,
        now: datetime,
        maximum: int,
    ) -> CurrentSubjectBindingState:
        records, truncated = self._current_evidence(
            now=_utc_second(now),
            maximum=maximum,
            subject=subject,
        )
        return CurrentSubjectBindingState(
            STATE_SCHEMA,
            VERSION,
            subject,
            True,
            truncated,
            records,
        )

    def current_for_device(
        self,
        subject: str,
        device_id: str,
        *,
        now: datetime,
        maximum: int,
    ) -> CurrentDeviceBindingState:
        records, truncated = self._current_evidence(
            now=_utc_second(now),
            maximum=maximum,
            subject=subject,
            device_id=device_id,
        )
        return CurrentDeviceBindingState(
            STATE_SCHEMA,
            VERSION,
            subject,
            device_id,
            True,
            truncated,
            records,
        )

    def current_for_public_key(
        self,
        public_key: str,
        *,
        now: datetime,
        maximum: int,
    ) -> CurrentPublicKeyBindingState:
        records, truncated = self._current_evidence(
            now=_utc_second(now),
            maximum=maximum,
            public_key=public_key,
        )
        return CurrentPublicKeyBindingState(
            STATE_SCHEMA,
            VERSION,
            public_key,
            True,
            truncated,
            records,
        )

    def current_legacy_binding(
        self,
        subject: str,
        binding_id: str,
        *,
        now: datetime,
        maximum: int,
    ) -> CurrentLegacyDeviceBindingState:
        if maximum != MAX_STATE_RECORDS:
            raise ValueError
        binding = self._binding_storage.binding_for_id(binding_id)
        records: tuple[MessagingDeviceBinding, ...] = ()
        if (
            binding is not None
            and binding.subject == subject
            and binding.active is True
            and binding.operation in {"register", "rotate"}
            and binding.valid_from <= now < binding.expires_at
        ):
            records = (binding,)
        return CurrentLegacyDeviceBindingState(
            STATE_SCHEMA,
            VERSION,
            subject,
            binding_id,
            True,
            False,
            records,
        )

    def get(self, request_id: str) -> AuthorizationReplayRecord | AdoptionReplayRecord | None:
        rows = (
            self._session.execute(
                select(SocialMessagingDeviceBindingAuthorizationReplayRow)
                .where(SocialMessagingDeviceBindingAuthorizationReplayRow.request_id == request_id)
                .limit(2)
                .with_for_update()
            )
            .scalars()
            .all()
        )
        if len(rows) > 1:
            raise ValueError
        if not rows:
            return None
        row = rows[0]
        evidence_row = self._session.get(
            SocialMessagingDeviceBindingAuthorizationEvidenceRow,
            row.result_binding_id,
            with_for_update=True,
        )
        if evidence_row is None:
            raise ValueError
        evidence = self._evidence_from_row(evidence_row)
        expected_result = canonical_authorization_result_bytes(evidence).decode("ascii")
        if (
            row.request_id != evidence_row.request_id
            or row.record_type != evidence_row.evidence_type
            or row.action != evidence_row.action
            or row.digest != evidence_row.digest
            or row.result_binding_id != evidence.binding.binding_id
            or row.result_proof_id != evidence.verification.proof_id
            or row.result_payload != expected_result
        ):
            raise ValueError
        _db_utc_second(row.created_at)
        if type(evidence) is AuthorizedDeviceBinding:
            return AuthorizationReplayRecord(
                row.request_id,
                row.digest,
                evidence,
                expected_result.encode("ascii"),
            )
        if type(evidence) is AdoptedDeviceBindingAuthorization:
            return AdoptionReplayRecord(
                row.request_id,
                row.digest,
                evidence,
                expected_result.encode("ascii"),
            )
        raise ValueError

    def record(
        self,
        record: AuthorizationReplayRecord | AdoptionReplayRecord,
    ) -> AuthorizationReplayRecord | AdoptionReplayRecord:
        if self._pending_replay is not None:
            raise ValueError
        if type(record) is AuthorizationReplayRecord:
            authorized_evidence = record.authorized_binding
            if (
                type(authorized_evidence) is not AuthorizedDeviceBinding
                or record.request_id != authorized_evidence.authorization.claim.request_id
                or record.authorization_digest != authorized_evidence.authorization.digest
                or record.canonical_result != canonical_authorization_result_bytes(authorized_evidence)
            ):
                raise ValueError
        elif type(record) is AdoptionReplayRecord:
            adopted_evidence = record.adopted_binding
            if (
                type(adopted_evidence) is not AdoptedDeviceBindingAuthorization
                or record.request_id != adopted_evidence.adoption.claim.request_id
                or record.adoption_digest != adopted_evidence.adoption.digest
                or record.canonical_result != canonical_authorization_result_bytes(adopted_evidence)
            ):
                raise ValueError
        else:
            raise ValueError
        self._pending_replay = record
        return record

    def persist(
        self,
        evidence: BindingAuthorizationEvidence,
        *,
        now: datetime,
    ) -> AuthorizationReplayRecord | AdoptionReplayRecord:
        if self._pending_replay is None:
            raise ValueError
        created_at = _utc_second(now)
        expected_replay: AuthorizationReplayRecord | AdoptionReplayRecord
        if type(evidence) is AuthorizedDeviceBinding:
            evidence_type = "lifecycle"
            action = evidence.authorization.claim.operation
            request_id = evidence.authorization.claim.request_id
            digest = evidence.authorization.digest
            payload = canonical_authorization_json(evidence.authorization)
            expected_replay = AuthorizationReplayRecord(
                request_id,
                digest,
                evidence,
                canonical_authorization_result_bytes(evidence),
            )
        elif type(evidence) is AdoptedDeviceBindingAuthorization:
            evidence_type = "adoption"
            action = "adopt"
            request_id = evidence.adoption.claim.request_id
            digest = evidence.adoption.digest
            payload = canonical_adoption_json(evidence.adoption)
            expected_replay = AdoptionReplayRecord(
                request_id,
                digest,
                evidence,
                canonical_authorization_result_bytes(evidence),
            )
        else:
            raise ValueError
        if self._pending_replay != expected_replay:
            raise ValueError
        binding = evidence.binding
        verification = evidence.verification
        evidence_row = SocialMessagingDeviceBindingAuthorizationEvidenceRow(
            binding_id=binding.binding_id,
            evidence_type=evidence_type,
            action=action,
            request_id=request_id,
            digest=digest,
            canonical_payload=payload,
            subject_pubkey=binding.subject,
            device_id=binding.device_id,
            public_key=binding.public_key,
            binding_version=binding.binding_version,
            binding_operation=binding.operation,
            binding_valid_from=binding.valid_from,
            binding_expires_at=binding.expires_at,
            evidence_valid_from=verification.evidence_valid_from,
            evidence_expires_at=verification.evidence_expires_at,
            created_at=created_at,
        )
        replay_row = SocialMessagingDeviceBindingAuthorizationReplayRow(
            request_id=request_id,
            record_type=evidence_type,
            action=action,
            digest=digest,
            result_binding_id=binding.binding_id,
            result_proof_id=verification.proof_id,
            result_payload=expected_replay.canonical_result.decode("ascii"),
            created_at=created_at,
        )
        self._session.add(evidence_row)
        self._session.add(replay_row)
        self._session.flush()
        return expected_replay


class SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage:
    """One authorization operation inside a caller-owned active transaction."""

    def __init__(
        self,
        session,
        *,
        signature_verifier: IdentitySignatureVerifier | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        bind = session.get_bind() if callable(getattr(session, "get_bind", None)) else None
        if (
            not callable(getattr(session, "execute", None))
            or not callable(getattr(session, "flush", None))
            or not callable(getattr(session, "in_transaction", None))
            or getattr(getattr(bind, "dialect", None), "name", None) != "postgresql"
            or session.in_transaction() is not True
            or clock is not None
            and not callable(clock)
        ):
            raise ValueError("invalid authorization storage transaction")
        isolation = session.execute(text("SHOW transaction_isolation")).scalar_one()
        if isolation != "read committed":
            raise ValueError("authorization storage requires READ COMMITTED")
        self._session = session
        self._signature_verifier = signature_verifier or Bip340IdentitySignatureVerifier()
        if not callable(getattr(self._signature_verifier, "verify", None)):
            raise ValueError("invalid authorization signature verifier")
        self._clock = clock or (lambda: datetime.now(timezone.utc).replace(microsecond=0))
        self._accepted_replay: AuthorizationReplayRecord | AdoptionReplayRecord | None = None

    def _now(self) -> datetime:
        value = self._clock()
        if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError
        return value.astimezone(timezone.utc).replace(microsecond=0)

    def accepted_result_bytes(self, evidence: BindingAuthorizationEvidence) -> bytes:
        """Return only the exact canonical result retained by this operation."""

        try:
            replay = self._accepted_replay
            if type(evidence) is AuthorizedDeviceBinding:
                return _validated_replay(
                    replay,
                    candidate=evidence,
                    signature_verifier=self._signature_verifier,
                ).canonical_result
            if type(evidence) is AdoptedDeviceBindingAuthorization:
                return _validated_adoption_replay(
                    replay,
                    candidate=evidence,
                    signature_verifier=self._signature_verifier,
                ).canonical_result
            raise ValueError
        except Exception:
            raise DeviceBindingAuthorizationUnavailable() from None

    def _lock_request(self, request_id: str) -> None:
        _advisory_lock(self._session, _REQUEST_LOCK_DOMAIN, request_id)

    def _lock_mutation(
        self,
        *,
        subject: str,
        device_id: str,
        public_keys: tuple[str, ...],
    ) -> None:
        _lock_subject_for_evidence_change(self._session, subject)
        _lock_subject_user(self._session, subject)
        _advisory_lock(self._session, _DEVICE_LOCK_DOMAIN, subject + ":" + device_id)
        _advisory_lock(self._session, _PUBLIC_KEY_GUARD_DOMAIN, "global")
        for public_key in sorted(set(public_keys)):
            _advisory_lock(self._session, _PUBLIC_KEY_LOCK_DOMAIN, public_key)

    def authorize_lifecycle(
        self,
        payload: object,
        *,
        authenticated_subject: object,
        admission_validator: Callable[[datetime], None] | None = None,
    ) -> AuthorizedDeviceBinding:
        try:
            authorization = parse_and_verify_device_binding_authorization(
                payload,
                authenticated_subject=authenticated_subject,
                signature_verifier=self._signature_verifier,
            )
            claim = authorization.claim
            self._lock_request(claim.request_id)
            ports = _TransactionPorts(
                self._session,
                signature_verifier=self._signature_verifier,
            )
            replay = ports.get(claim.request_id)
            if replay is not None:
                now = self._now()
                if claim.issued_at > now or claim.binding_valid_from > now:
                    raise ValueError
                candidate = _authorized_from(authorization)
                accepted = _validated_replay(
                    replay,
                    candidate=candidate,
                    signature_verifier=self._signature_verifier,
                )
                self._accepted_replay = accepted
                return accepted.authorized_binding
            self._lock_mutation(
                subject=claim.subject,
                device_id=claim.device_id,
                public_keys=(claim.public_key,),
            )
            now = self._now()
            if claim.issued_at > now or claim.binding_valid_from > now:
                raise ValueError
            if now >= claim.expires_at:
                raise _ExpiredUnacceptedAuthorization
            if now >= claim.binding_expires_at:
                raise ValueError
            if admission_validator is not None:
                if not callable(admission_validator):
                    raise ValueError
                admission_validator(now)
            current_full = SqlAlchemyTransactionBoundCurrentFullVerifier(self._session)
            current_full.verify_in_transaction(claim.subject, now=now)
            coordinator = SocialMessagingDeviceBindingAuthorizationV1(
                state_provider=ports,
                replay_ledger=ports,
                signature_verifier=self._signature_verifier,
                clock=lambda: now,
            )
            result = coordinator.authorize(
                payload,
                authenticated_subject=authenticated_subject,
            )
            ports._binding_storage.apply_authorized(result.binding, now=now)
            self._accepted_replay = ports.persist(result, now=now)
            return result
        except DeviceBindingAuthorizationUnavailable:
            raise
        except _ExpiredUnacceptedAuthorization:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise DeviceBindingAuthorizationUnavailable() from None
        except Exception:
            raise DeviceBindingAuthorizationUnavailable() from None

    def adopt_legacy(
        self,
        payload: object,
        *,
        authenticated_subject: object,
        admission_validator: Callable[[datetime], None] | None = None,
    ) -> AdoptedDeviceBindingAuthorization:
        try:
            adoption = parse_and_verify_device_binding_adoption(
                payload,
                authenticated_subject=authenticated_subject,
                signature_verifier=self._signature_verifier,
            )
            claim = adoption.claim
            binding = claim.binding
            self._lock_request(claim.request_id)
            ports = _TransactionPorts(
                self._session,
                signature_verifier=self._signature_verifier,
            )
            replay = ports.get(claim.request_id)
            if replay is not None:
                now = self._now()
                if claim.issued_at > now or binding.valid_from > now:
                    raise ValueError
                candidate = _adopted_from(adoption)
                accepted = _validated_adoption_replay(
                    replay,
                    candidate=candidate,
                    signature_verifier=self._signature_verifier,
                )
                self._accepted_replay = accepted
                return accepted.adopted_binding
            self._lock_mutation(
                subject=binding.subject,
                device_id=binding.device_id,
                public_keys=(binding.public_key,),
            )
            now = self._now()
            if claim.issued_at > now or binding.valid_from > now:
                raise ValueError
            if now >= claim.expires_at:
                raise _ExpiredUnacceptedAuthorization
            if now >= binding.expires_at:
                raise ValueError
            if admission_validator is not None:
                if not callable(admission_validator):
                    raise ValueError
                admission_validator(now)
            current_full = SqlAlchemyTransactionBoundCurrentFullVerifier(self._session)
            coordinator = SocialMessagingLegacyBindingAdoptionV1(
                state_provider=ports,
                current_full_prerequisite=current_full,
                replay_ledger=ports,
                signature_verifier=self._signature_verifier,
                clock=lambda: now,
            )
            result = coordinator.adopt(
                payload,
                authenticated_subject=authenticated_subject,
            )
            self._accepted_replay = ports.persist(result, now=now)
            return result
        except DeviceBindingAuthorizationUnavailable:
            raise
        except _ExpiredUnacceptedAuthorization:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise DeviceBindingAuthorizationUnavailable() from None
        except Exception:
            raise DeviceBindingAuthorizationUnavailable() from None

    def create_intent(
        self,
        payload: object,
        *,
        authenticated_subject: object,
        binding_lifetime_seconds: int,
    ) -> TrustedAuthorizationIntent:
        """Derive an intent from authoritative reads without staging writes."""

        try:
            proposal = parse_authorization_intent_proposal(payload)
            now = self._now()
            ports = _TransactionPorts(
                self._session,
                signature_verifier=self._signature_verifier,
            )
            current_full = SqlAlchemyTransactionBoundCurrentFullVerifier(self._session)
            return derive_trusted_authorization_intent(
                proposal,
                authenticated_subject=authenticated_subject,
                state_provider=ports,
                binding_state=ports._binding_storage,
                current_full=current_full,
                now=now,
                binding_lifetime_seconds=binding_lifetime_seconds,
                signature_verifier=self._signature_verifier,
            )
        except DeviceBindingAuthorizationUnavailable:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise DeviceBindingAuthorizationUnavailable() from None
        except Exception:
            raise DeviceBindingAuthorizationUnavailable() from None


__all__ = [
    "EVIDENCE_TABLE",
    "MAX_PERSISTED_PAYLOAD_BYTES",
    "REPLAY_TABLE",
    "SocialMessagingDeviceBindingAuthorizationEvidenceRow",
    "SocialMessagingDeviceBindingAuthorizationReplayRow",
    "SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage",
]
