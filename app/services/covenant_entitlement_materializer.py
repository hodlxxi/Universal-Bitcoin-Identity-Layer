"""Dormant materializer from trusted covenant observations to evidence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable
import uuid

from app.services.action_authorization import IdentityClass
from app.services.covenant_relation import (
    CovenantRelationDecision,
    CovenantRelationEvaluation,
    evaluate_covenant_relation,
)
from app.services.current_entitlement_evidence import CONTRACT_VERSION, CurrentEntitlementEvidenceRecord
from app.services.trusted_covenant_observation import InvalidTrustedCovenantOutpoint, TrustedCovenantOutpoint

MATERIALIZER_VERSION = "hodlxxi.covenant_entitlement_materializer.v1"
EVIDENCE_SOURCE = "trusted_bitcoin_covenant_observation"
EVIDENCE_VERSION = "hodlxxi.trusted_covenant_observation_adapter.v1"
EVIDENCE_VALIDITY_SECONDS = 300
MAX_OBSERVATION_AGE_SECONDS = 60
MAX_FUTURE_SKEW_SECONDS = 5


class CovenantEntitlementMaterializationUnavailable(RuntimeError):
    """Entitlement evidence could not be materialized safely."""

    def __init__(self):
        super().__init__("covenant entitlement materialization unavailable")


class CovenantEntitlementMaterializer:
    """Append one fresh FULL or LIMITED record through injected dependencies."""

    def __init__(
        self,
        observation_adapter: object,
        repository: object,
        clock: Callable[[], datetime] | None = None,
        uuid_factory: Callable[[], uuid.UUID] | None = None,
    ):
        if not callable(getattr(observation_adapter, "observe", None)):
            raise ValueError("observation_adapter must expose callable observe")
        if not callable(getattr(repository, "append", None)):
            raise ValueError("repository must expose callable append")
        if clock is not None and not callable(clock):
            raise ValueError("clock must be callable")
        if uuid_factory is not None and not callable(uuid_factory):
            raise ValueError("uuid_factory must be callable")
        self._observation_adapter = observation_adapter
        self._repository = repository
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._uuid_factory = uuid_factory or uuid.uuid4

    def materialize(self, outpoints: tuple[TrustedCovenantOutpoint, ...]) -> CurrentEntitlementEvidenceRecord:
        try:
            evaluation = self._observation_adapter.observe(outpoints)
        except InvalidTrustedCovenantOutpoint:
            raise
        except Exception:
            raise CovenantEntitlementMaterializationUnavailable() from None

        try:
            if type(evaluation) is not CovenantRelationEvaluation:
                raise CovenantEntitlementMaterializationUnavailable()
            decision = evaluate_covenant_relation(evaluation)
            if type(decision) is not CovenantRelationDecision:
                raise CovenantEntitlementMaterializationUnavailable()
            raw_materializer_time = self._clock()
            if (
                type(raw_materializer_time) is not datetime
                or raw_materializer_time.tzinfo is None
                or raw_materializer_time.utcoffset() is None
            ):
                raise CovenantEntitlementMaterializationUnavailable()
            raw_materializer_time = raw_materializer_time.astimezone(timezone.utc)
            if decision.observed_at - raw_materializer_time > timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
                raise CovenantEntitlementMaterializationUnavailable()
            if raw_materializer_time - decision.observed_at > timedelta(seconds=MAX_OBSERVATION_AGE_SECONDS):
                raise CovenantEntitlementMaterializationUnavailable()
            created_at = max(raw_materializer_time, decision.observed_at)

            generated_uuid = self._uuid_factory()
            if type(generated_uuid) is not uuid.UUID:
                raise CovenantEntitlementMaterializationUnavailable()
            evidence_id = str(generated_uuid)
            if str(uuid.UUID(evidence_id)) != evidence_id:
                raise CovenantEntitlementMaterializationUnavailable()
            is_full = decision.current_full_relation_satisfied
            record = CurrentEntitlementEvidenceRecord(
                evidence_id=evidence_id,
                contract_version=CONTRACT_VERSION,
                subject_pubkey=decision.subject_pubkey,
                identity_class=IdentityClass.FULL if is_full else IdentityClass.LIMITED,
                current_full_relation_satisfied=is_full,
                evidence_source=EVIDENCE_SOURCE,
                evidence_version=EVIDENCE_VERSION,
                source_evidence_sha256=decision.source_evidence_sha256,
                observed_at=decision.observed_at,
                valid_until=decision.observed_at + timedelta(seconds=EVIDENCE_VALIDITY_SECONDS),
                revoked_at=None,
                created_at=created_at,
            )
            self._repository.append(record)
            return record
        except CovenantEntitlementMaterializationUnavailable:
            raise
        except Exception:
            raise CovenantEntitlementMaterializationUnavailable() from None
