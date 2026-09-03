"""Atomic evidence materialization for both endpoints of one root-bound reciprocal relation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable
import uuid

from app.services.canonical_root_entitlement_materializer import (
    EVIDENCE_VALIDITY_SECONDS,
    MAX_FUTURE_SKEW_SECONDS,
    MAX_OBSERVATION_AGE_SECONDS,
)
from app.services.canonical_root_entitlement_policy import (
    CanonicalRootEntitlementDecision,
    evaluate_canonical_root_entitlement,
)
from app.services.canonical_root_reciprocal_entitlement_policy import (
    CanonicalRootReciprocalEntitlementDecision,
    evaluate_canonical_root_reciprocal_entitlement,
)
from app.services.current_entitlement_evidence import (
    CONTRACT_VERSION,
    CurrentEntitlementEvidenceRecord,
)
from app.services.edge_local_covenant_observation import (
    EdgeLocalCovenantRelationResult,
)

_canonical_root_evaluate = evaluate_canonical_root_entitlement
_canonical_reciprocal_evaluate = evaluate_canonical_root_reciprocal_entitlement


class CanonicalRootReciprocalEntitlementMaterializationUnavailable(RuntimeError):
    def __init__(self) -> None:
        super().__init__("canonical root reciprocal entitlement materialization unavailable")


@dataclass(frozen=True, slots=True)
class CanonicalRootReciprocalEntitlementMaterialization:
    root_evidence: CurrentEntitlementEvidenceRecord
    reciprocal_evidence: CurrentEntitlementEvidenceRecord

    def __post_init__(self) -> None:
        root = CurrentEntitlementEvidenceRecord(**vars(self.root_evidence))
        reciprocal = CurrentEntitlementEvidenceRecord(**vars(self.reciprocal_evidence))

        if (
            root.subject_pubkey == reciprocal.subject_pubkey
            or root.evidence_id == reciprocal.evidence_id
            or root.observed_at != reciprocal.observed_at
            or root.valid_until != reciprocal.valid_until
            or root.created_at != reciprocal.created_at
        ):
            raise ValueError("invalid reciprocal evidence pair")


class CanonicalRootReciprocalEntitlementMaterializer:
    """Revalidate and atomically persist both subject-relative endpoints."""

    def __init__(
        self,
        repository: object,
        *,
        clock: Callable[[], datetime] | None = None,
        uuid_factory: Callable[[], uuid.UUID] | None = None,
    ) -> None:
        try:
            if not callable(getattr(repository, "append_pair", None)):
                raise ValueError()

            if clock is not None and not callable(clock):
                raise ValueError()

            if uuid_factory is not None and not callable(uuid_factory):
                raise ValueError()

            self._repository = repository
            self._clock = (lambda: datetime.now(timezone.utc)) if clock is None else clock
            self._uuid_factory = uuid_factory or uuid.uuid4

        except (KeyboardInterrupt, SystemExit):
            raise

        except Exception:
            raise (CanonicalRootReciprocalEntitlementMaterializationUnavailable()) from None

    def materialize(
        self,
        graph_or_protocol_id: str,
        root_subject_xonly_pubkey: str,
        relation: EdgeLocalCovenantRelationResult,
    ) -> CanonicalRootReciprocalEntitlementMaterialization:
        try:
            if type(relation) is not EdgeLocalCovenantRelationResult:
                raise ValueError()

            root_decision = evaluate_canonical_root_entitlement(
                graph_or_protocol_id,
                root_subject_xonly_pubkey,
                relation,
            )

            canonical_root = _canonical_root_evaluate(
                graph_or_protocol_id,
                root_subject_xonly_pubkey,
                relation,
            )

            if type(root_decision) is not CanonicalRootEntitlementDecision or root_decision != canonical_root:
                raise ValueError()

            reciprocal_decision = evaluate_canonical_root_reciprocal_entitlement(
                graph_or_protocol_id,
                root_subject_xonly_pubkey,
                relation,
            )

            canonical_reciprocal = _canonical_reciprocal_evaluate(
                graph_or_protocol_id,
                root_subject_xonly_pubkey,
                relation,
            )

            if (
                type(reciprocal_decision) is not CanonicalRootReciprocalEntitlementDecision
                or reciprocal_decision != canonical_reciprocal
                or reciprocal_decision.root_subject_xonly_pubkey != root_decision.subject_xonly_pubkey
                or reciprocal_decision.subject_xonly_pubkey != root_decision.counterparty_xonly_pubkey
                or reciprocal_decision.counterparty_xonly_pubkey != root_decision.subject_xonly_pubkey
                or reciprocal_decision.root_source_evidence_sha256 != root_decision.source_evidence_sha256
                or reciprocal_decision.observed_at != root_decision.observed_at
                or reciprocal_decision.observed_block_height != root_decision.observed_block_height
            ):
                raise ValueError()

            observed_at = root_decision.observed_at.astimezone(timezone.utc)

            raw_now = self._clock()

            if type(raw_now) is not datetime or raw_now.tzinfo is None or raw_now.utcoffset() is None:
                raise ValueError()

            materializer_time = raw_now.astimezone(timezone.utc)

            if materializer_time - observed_at > timedelta(seconds=MAX_OBSERVATION_AGE_SECONDS):
                raise ValueError()

            if observed_at - materializer_time > timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
                raise ValueError()

            first_uuid = self._uuid_factory()
            second_uuid = self._uuid_factory()

            if type(first_uuid) is not uuid.UUID or type(second_uuid) is not uuid.UUID or first_uuid == second_uuid:
                raise ValueError()

            created_at = max(materializer_time, observed_at)
            valid_until = observed_at + timedelta(seconds=EVIDENCE_VALIDITY_SECONDS)

            root_evidence = CurrentEntitlementEvidenceRecord(
                evidence_id=str(first_uuid),
                contract_version=CONTRACT_VERSION,
                subject_pubkey=root_decision.subject_xonly_pubkey,
                identity_class=root_decision.identity_class,
                current_full_relation_satisfied=(root_decision.current_full_relation_satisfied),
                evidence_source=root_decision.evidence_source,
                evidence_version=root_decision.policy_version,
                source_evidence_sha256=(root_decision.source_evidence_sha256),
                observed_at=observed_at,
                valid_until=valid_until,
                revoked_at=None,
                created_at=created_at,
            )

            reciprocal_evidence = CurrentEntitlementEvidenceRecord(
                evidence_id=str(second_uuid),
                contract_version=CONTRACT_VERSION,
                subject_pubkey=(reciprocal_decision.subject_xonly_pubkey),
                identity_class=reciprocal_decision.identity_class,
                current_full_relation_satisfied=(reciprocal_decision.current_full_relation_satisfied),
                evidence_source=reciprocal_decision.evidence_source,
                evidence_version=reciprocal_decision.policy_version,
                source_evidence_sha256=(reciprocal_decision.source_evidence_sha256),
                observed_at=observed_at,
                valid_until=valid_until,
                revoked_at=None,
                created_at=created_at,
            )

            pair = (
                root_evidence,
                reciprocal_evidence,
            )

            self._repository.append_pair(pair)

            return CanonicalRootReciprocalEntitlementMaterialization(
                root_evidence,
                reciprocal_evidence,
            )

        except (KeyboardInterrupt, SystemExit):
            raise

        except Exception:
            raise (CanonicalRootReciprocalEntitlementMaterializationUnavailable()) from None
