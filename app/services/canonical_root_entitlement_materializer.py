"""Append fresh canonical-root entitlement decisions as immutable evidence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable
import uuid

from app.services.action_authorization import IdentityClass
from app.services.canonical_root_entitlement_policy import (
    EVIDENCE_SOURCE,
    POLICY_VERSION,
    CanonicalRootEntitlementDecision,
    evaluate_canonical_root_entitlement,
)
from app.services.canonical_controlling_registration import (
    ControllingRegistrationSelectionSource,
)
from app.services.current_entitlement_evidence import (
    CONTRACT_VERSION,
    CurrentEntitlementEvidenceRecord,
)
from app.services.edge_local_covenant_observation import EdgeLocalCovenantRelationResult

EVIDENCE_VALIDITY_SECONDS = 300
MAX_OBSERVATION_AGE_SECONDS = 60
MAX_FUTURE_SKEW_SECONDS = 5

_canonical_evaluate_canonical_root_entitlement = evaluate_canonical_root_entitlement


class CanonicalRootEntitlementMaterializationUnavailable(RuntimeError):
    """Canonical-root entitlement evidence could not be appended safely."""

    def __init__(self) -> None:
        super().__init__("canonical root entitlement materialization unavailable")


class CanonicalRootEntitlementMaterializer:
    """Revalidate one edge-local result and append its canonical decision."""

    def __init__(
        self,
        repository: object,
        *,
        clock: Callable[[], datetime] | None = None,
        uuid_factory: Callable[[], uuid.UUID] | None = None,
    ) -> None:
        try:
            if not callable(getattr(repository, "append", None)):
                raise ValueError()
            if clock is not None and not callable(clock):
                raise ValueError()
            if uuid_factory is not None and not callable(uuid_factory):
                raise ValueError()
            self._repository = repository
            self._clock = clock or (lambda: datetime.now(timezone.utc))
            self._uuid_factory = uuid_factory or uuid.uuid4
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise CanonicalRootEntitlementMaterializationUnavailable() from None

    def materialize(
        self,
        graph_or_protocol_id: str,
        subject_xonly_pubkey: str,
        edge_local_result: EdgeLocalCovenantRelationResult,
    ) -> CurrentEntitlementEvidenceRecord:
        try:
            decision = evaluate_canonical_root_entitlement(
                graph_or_protocol_id,
                subject_xonly_pubkey,
                edge_local_result,
            )
            if type(decision) is not CanonicalRootEntitlementDecision:
                raise ValueError()
            canonical_decision = _canonical_evaluate_canonical_root_entitlement(
                graph_or_protocol_id,
                subject_xonly_pubkey,
                edge_local_result,
            )
            if type(canonical_decision) is not CanonicalRootEntitlementDecision:
                raise ValueError()
            if decision != canonical_decision:
                raise ValueError()
            if (
                decision.graph_or_protocol_id != graph_or_protocol_id
                or decision.subject_xonly_pubkey != subject_xonly_pubkey
                or type(edge_local_result) is not EdgeLocalCovenantRelationResult
                or decision.counterparty_xonly_pubkey
                != edge_local_result.counterparty_xonly_pubkey
                or decision.controlling_selection_source
                is not ControllingRegistrationSelectionSource.CANONICAL_ROOT_REGISTRATION_BINDING
                or decision.controlling_selection_source
                is not edge_local_result.controlling_selection_source
                or decision.selector_record_id != edge_local_result.selector_record_id
                or decision.selector_record_sha256 != edge_local_result.selector_record_sha256
                or decision.trusted_registration_id != edge_local_result.trusted_registration_id
                or decision.trusted_registration_sha256
                != edge_local_result.trusted_registration_sha256
                or decision.funding_set_id != edge_local_result.funding_set_id
                or decision.funding_set_sha256 != edge_local_result.funding_set_sha256
                or decision.recognized_outpoint_count
                != edge_local_result.recognized_outpoint_count
                or decision.qualifying_observation_count
                != edge_local_result.qualifying_observation_count
                or decision.observed_at
                != edge_local_result.observed_at.astimezone(timezone.utc)
                or decision.observed_block_height != edge_local_result.observed_block_height
                or decision.incoming_sats != edge_local_result.incoming_sats
                or decision.outgoing_sats != edge_local_result.outgoing_sats
                or decision.relation_reason is not edge_local_result.relation_reason
                or decision.relation_source_evidence_sha256
                != edge_local_result.relation_source_evidence_sha256
                or decision.policy_version != POLICY_VERSION
                or decision.evidence_source != EVIDENCE_SOURCE
                or type(decision.identity_class) is not IdentityClass
                or decision.identity_class not in (IdentityClass.FULL, IdentityClass.LIMITED)
                or type(decision.current_full_relation_satisfied) is not bool
                or decision.current_full_relation_satisfied
                is not edge_local_result.current_full_relation_satisfied
                or (decision.identity_class is IdentityClass.FULL)
                is not decision.current_full_relation_satisfied
                or type(decision.observed_at) is not datetime
                or decision.observed_at.tzinfo is None
                or decision.observed_at.utcoffset() is None
            ):
                raise ValueError()

            observed_at = decision.observed_at.astimezone(timezone.utc)
            raw_materializer_time = self._clock()
            if (
                type(raw_materializer_time) is not datetime
                or raw_materializer_time.tzinfo is None
                or raw_materializer_time.utcoffset() is None
            ):
                raise ValueError()
            materializer_time = raw_materializer_time.astimezone(timezone.utc)
            if materializer_time - observed_at > timedelta(seconds=MAX_OBSERVATION_AGE_SECONDS):
                raise ValueError()
            if observed_at - materializer_time > timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
                raise ValueError()

            generated_uuid = self._uuid_factory()
            if type(generated_uuid) is not uuid.UUID:
                raise ValueError()
            evidence_id = str(generated_uuid)
            if str(uuid.UUID(evidence_id)) != evidence_id:
                raise ValueError()

            record = CurrentEntitlementEvidenceRecord(
                evidence_id=evidence_id,
                contract_version=CONTRACT_VERSION,
                subject_pubkey=decision.subject_xonly_pubkey,
                identity_class=decision.identity_class,
                current_full_relation_satisfied=decision.current_full_relation_satisfied,
                evidence_source=decision.evidence_source,
                evidence_version=decision.policy_version,
                source_evidence_sha256=decision.source_evidence_sha256,
                observed_at=observed_at,
                valid_until=observed_at + timedelta(seconds=EVIDENCE_VALIDITY_SECONDS),
                revoked_at=None,
                created_at=max(materializer_time, observed_at),
            )
            self._repository.append(record)
            return record
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise CanonicalRootEntitlementMaterializationUnavailable() from None
