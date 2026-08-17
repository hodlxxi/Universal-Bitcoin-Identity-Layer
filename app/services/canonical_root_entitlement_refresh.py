"""Coordinate one canonical-root entitlement refresh without runtime wiring."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Protocol

from app.services.action_authorization import IdentityClass
from app.services.canonical_controlling_registration import (
    ControllingRegistrationSelectionSource,
)
from app.services.canonical_root_entitlement_materializer import (
    CanonicalRootEntitlementMaterializer,
)
from app.services.canonical_root_entitlement_policy import (
    EVIDENCE_SOURCE,
    POLICY_VERSION,
    CanonicalRootEntitlementDecision,
    _canonical_source_bytes,
    evaluate_canonical_root_entitlement,
)
from app.services.current_entitlement_evidence import CurrentEntitlementEvidenceRecord
from app.services.edge_local_covenant_observation import (
    EdgeLocalCovenantRelationResult,
    observe_edge_local_covenant_relation,
)

REFRESH_CONTRACT_VERSION = "hodlxxi.canonical_root_entitlement_refresh.v1"


class CanonicalRootEntitlementRefreshUnavailable(RuntimeError):
    """The requested refresh could not be completed safely."""

    def __init__(self) -> None:
        super().__init__("canonical root entitlement refresh unavailable")


class CanonicalRootEntitlementRefreshMode(Enum):
    DRY_RUN = "dry_run"
    COMMIT = "commit"


class CanonicalRootEntitlementRefreshOutcome(Enum):
    PREVIEW = "preview"
    APPENDED = "appended"
    UNCHANGED = "unchanged"


class ExclusiveSubjectExecutionGuard(Protocol):
    """Caller-owned exclusive guard; deployment semantics are intentionally absent."""

    exclusive: bool

    def hold(self, subject_xonly_pubkey: str) -> AbstractContextManager[object]: ...


def _utc(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError()
    return value.astimezone(timezone.utc)


def _reconstruct_evidence(value: object) -> CurrentEntitlementEvidenceRecord:
    if type(value) is not CurrentEntitlementEvidenceRecord:
        raise ValueError()
    return CurrentEntitlementEvidenceRecord(**vars(value))


def _validate_pair(
    graph: str,
    subject: str,
    relation: object,
    decision: object,
) -> tuple[EdgeLocalCovenantRelationResult, CanonicalRootEntitlementDecision]:
    if type(relation) is not EdgeLocalCovenantRelationResult:
        raise ValueError()
    if type(decision) is not CanonicalRootEntitlementDecision:
        raise ValueError()
    if (
        relation.graph_or_protocol_id != graph
        or decision.graph_or_protocol_id != graph
        or relation.subject_xonly_pubkey != subject
        or decision.subject_xonly_pubkey != subject
        or relation.controlling_selection_source
        is not ControllingRegistrationSelectionSource.CANONICAL_ROOT_REGISTRATION_BINDING
        or decision.controlling_selection_source is not relation.controlling_selection_source
        or decision.counterparty_xonly_pubkey != relation.counterparty_xonly_pubkey
        or decision.selector_record_id != relation.selector_record_id
        or decision.selector_record_sha256 != relation.selector_record_sha256
        or decision.trusted_registration_id != relation.trusted_registration_id
        or decision.trusted_registration_sha256 != relation.trusted_registration_sha256
        or decision.funding_set_id != relation.funding_set_id
        or decision.funding_set_sha256 != relation.funding_set_sha256
        or decision.recognized_outpoint_count != relation.recognized_outpoint_count
        or decision.qualifying_observation_count != relation.qualifying_observation_count
        or decision.observed_at != _utc(relation.observed_at)
        or decision.observed_block_height != relation.observed_block_height
        or decision.incoming_sats != relation.incoming_sats
        or decision.outgoing_sats != relation.outgoing_sats
        or decision.current_full_relation_satisfied is not relation.current_full_relation_satisfied
        or decision.relation_reason is not relation.relation_reason
        or decision.relation_source_evidence_sha256 != relation.relation_source_evidence_sha256
        or decision.policy_version != POLICY_VERSION
        or decision.evidence_source != EVIDENCE_SOURCE
        or type(decision.identity_class) is not IdentityClass
        or decision.identity_class not in (IdentityClass.FULL, IdentityClass.LIMITED)
        or (decision.identity_class is IdentityClass.FULL) is not decision.current_full_relation_satisfied
        or decision.source_evidence_sha256
        != hashlib.sha256(_canonical_source_bytes(relation, _utc(relation.observed_at))).hexdigest()
    ):
        raise ValueError()
    return relation, decision


def _is_exact_replay(
    latest: CurrentEntitlementEvidenceRecord,
    decision: CanonicalRootEntitlementDecision,
) -> bool:
    return (
        latest.subject_pubkey == decision.subject_xonly_pubkey
        and latest.evidence_version == decision.policy_version
        and latest.evidence_source == decision.evidence_source
        and latest.source_evidence_sha256 == decision.source_evidence_sha256
        and latest.identity_class is decision.identity_class
        and latest.current_full_relation_satisfied is decision.current_full_relation_satisfied
        and latest.observed_at == decision.observed_at
    )


@dataclass(frozen=True, slots=True)
class CanonicalRootEntitlementRefreshResult:
    contract_version: str
    mode: CanonicalRootEntitlementRefreshMode
    outcome: CanonicalRootEntitlementRefreshOutcome
    graph_or_protocol_id: str
    subject_xonly_pubkey: str
    evaluated_at: datetime
    edge_local_result: EdgeLocalCovenantRelationResult
    decision: CanonicalRootEntitlementDecision
    evidence: CurrentEntitlementEvidenceRecord | None
    append_performed: bool

    def __post_init__(self) -> None:
        if (
            self.contract_version != REFRESH_CONTRACT_VERSION
            or type(self.mode) is not CanonicalRootEntitlementRefreshMode
            or type(self.outcome) is not CanonicalRootEntitlementRefreshOutcome
            or type(self.graph_or_protocol_id) is not str
            or not self.graph_or_protocol_id
            or self.graph_or_protocol_id.strip() != self.graph_or_protocol_id
            or type(self.subject_xonly_pubkey) is not str
            or len(self.subject_xonly_pubkey) != 64
        ):
            raise ValueError("invalid canonical root refresh result")
        evaluated_at = _utc(self.evaluated_at)
        _validate_pair(
            self.graph_or_protocol_id,
            self.subject_xonly_pubkey,
            self.edge_local_result,
            self.decision,
        )
        preview = self.mode is CanonicalRootEntitlementRefreshMode.DRY_RUN
        if preview is not (self.outcome is CanonicalRootEntitlementRefreshOutcome.PREVIEW):
            raise ValueError("invalid canonical root refresh result")
        expected_append = self.outcome is CanonicalRootEntitlementRefreshOutcome.APPENDED
        if type(self.append_performed) is not bool or self.append_performed is not expected_append:
            raise ValueError("invalid canonical root refresh result")
        if self.outcome is CanonicalRootEntitlementRefreshOutcome.PREVIEW:
            if self.evidence is not None:
                raise ValueError("invalid canonical root refresh result")
        else:
            evidence = _reconstruct_evidence(self.evidence)
            if not _is_exact_replay(evidence, self.decision):
                raise ValueError("invalid canonical root refresh result")
        object.__setattr__(self, "evaluated_at", evaluated_at)


def refresh_canonical_root_entitlement(
    graph_or_protocol_id: str,
    subject_xonly_pubkey: str,
    *,
    evaluated_at: datetime,
    mode: CanonicalRootEntitlementRefreshMode,
    genesis_repository: object,
    admission_edge_repository: object,
    root_registration_binding_repository: object,
    trusted_registration_repository: object,
    funding_set_repository: object,
    evidence_repository: object | None = None,
    observer: object | None = None,
    rpc_factory=None,
    execution_guard: ExclusiveSubjectExecutionGuard | None = None,
) -> CanonicalRootEntitlementRefreshResult:
    """Perform exactly one dry-run or guarded commit refresh."""

    def observe_and_decide():
        relation = observe_edge_local_covenant_relation(
            graph_or_protocol_id,
            subject_xonly_pubkey,
            evaluated_at=evaluated_at,
            genesis_repository=genesis_repository,
            admission_edge_repository=admission_edge_repository,
            root_registration_binding_repository=root_registration_binding_repository,
            trusted_registration_repository=trusted_registration_repository,
            funding_set_repository=funding_set_repository,
            observer=observer,
            rpc_factory=rpc_factory,
        )
        decision = evaluate_canonical_root_entitlement(graph_or_protocol_id, subject_xonly_pubkey, relation)
        return _validate_pair(graph_or_protocol_id, subject_xonly_pubkey, relation, decision)

    def result(outcome, relation, decision, evidence=None):
        return CanonicalRootEntitlementRefreshResult(
            REFRESH_CONTRACT_VERSION,
            mode,
            outcome,
            graph_or_protocol_id,
            subject_xonly_pubkey,
            evaluated_at,
            relation,
            decision,
            evidence,
            outcome is CanonicalRootEntitlementRefreshOutcome.APPENDED,
        )

    try:
        if type(mode) is not CanonicalRootEntitlementRefreshMode:
            raise ValueError()
        _utc(evaluated_at)
        if mode is CanonicalRootEntitlementRefreshMode.DRY_RUN:
            relation, decision = observe_and_decide()
            return result(CanonicalRootEntitlementRefreshOutcome.PREVIEW, relation, decision)

        if (
            execution_guard is None
            or getattr(execution_guard, "exclusive", None) is not True
            or not callable(getattr(execution_guard, "hold", None))
            or evidence_repository is None
            or not callable(getattr(evidence_repository, "get_latest", None))
            or not callable(getattr(evidence_repository, "append", None))
        ):
            raise ValueError()
        held = execution_guard.hold(subject_xonly_pubkey)
        if not callable(getattr(held, "__enter__", None)) or not callable(getattr(held, "__exit__", None)):
            raise ValueError()
        with held:
            raw_latest = evidence_repository.get_latest(subject_xonly_pubkey)
            latest = None if raw_latest is None else _reconstruct_evidence(raw_latest)
            relation, decision = observe_and_decide()
            if latest is not None and _is_exact_replay(latest, decision):
                return result(
                    CanonicalRootEntitlementRefreshOutcome.UNCHANGED,
                    relation,
                    decision,
                    latest,
                )
            materialized = CanonicalRootEntitlementMaterializer(evidence_repository).materialize(
                graph_or_protocol_id, subject_xonly_pubkey, relation
            )
            materialized = _reconstruct_evidence(materialized)
            verified = _reconstruct_evidence(evidence_repository.get_latest(subject_xonly_pubkey))
            if verified != materialized:
                raise ValueError()
            return result(
                CanonicalRootEntitlementRefreshOutcome.APPENDED,
                relation,
                decision,
                materialized,
            )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise CanonicalRootEntitlementRefreshUnavailable() from None
