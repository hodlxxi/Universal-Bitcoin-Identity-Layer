"""Read-only observation of one pointer-selected recognized funding relation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Callable
import uuid

from app.services.canonical_controlling_registration import (
    ControllingRegistrationSelection,
    ControllingRegistrationSelectionSource,
    resolve_controlling_registration,
)
from app.services.canonical_covenant_funding_set import (
    CanonicalCovenantFundingSet,
    CovenantFundingSetLifecycle,
    canonical_covenant_funding_set_bytes,
    canonical_covenant_funding_set_sha256,
    parse_canonical_covenant_funding_set,
    trusted_outpoints_from_canonical_funding_set,
    validate_funding_set_registration,
)
from app.services.covenant_relation import (
    CovenantRelationDecision,
    CovenantRelationEvaluation,
    CovenantRelationReason,
    canonical_relation_bytes,
    evaluate_covenant_relation,
)
from app.services.trusted_covenant_observation import TrustedBitcoinCovenantObservationAdapter
from app.services.trusted_covenant_registration import (
    TrustedCovenantRegistration,
    TrustedCovenantRegistrationLifecycle,
    canonical_trusted_registration_bytes,
    trusted_registration_sha256,
)

_canonical_evaluate_covenant_relation = evaluate_covenant_relation


class EdgeLocalCovenantObservationUnavailable(RuntimeError):
    def __init__(self) -> None:
        super().__init__("edge-local covenant observation unavailable")


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _uuid(value: object) -> None:
    if type(value) is not str or str(uuid.UUID(value)) != value:
        raise ValueError()


def _digest(value: object) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ValueError()


@dataclass(frozen=True, slots=True)
class EdgeLocalCovenantRelationResult:
    graph_or_protocol_id: str
    subject_xonly_pubkey: str
    counterparty_xonly_pubkey: str
    controlling_selection_source: ControllingRegistrationSelectionSource
    selector_record_id: str
    selector_record_sha256: str
    trusted_registration_id: str
    trusted_registration_sha256: str
    funding_set_id: str
    funding_set_sha256: str
    recognized_outpoint_count: int
    qualifying_observation_count: int
    observed_block_height: int
    incoming_sats: int
    outgoing_sats: int
    current_full_relation_satisfied: bool
    relation_reason: CovenantRelationReason
    relation_source_evidence_sha256: str


def _registration(value: object) -> TrustedCovenantRegistration:
    if type(value) is not TrustedCovenantRegistration:
        raise ValueError()
    canonical_trusted_registration_bytes(value)
    result = TrustedCovenantRegistration(
        *(getattr(value, field) for field in TrustedCovenantRegistration.__dataclass_fields__)
    )
    if result.lifecycle_state is not TrustedCovenantRegistrationLifecycle.ACTIVE:
        raise ValueError()
    return result


def _selection(value: object, graph: str, subject: str) -> ControllingRegistrationSelection:
    if type(value) is not ControllingRegistrationSelection:
        raise ValueError()
    registration = _registration(value.registration)
    if (
        value.graph_or_protocol_id != graph
        or value.subject_xonly_pubkey != subject
        or type(value.selection_source) is not ControllingRegistrationSelectionSource
        or registration.subject_xonly_pubkey != subject
    ):
        raise ValueError()
    _uuid(value.selector_record_id)
    _digest(value.selector_record_sha256)
    return ControllingRegistrationSelection(
        value.graph_or_protocol_id,
        value.subject_xonly_pubkey,
        value.selection_source,
        value.selector_record_id,
        value.selector_record_sha256,
        registration,
    )


def _evaluation(value: object) -> CovenantRelationEvaluation:
    if type(value) is not CovenantRelationEvaluation:
        raise ValueError()
    canonical_relation_bytes(value)
    return CovenantRelationEvaluation(
        *(getattr(value, field) for field in CovenantRelationEvaluation.__dataclass_fields__)
    )


def observe_edge_local_covenant_relation(
    graph_or_protocol_id: str,
    subject_xonly_pubkey: str,
    *,
    evaluated_at: datetime,
    genesis_repository,
    admission_edge_repository,
    root_registration_binding_repository,
    trusted_registration_repository,
    funding_set_repository,
    observer=None,
    rpc_factory: Callable[[], object] | None = None,
) -> EdgeLocalCovenantRelationResult:
    """Observe one controlling edge without persisting or granting entitlement."""
    try:
        selection = _selection(resolve_controlling_registration(
            graph_or_protocol_id,
            subject_xonly_pubkey,
            evaluated_at=evaluated_at,
            genesis_repository=genesis_repository,
            admission_edge_repository=admission_edge_repository,
            root_registration_binding_repository=root_registration_binding_repository,
            trusted_registration_repository=trusted_registration_repository,
        ), graph_or_protocol_id, subject_xonly_pubkey)
        registration = selection.registration

        raw_funding_set = funding_set_repository.resolve_effective(registration.registration_id)
        if type(raw_funding_set) is not CanonicalCovenantFundingSet:
            raise ValueError()
        funding_set = parse_canonical_covenant_funding_set(
            canonical_covenant_funding_set_bytes(raw_funding_set)
        )
        funding_set = validate_funding_set_registration(funding_set, registration)
        if (
            funding_set.lifecycle_state is not CovenantFundingSetLifecycle.EFFECTIVE
            or funding_set.trusted_registration_id != registration.registration_id
            or funding_set.trusted_registration_sha256 != trusted_registration_sha256(registration)
            or funding_set.subject_xonly_pubkey != registration.subject_xonly_pubkey
            or funding_set.counterparty_xonly_pubkey != registration.counterparty_xonly_pubkey
            or funding_set.pair_sha256 != registration.pair_sha256
        ):
            raise ValueError()
        trusted_outpoints = trusted_outpoints_from_canonical_funding_set(funding_set)

        if observer is None:
            if rpc_factory is None:
                from app.utils import get_rpc_connection
                rpc_factory = get_rpc_connection
            observer = TrustedBitcoinCovenantObservationAdapter(rpc_factory())
        if not callable(getattr(observer, "observe", None)):
            raise ValueError()
        evaluation = _evaluation(observer.observe(trusted_outpoints))
        if (
            evaluation.subject_pubkey != registration.subject_xonly_pubkey
            or evaluation.counterparty_pubkey != registration.counterparty_xonly_pubkey
            or len(evaluation.observations) != len(trusted_outpoints)
            or {
                (x.subject_pubkey, x.counterparty_pubkey, x.direction, x.txid, x.vout,
                 x.amount_sats, x.script_sha256, x.descriptor_sha256)
                for x in evaluation.observations
            } != {
                (x.subject_pubkey, x.counterparty_pubkey, x.direction, x.txid, x.vout,
                 x.amount_sats, x.script_sha256, x.descriptor_sha256)
                for x in trusted_outpoints
            }
        ):
            raise ValueError()
        decision = evaluate_covenant_relation(evaluation)
        if type(decision) is not CovenantRelationDecision:
            raise ValueError()
        # Reconstruct the frozen result to enforce the decision's domain contract.
        decision = CovenantRelationDecision(
            *(getattr(decision, field) for field in CovenantRelationDecision.__dataclass_fields__)
        )
        expected_decision = _canonical_evaluate_covenant_relation(evaluation)
        if decision != expected_decision:
            raise ValueError()
        return EdgeLocalCovenantRelationResult(
            graph_or_protocol_id,
            subject_xonly_pubkey,
            registration.counterparty_xonly_pubkey,
            selection.selection_source,
            selection.selector_record_id,
            selection.selector_record_sha256,
            registration.registration_id,
            trusted_registration_sha256(registration),
            funding_set.funding_set_id,
            canonical_covenant_funding_set_sha256(funding_set),
            len(trusted_outpoints),
            decision.qualifying_observation_count,
            decision.observed_block_height,
            decision.incoming_sats,
            decision.outgoing_sats,
            decision.current_full_relation_satisfied,
            decision.reason,
            decision.source_evidence_sha256,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise EdgeLocalCovenantObservationUnavailable() from None
