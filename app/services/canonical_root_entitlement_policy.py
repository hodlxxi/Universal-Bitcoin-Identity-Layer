"""Pure mapping of a canonical root-bound relation to participant entitlement."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
import uuid

from app.services.action_authorization import IdentityClass
from app.services.canonical_controlling_registration import (
    ControllingRegistrationSelectionSource,
)
from app.services.covenant_relation import MAX_BITCOIN_SATS, CovenantRelationReason
from app.services.edge_local_covenant_observation import EdgeLocalCovenantRelationResult

POLICY_VERSION = "hodlxxi.canonical_root_entitlement_policy.v1"
EVIDENCE_SOURCE = "canonical_root_bound_covenant_relation"

_XONLY = re.compile(r"[0-9a-f]{64}\Z")


class CanonicalRootEntitlementPolicyUnavailable(RuntimeError):
    def __init__(self) -> None:
        super().__init__("canonical root entitlement policy unavailable")


@dataclass(frozen=True, slots=True)
class CanonicalRootEntitlementDecision:
    policy_version: str
    graph_or_protocol_id: str
    subject_xonly_pubkey: str
    counterparty_xonly_pubkey: str
    identity_class: IdentityClass
    current_full_relation_satisfied: bool
    relation_reason: CovenantRelationReason
    evidence_source: str
    source_evidence_sha256: str
    observed_at: datetime
    observed_block_height: int
    controlling_selection_source: ControllingRegistrationSelectionSource
    selector_record_id: str
    selector_record_sha256: str
    trusted_registration_id: str
    trusted_registration_sha256: str
    funding_set_id: str
    funding_set_sha256: str
    recognized_outpoint_count: int
    qualifying_observation_count: int
    incoming_sats: int
    outgoing_sats: int
    relation_source_evidence_sha256: str


def _digest(value: object) -> None:
    if type(value) is not str or _XONLY.fullmatch(value) is None:
        raise ValueError()


def _identifier(value: object) -> None:
    if type(value) is not str or str(uuid.UUID(value)) != value:
        raise ValueError()


def _integer(value: object, minimum: int, maximum: int = MAX_BITCOIN_SATS) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError()


def _timestamp(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError()
    return value.astimezone(timezone.utc)


def _reason(incoming: int, outgoing: int) -> CovenantRelationReason:
    if incoming == 0 and outgoing == 0:
        return CovenantRelationReason.NO_QUALIFYING_OBSERVATIONS
    if incoming == 0:
        return CovenantRelationReason.MISSING_INCOMING
    if outgoing == 0:
        return CovenantRelationReason.MISSING_OUTGOING
    if outgoing < incoming:
        return CovenantRelationReason.OUTGOING_BELOW_INCOMING
    return CovenantRelationReason.FULL_RELATION_SATISFIED


def _canonical_source_bytes(result: EdgeLocalCovenantRelationResult, observed_at: datetime) -> bytes:
    payload = {
        "policy_version": POLICY_VERSION,
        "graph_or_protocol_id": result.graph_or_protocol_id,
        "subject_xonly_pubkey": result.subject_xonly_pubkey,
        "counterparty_xonly_pubkey": result.counterparty_xonly_pubkey,
        "controlling_selection_source": result.controlling_selection_source.value,
        "selector_record_id": result.selector_record_id,
        "selector_record_sha256": result.selector_record_sha256,
        "trusted_registration_id": result.trusted_registration_id,
        "trusted_registration_sha256": result.trusted_registration_sha256,
        "funding_set_id": result.funding_set_id,
        "funding_set_sha256": result.funding_set_sha256,
        "recognized_outpoint_count": result.recognized_outpoint_count,
        "qualifying_observation_count": result.qualifying_observation_count,
        "observed_at": observed_at.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "observed_block_height": result.observed_block_height,
        "incoming_sats": result.incoming_sats,
        "outgoing_sats": result.outgoing_sats,
        "current_full_relation_satisfied": result.current_full_relation_satisfied,
        "relation_reason": result.relation_reason.value,
        "relation_source_evidence_sha256": result.relation_source_evidence_sha256,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def evaluate_canonical_root_entitlement(
    graph_or_protocol_id: str,
    subject_xonly_pubkey: str,
    result: EdgeLocalCovenantRelationResult,
) -> CanonicalRootEntitlementDecision:
    """Validate one root summary and map it without I/O or materialization."""
    try:
        if type(result) is not EdgeLocalCovenantRelationResult:
            raise ValueError()
        if (
            type(graph_or_protocol_id) is not str
            or not graph_or_protocol_id
            or graph_or_protocol_id.strip() != graph_or_protocol_id
            or type(result.graph_or_protocol_id) is not str
            or result.graph_or_protocol_id != graph_or_protocol_id
        ):
            raise ValueError()
        _digest(subject_xonly_pubkey)
        _digest(result.subject_xonly_pubkey)
        _digest(result.counterparty_xonly_pubkey)
        if (
            result.subject_xonly_pubkey != subject_xonly_pubkey
            or subject_xonly_pubkey == result.counterparty_xonly_pubkey
        ):
            raise ValueError()
        if (
            result.controlling_selection_source
            is not ControllingRegistrationSelectionSource.CANONICAL_ROOT_REGISTRATION_BINDING
        ):
            raise ValueError()
        for value in (result.selector_record_id, result.trusted_registration_id, result.funding_set_id):
            _identifier(value)
        for value in (
            result.selector_record_sha256,
            result.trusted_registration_sha256,
            result.funding_set_sha256,
            result.relation_source_evidence_sha256,
        ):
            _digest(value)
        observed_at = _timestamp(result.observed_at)
        _integer(result.observed_block_height, 0)
        _integer(result.recognized_outpoint_count, 2)
        _integer(result.qualifying_observation_count, 0)
        _integer(result.incoming_sats, 0)
        _integer(result.outgoing_sats, 0)
        if result.qualifying_observation_count > result.recognized_outpoint_count:
            raise ValueError()
        if (
            type(result.relation_reason) is not CovenantRelationReason
            or type(result.current_full_relation_satisfied) is not bool
        ):
            raise ValueError()
        expected_reason = _reason(result.incoming_sats, result.outgoing_sats)
        if result.relation_reason is not expected_reason:
            raise ValueError()
        full = expected_reason is CovenantRelationReason.FULL_RELATION_SATISFIED
        if result.current_full_relation_satisfied is not full:
            raise ValueError()
        totals_zero = result.incoming_sats == 0 and result.outgoing_sats == 0
        if (result.qualifying_observation_count == 0) is not totals_zero:
            raise ValueError()
        if result.incoming_sats > 0 and result.outgoing_sats > 0 and result.qualifying_observation_count < 2:
            raise ValueError()
        qualifying_total = result.incoming_sats + result.outgoing_sats
        if qualifying_total < result.qualifying_observation_count:
            raise ValueError()
        ignored = result.recognized_outpoint_count - result.qualifying_observation_count
        if qualifying_total + ignored > MAX_BITCOIN_SATS:
            raise ValueError()
        source_hash = hashlib.sha256(_canonical_source_bytes(result, observed_at)).hexdigest()
        return CanonicalRootEntitlementDecision(
            POLICY_VERSION,
            graph_or_protocol_id,
            subject_xonly_pubkey,
            result.counterparty_xonly_pubkey,
            IdentityClass.FULL if full else IdentityClass.LIMITED,
            full,
            expected_reason,
            EVIDENCE_SOURCE,
            source_hash,
            observed_at,
            result.observed_block_height,
            result.controlling_selection_source,
            result.selector_record_id,
            result.selector_record_sha256,
            result.trusted_registration_id,
            result.trusted_registration_sha256,
            result.funding_set_id,
            result.funding_set_sha256,
            result.recognized_outpoint_count,
            result.qualifying_observation_count,
            result.incoming_sats,
            result.outgoing_sats,
            result.relation_source_evidence_sha256,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise CanonicalRootEntitlementPolicyUnavailable() from None
