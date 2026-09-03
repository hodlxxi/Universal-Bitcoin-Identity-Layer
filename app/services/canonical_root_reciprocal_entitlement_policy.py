"""Entitlement projection for the reciprocal counterparty of one canonical root-bound covenant relation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
import uuid

from app.services.action_authorization import IdentityClass
from app.services.canonical_root_entitlement_policy import (
    CanonicalRootEntitlementDecision,
    evaluate_canonical_root_entitlement,
)
from app.services.covenant_relation import (
    MAX_BITCOIN_SATS,
    CovenantRelationReason,
)
from app.services.edge_local_covenant_observation import (
    EdgeLocalCovenantRelationResult,
)

POLICY_VERSION = "hodlxxi.canonical_root_reciprocal_entitlement_policy.v1"
EVIDENCE_SOURCE = "canonical_root_bound_reciprocal_counterparty_relation"

_XONLY = re.compile(r"[0-9a-f]{64}\Z")


class CanonicalRootReciprocalEntitlementPolicyUnavailable(RuntimeError):
    """The reciprocal endpoint entitlement cannot be derived safely."""

    def __init__(self) -> None:
        super().__init__("canonical root reciprocal entitlement policy unavailable")


def _digest(value: object) -> str:
    if type(value) is not str or _XONLY.fullmatch(value) is None:
        raise ValueError()
    return value


def _uuid(value: object) -> str:
    if type(value) is not str or str(uuid.UUID(value)) != value:
        raise ValueError()
    return value


def _integer(
    value: object,
    minimum: int,
    maximum: int = MAX_BITCOIN_SATS,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError()
    return value


def _utc(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError()
    return value.astimezone(timezone.utc)


def _reason(
    incoming_sats: int,
    outgoing_sats: int,
) -> CovenantRelationReason:
    if incoming_sats == 0 and outgoing_sats == 0:
        return CovenantRelationReason.NO_QUALIFYING_OBSERVATIONS
    if incoming_sats == 0:
        return CovenantRelationReason.MISSING_INCOMING
    if outgoing_sats == 0:
        return CovenantRelationReason.MISSING_OUTGOING
    if outgoing_sats < incoming_sats:
        return CovenantRelationReason.OUTGOING_BELOW_INCOMING
    return CovenantRelationReason.FULL_RELATION_SATISFIED


@dataclass(frozen=True, slots=True)
class CanonicalRootReciprocalEntitlementDecision:
    policy_version: str
    graph_or_protocol_id: str
    root_subject_xonly_pubkey: str
    subject_xonly_pubkey: str
    counterparty_xonly_pubkey: str
    identity_class: IdentityClass
    current_full_relation_satisfied: bool
    relation_reason: CovenantRelationReason
    evidence_source: str
    source_evidence_sha256: str
    root_source_evidence_sha256: str
    relation_source_evidence_sha256: str
    observed_at: datetime
    observed_block_height: int
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

    def __post_init__(self) -> None:
        if (
            self.policy_version != POLICY_VERSION
            or self.evidence_source != EVIDENCE_SOURCE
            or type(self.graph_or_protocol_id) is not str
            or not self.graph_or_protocol_id
            or self.graph_or_protocol_id.strip() != self.graph_or_protocol_id
            or type(self.identity_class) is not IdentityClass
            or type(self.current_full_relation_satisfied) is not bool
            or type(self.relation_reason) is not CovenantRelationReason
        ):
            raise ValueError("invalid reciprocal entitlement decision")

        root = _digest(self.root_subject_xonly_pubkey)
        subject = _digest(self.subject_xonly_pubkey)
        counterparty = _digest(self.counterparty_xonly_pubkey)

        if root != counterparty or subject == counterparty or subject == root:
            raise ValueError("invalid reciprocal endpoint identities")

        for value in (
            self.source_evidence_sha256,
            self.root_source_evidence_sha256,
            self.relation_source_evidence_sha256,
            self.selector_record_sha256,
            self.trusted_registration_sha256,
            self.funding_set_sha256,
        ):
            _digest(value)

        for value in (
            self.selector_record_id,
            self.trusted_registration_id,
            self.funding_set_id,
        ):
            _uuid(value)

        observed = _utc(self.observed_at)

        _integer(self.observed_block_height, 0)
        _integer(self.recognized_outpoint_count, 2)
        _integer(self.qualifying_observation_count, 0)
        _integer(self.incoming_sats, 0)
        _integer(self.outgoing_sats, 0)

        if self.qualifying_observation_count > self.recognized_outpoint_count:
            raise ValueError("invalid reciprocal observation counts")

        expected_reason = _reason(
            self.incoming_sats,
            self.outgoing_sats,
        )
        expected_full = expected_reason is CovenantRelationReason.FULL_RELATION_SATISFIED

        if (
            self.relation_reason is not expected_reason
            or self.current_full_relation_satisfied is not expected_full
            or (self.identity_class is IdentityClass.FULL) is not expected_full
        ):
            raise ValueError("invalid reciprocal entitlement state")

        if self.incoming_sats > 0 and self.outgoing_sats > 0 and self.qualifying_observation_count < 2:
            raise ValueError("invalid reciprocal qualifying evidence")

        object.__setattr__(self, "observed_at", observed)


def _canonical_source_bytes(
    *,
    root_decision: CanonicalRootEntitlementDecision,
    subject_xonly_pubkey: str,
    incoming_sats: int,
    outgoing_sats: int,
    relation_reason: CovenantRelationReason,
    current_full: bool,
) -> bytes:
    payload = {
        "policy_version": POLICY_VERSION,
        "evidence_source": EVIDENCE_SOURCE,
        "graph_or_protocol_id": root_decision.graph_or_protocol_id,
        "root_subject_xonly_pubkey": root_decision.subject_xonly_pubkey,
        "subject_xonly_pubkey": subject_xonly_pubkey,
        "counterparty_xonly_pubkey": root_decision.subject_xonly_pubkey,
        "root_source_evidence_sha256": root_decision.source_evidence_sha256,
        "relation_source_evidence_sha256": root_decision.relation_source_evidence_sha256,
        "selector_record_id": root_decision.selector_record_id,
        "selector_record_sha256": root_decision.selector_record_sha256,
        "trusted_registration_id": root_decision.trusted_registration_id,
        "trusted_registration_sha256": root_decision.trusted_registration_sha256,
        "funding_set_id": root_decision.funding_set_id,
        "funding_set_sha256": root_decision.funding_set_sha256,
        "recognized_outpoint_count": root_decision.recognized_outpoint_count,
        "qualifying_observation_count": root_decision.qualifying_observation_count,
        "observed_at": root_decision.observed_at.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z"),
        "observed_block_height": root_decision.observed_block_height,
        "incoming_sats": incoming_sats,
        "outgoing_sats": outgoing_sats,
        "relation_reason": relation_reason.value,
        "current_full_relation_satisfied": current_full,
    }

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def evaluate_canonical_root_reciprocal_entitlement(
    graph_or_protocol_id: str,
    root_subject_xonly_pubkey: str,
    relation: EdgeLocalCovenantRelationResult,
) -> CanonicalRootReciprocalEntitlementDecision:
    """
    Evaluate the counterparty endpoint of one canonical root-bound relation.

    This does not create or imply a canonical admission edge.  It reuses the
    already-authoritative root-bound relation and evaluates the same Bitcoin
    funding from the counterparty's subject-relative direction.
    """

    try:
        root = evaluate_canonical_root_entitlement(
            graph_or_protocol_id,
            root_subject_xonly_pubkey,
            relation,
        )

        if type(root) is not CanonicalRootEntitlementDecision:
            raise ValueError()

        root = CanonicalRootEntitlementDecision(
            *(getattr(root, field) for field in CanonicalRootEntitlementDecision.__dataclass_fields__)
        )

        if (
            root.subject_xonly_pubkey != root_subject_xonly_pubkey
            or root.counterparty_xonly_pubkey != relation.counterparty_xonly_pubkey
        ):
            raise ValueError()

        subject = root.counterparty_xonly_pubkey

        # Subject-relative direction reverses for the opposite endpoint.
        incoming_sats = root.outgoing_sats
        outgoing_sats = root.incoming_sats

        reason = _reason(
            incoming_sats,
            outgoing_sats,
        )

        current_full = reason is CovenantRelationReason.FULL_RELATION_SATISFIED

        source_hash = hashlib.sha256(
            _canonical_source_bytes(
                root_decision=root,
                subject_xonly_pubkey=subject,
                incoming_sats=incoming_sats,
                outgoing_sats=outgoing_sats,
                relation_reason=reason,
                current_full=current_full,
            )
        ).hexdigest()

        return CanonicalRootReciprocalEntitlementDecision(
            POLICY_VERSION,
            root.graph_or_protocol_id,
            root.subject_xonly_pubkey,
            subject,
            root.subject_xonly_pubkey,
            (IdentityClass.FULL if current_full else IdentityClass.LIMITED),
            current_full,
            reason,
            EVIDENCE_SOURCE,
            source_hash,
            root.source_evidence_sha256,
            root.relation_source_evidence_sha256,
            root.observed_at,
            root.observed_block_height,
            root.selector_record_id,
            root.selector_record_sha256,
            root.trusted_registration_id,
            root.trusted_registration_sha256,
            root.funding_set_id,
            root.funding_set_sha256,
            root.recognized_outpoint_count,
            root.qualifying_observation_count,
            incoming_sats,
            outgoing_sats,
        )

    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise (CanonicalRootReciprocalEntitlementPolicyUnavailable()) from None
