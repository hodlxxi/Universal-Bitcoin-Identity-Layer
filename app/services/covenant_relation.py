"""Pure evaluation of a canonical, exact-pair Bitcoin covenant relation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re

OBSERVATION_SCHEMA = "hodlxxi.covenant_relation_observation.v1"
EVALUATION_SCHEMA = "hodlxxi.covenant_relation_evaluation.v1"
DECISION_SCHEMA = "hodlxxi.covenant_relation_decision.v1"
NETWORK = "bitcoin"
MIN_CONFIRMATIONS = 1
MAX_BITCOIN_SATS = 2_100_000_000_000_000
MAX_VOUT = 4_294_967_295

_LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")


class InvalidCovenantRelation(ValueError):
    """Raised when covenant relation input violates the canonical contract."""


class CovenantDirection(Enum):
    INCOMING = "incoming"
    OUTGOING = "outgoing"


class CovenantRelationReason(Enum):
    FULL_RELATION_SATISFIED = "full_relation_satisfied"
    NO_QUALIFYING_OBSERVATIONS = "no_qualifying_observations"
    MISSING_INCOMING = "missing_incoming"
    MISSING_OUTGOING = "missing_outgoing"
    OUTGOING_BELOW_INCOMING = "outgoing_below_incoming"


def _require_digest(value: object, field: str) -> None:
    if type(value) is not str or _LOWER_HEX_64.fullmatch(value) is None:
        raise InvalidCovenantRelation(f"{field} must be canonical lowercase 64-hex")


def _require_exact_int(value: object, field: str, *, minimum: int, maximum: int | None = None) -> None:
    if type(value) is not int:
        raise InvalidCovenantRelation(f"{field} must be an exact int")
    if value < minimum or (maximum is not None and value > maximum):
        raise InvalidCovenantRelation(f"{field} is outside its permitted range")


def _require_pair(subject_pubkey: object, counterparty_pubkey: object) -> None:
    _require_digest(subject_pubkey, "subject_pubkey")
    _require_digest(counterparty_pubkey, "counterparty_pubkey")
    if subject_pubkey == counterparty_pubkey:
        raise InvalidCovenantRelation("subject_pubkey and counterparty_pubkey must differ")


def _utc(value: object, field: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise InvalidCovenantRelation(f"{field} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class CovenantRelationObservation:
    schema: str
    subject_pubkey: str
    counterparty_pubkey: str
    direction: CovenantDirection
    txid: str
    vout: int
    amount_sats: int
    script_sha256: str
    descriptor_sha256: str | None
    confirmations: int
    unspent: bool

    def __post_init__(self) -> None:
        if type(self.schema) is not str or self.schema != OBSERVATION_SCHEMA:
            raise InvalidCovenantRelation("invalid observation schema")
        _require_pair(self.subject_pubkey, self.counterparty_pubkey)
        if type(self.direction) is not CovenantDirection:
            raise InvalidCovenantRelation("direction must be an exact CovenantDirection")
        _require_digest(self.txid, "txid")
        _require_exact_int(self.vout, "vout", minimum=0, maximum=MAX_VOUT)
        _require_exact_int(self.amount_sats, "amount_sats", minimum=1, maximum=MAX_BITCOIN_SATS)
        _require_digest(self.script_sha256, "script_sha256")
        if self.descriptor_sha256 is not None:
            _require_digest(self.descriptor_sha256, "descriptor_sha256")
        _require_exact_int(self.confirmations, "confirmations", minimum=0)
        if type(self.unspent) is not bool:
            raise InvalidCovenantRelation("unspent must be an exact bool")


@dataclass(frozen=True, slots=True)
class CovenantRelationEvaluation:
    schema: str
    network: str
    subject_pubkey: str
    counterparty_pubkey: str
    observed_at: datetime
    observed_block_height: int
    observations: tuple[CovenantRelationObservation, ...]

    def __post_init__(self) -> None:
        if type(self.schema) is not str or self.schema != EVALUATION_SCHEMA:
            raise InvalidCovenantRelation("invalid evaluation schema")
        if type(self.network) is not str or self.network != NETWORK:
            raise InvalidCovenantRelation("network must be exactly bitcoin")
        _require_pair(self.subject_pubkey, self.counterparty_pubkey)
        object.__setattr__(self, "observed_at", _utc(self.observed_at, "observed_at"))
        _require_exact_int(self.observed_block_height, "observed_block_height", minimum=0)
        if type(self.observations) is not tuple:
            raise InvalidCovenantRelation("observations must be an immutable tuple")

        seen: set[tuple[str, int]] = set()
        total = 0
        for observation in self.observations:
            if type(observation) is not CovenantRelationObservation:
                raise InvalidCovenantRelation("every item must be an exact CovenantRelationObservation")
            if observation.subject_pubkey != self.subject_pubkey:
                raise InvalidCovenantRelation("observation subject does not match evaluation subject")
            if observation.counterparty_pubkey != self.counterparty_pubkey:
                raise InvalidCovenantRelation("observation counterparty does not match evaluation counterparty")
            outpoint = (observation.txid, observation.vout)
            if outpoint in seen:
                raise InvalidCovenantRelation("duplicate outpoint")
            seen.add(outpoint)
            total += observation.amount_sats
            if total > MAX_BITCOIN_SATS:
                raise InvalidCovenantRelation("total observation amount exceeds MAX_BITCOIN_SATS")


@dataclass(frozen=True, slots=True)
class CovenantRelationDecision:
    schema: str
    subject_pubkey: str
    counterparty_pubkey: str
    current_full_relation_satisfied: bool
    reason: CovenantRelationReason
    incoming_sats: int
    outgoing_sats: int
    qualifying_observation_count: int
    ignored_observation_count: int
    observed_at: datetime
    observed_block_height: int
    source_evidence_sha256: str

    def __post_init__(self) -> None:
        if type(self.schema) is not str or self.schema != DECISION_SCHEMA:
            raise InvalidCovenantRelation("invalid decision schema")
        _require_pair(self.subject_pubkey, self.counterparty_pubkey)
        if type(self.reason) is not CovenantRelationReason:
            raise InvalidCovenantRelation("reason must be an exact CovenantRelationReason")
        if type(self.current_full_relation_satisfied) is not bool:
            raise InvalidCovenantRelation("current_full_relation_satisfied must be an exact bool")
        expected = self.reason is CovenantRelationReason.FULL_RELATION_SATISFIED
        if self.current_full_relation_satisfied is not expected:
            raise InvalidCovenantRelation("decision boolean is inconsistent with reason")
        for field in (
            "incoming_sats",
            "outgoing_sats",
            "qualifying_observation_count",
            "ignored_observation_count",
            "observed_block_height",
        ):
            _require_exact_int(getattr(self, field), field, minimum=0)
        object.__setattr__(self, "observed_at", _utc(self.observed_at, "observed_at"))
        _require_digest(self.source_evidence_sha256, "source_evidence_sha256")


def _validated(evaluation: object) -> CovenantRelationEvaluation:
    if type(evaluation) is not CovenantRelationEvaluation:
        raise InvalidCovenantRelation("evaluation must be an exact CovenantRelationEvaluation")
    return CovenantRelationEvaluation(
        schema=evaluation.schema,
        network=evaluation.network,
        subject_pubkey=evaluation.subject_pubkey,
        counterparty_pubkey=evaluation.counterparty_pubkey,
        observed_at=evaluation.observed_at,
        observed_block_height=evaluation.observed_block_height,
        observations=evaluation.observations,
    )


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical_relation_bytes(evaluation: CovenantRelationEvaluation) -> bytes:
    """Return the exact ASCII-safe canonical JSON source representation."""
    evaluation = _validated(evaluation)
    observations = sorted(
        evaluation.observations,
        key=lambda item: (item.txid, item.vout, item.direction.value),
    )
    payload = {
        "schema": evaluation.schema,
        "network": evaluation.network,
        "subject_pubkey": evaluation.subject_pubkey,
        "counterparty_pubkey": evaluation.counterparty_pubkey,
        "observed_at": _timestamp(evaluation.observed_at),
        "observed_block_height": evaluation.observed_block_height,
        "observations": [
            {
                "schema": item.schema,
                "subject_pubkey": item.subject_pubkey,
                "counterparty_pubkey": item.counterparty_pubkey,
                "direction": item.direction.value,
                "txid": item.txid,
                "vout": item.vout,
                "amount_sats": item.amount_sats,
                "script_sha256": item.script_sha256,
                "descriptor_sha256": item.descriptor_sha256,
                "confirmations": item.confirmations,
                "unspent": item.unspent,
            }
            for item in observations
        ],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def covenant_relation_source_sha256(evaluation: CovenantRelationEvaluation) -> str:
    """Hash the exact canonical evaluation source bytes with SHA-256."""
    return hashlib.sha256(canonical_relation_bytes(evaluation)).hexdigest()


def evaluate_covenant_relation(evaluation: CovenantRelationEvaluation) -> CovenantRelationDecision:
    """Evaluate one exact reciprocal pair without I/O or external state."""
    evaluation = _validated(evaluation)
    qualifying = tuple(
        item for item in evaluation.observations if item.unspent is True and item.confirmations >= MIN_CONFIRMATIONS
    )
    incoming = sum(item.amount_sats for item in qualifying if item.direction is CovenantDirection.INCOMING)
    outgoing = sum(item.amount_sats for item in qualifying if item.direction is CovenantDirection.OUTGOING)

    if incoming == 0 and outgoing == 0:
        reason = CovenantRelationReason.NO_QUALIFYING_OBSERVATIONS
    elif incoming == 0:
        reason = CovenantRelationReason.MISSING_INCOMING
    elif outgoing == 0:
        reason = CovenantRelationReason.MISSING_OUTGOING
    elif outgoing < incoming:
        reason = CovenantRelationReason.OUTGOING_BELOW_INCOMING
    else:
        reason = CovenantRelationReason.FULL_RELATION_SATISFIED

    return CovenantRelationDecision(
        schema=DECISION_SCHEMA,
        subject_pubkey=evaluation.subject_pubkey,
        counterparty_pubkey=evaluation.counterparty_pubkey,
        current_full_relation_satisfied=reason is CovenantRelationReason.FULL_RELATION_SATISFIED,
        reason=reason,
        incoming_sats=incoming,
        outgoing_sats=outgoing,
        qualifying_observation_count=len(qualifying),
        ignored_observation_count=len(evaluation.observations) - len(qualifying),
        observed_at=evaluation.observed_at,
        observed_block_height=evaluation.observed_block_height,
        source_evidence_sha256=covenant_relation_source_sha256(evaluation),
    )
