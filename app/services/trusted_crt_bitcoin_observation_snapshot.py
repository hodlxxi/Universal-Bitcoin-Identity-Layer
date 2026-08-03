"""Dormant globally anchored Bitcoin observation of one exact CRT source plan."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import json
import re
from typing import Callable
from types import SimpleNamespace

from app.services.trusted_crt_authorization_source_plan import (
    TrustedCrtAuthorizationSourcePlan,
    TrustedCrtLineageSource,
    trusted_crt_authorization_source_plan_manifest_bytes,
    trusted_crt_authorization_source_plan_manifest_sha256,
)
from app.services.trusted_covenant_registration import trusted_outpoints_from_registration
from app.services.trusted_covenant_observation import (
    TrustedBitcoinCovenantObservationAdapter,
    TrustedCovenantOutpoint,
)
from app.services.covenant_relation import (
    CovenantRelationEvaluation,
    CovenantRelationObservation,
    canonical_relation_bytes,
    covenant_relation_source_sha256,
)

SCHEMA = "hodlxxi.trusted_crt_bitcoin_observation_snapshot.v1"
ADAPTER_VERSION = "hodlxxi.trusted_crt_bitcoin_observation_snapshot_adapter.v1"
OUTPOINT_MANIFEST_SCHEMA = "hodlxxi.trusted_crt_outpoint_manifest.v1"
STATUS = (
    "IMPLEMENTED_DORMANT", "READ_ONLY_INJECTED_BITCOIN_OBSERVATION",
    "GLOBALLY_ANCHORED_MULTI_EDGE_SNAPSHOT", "BEST_BLOCK_HASH_BOUND",
    "SOURCE_PLAN_CONSUMER_ONLY", "NOT_LINEAGE_EVIDENCE_CONVERSION",
    "NOT_PROOF_GENERATION", "NOT_PRODUCTION_RPC_WIRING",
    "NOT_RUNTIME_AUTHORIZATION", "NOT_DEPLOYED",
)
EXPLICIT_NON_CLAIMS = (
    "no transaction broadcast", "no signing", "no wallet import", "no custody",
    "no LND call", "no production RPC singleton", "no production RPC configuration",
    "no database read", "no database write", "no repository lookup",
    "no target-edge discovery", "no participant discovery", "no lineage-evidence conversion",
    "no PR6.16 invocation", "no membership evaluation", "no FULL/LIMITED decision",
    "no authorization proof generation", "no entitlement evidence write",
    "no current-entitlement integration", "no action-authorization integration",
    "no session mutation", "no role mutation", "no scope grant",
    "no administrator/operator grant", "no invite/sponsor permission",
    "no proof of private-key possession", "no signature or issuer attestation",
    "no finality guarantee beyond reported confirmations",
    "no claim after observation_completed_at", "no mempool-inclusive observation",
    "no HTTP route", "no MCP tool", "no paid job", "no CLI", "no scheduler",
    "no deployment or production-enforcement claim",
)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class TrustedCrtBitcoinObservationUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("trusted CRT Bitcoin observation unavailable")


class TrustedCrtBitcoinObservationState(Enum):
    OBSERVED = "observed"
    NOT_REQUIRED = "not_required"


def _fail() -> None:
    raise TrustedCrtBitcoinObservationUnavailable()


def _digest(value: object) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _fail()


def _utc(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _source_plan(value: object) -> tuple[TrustedCrtAuthorizationSourcePlan, str]:
    """Deep-detach and authoritatively revalidate one exact PR6.17 plan."""
    if type(value) is not TrustedCrtAuthorizationSourcePlan:
        _fail()
    try:
        detached = TrustedCrtAuthorizationSourcePlan(*(
            deepcopy(getattr(value, field))
            for field in TrustedCrtAuthorizationSourcePlan.__dataclass_fields__
        ))
        encoded = trusted_crt_authorization_source_plan_manifest_bytes(detached)
        digest = sha256(encoded).hexdigest()
        if (digest != detached.manifest_sha256
                or digest != trusted_crt_authorization_source_plan_manifest_sha256(detached)):
            _fail()
        return detached, digest
    except (KeyboardInterrupt, SystemExit):
        raise
    except TrustedCrtBitcoinObservationUnavailable:
        raise
    except Exception:
        _fail()


def _outpoint(value: object) -> TrustedCovenantOutpoint:
    if type(value) is not TrustedCovenantOutpoint:
        _fail()
    try:
        return TrustedCovenantOutpoint(*(getattr(value, f) for f in TrustedCovenantOutpoint.__dataclass_fields__))
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        _fail()


def trusted_crt_outpoint_manifest_bytes(outpoints: tuple[TrustedCovenantOutpoint, ...]) -> bytes:
    if type(outpoints) is not tuple or len(outpoints) != 2:
        _fail()
    detached = tuple(sorted((_outpoint(item) for item in outpoints), key=lambda x: (x.txid, x.vout, x.direction.value)))
    if len({(x.txid, x.vout) for x in detached}) != 2:
        _fail()
    payload = {"schema": OUTPOINT_MANIFEST_SCHEMA, "outpoints": [{
        "subject": x.subject_pubkey, "counterparty": x.counterparty_pubkey,
        "direction": x.direction.value, "txid": x.txid, "vout": x.vout,
        "amount_sats": x.amount_sats, "script_sha256": x.script_sha256,
        "descriptor_sha256": x.descriptor_sha256,
    } for x in detached]}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def trusted_crt_outpoint_manifest_sha256(outpoints: tuple[TrustedCovenantOutpoint, ...]) -> str:
    return sha256(trusted_crt_outpoint_manifest_bytes(outpoints)).hexdigest()


def _observation(value: object) -> CovenantRelationObservation:
    if type(value) is not CovenantRelationObservation:
        _fail()
    try:
        return CovenantRelationObservation(*(getattr(value, f) for f in CovenantRelationObservation.__dataclass_fields__))
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        _fail()


def _evaluation(value: object) -> CovenantRelationEvaluation:
    if type(value) is not CovenantRelationEvaluation:
        _fail()
    try:
        return CovenantRelationEvaluation(
            value.schema, value.network, value.subject_pubkey, value.counterparty_pubkey,
            value.observed_at, value.observed_block_height,
            tuple(_observation(item) for item in value.observations),
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        _fail()


@dataclass(frozen=True, slots=True)
class TrustedCrtObservedLineageRelation:
    depth: int
    edge_id: str
    edge_sha256: str
    registration_id: str
    registration_sha256: str
    trusted_outpoints: tuple[TrustedCovenantOutpoint, ...]
    trusted_outpoints_sha256: str
    relation_evaluation: CovenantRelationEvaluation
    relation_evaluation_sha256: str

    def __post_init__(self):
        if type(self) is not TrustedCrtObservedLineageRelation or type(self.depth) is not int or self.depth < 1:
            _fail()
        for value in (self.edge_sha256, self.registration_sha256, self.trusted_outpoints_sha256,
                      self.relation_evaluation_sha256):
            _digest(value)
        if type(self.edge_id) is not str or type(self.registration_id) is not str:
            _fail()
        outpoints = tuple(_outpoint(x) for x in self.trusted_outpoints) if type(self.trusted_outpoints) is tuple else _fail()
        evaluation = _evaluation(self.relation_evaluation)
        ordered = tuple(sorted(outpoints, key=lambda x: (x.txid, x.vout, x.direction.value)))
        if (len(ordered) != 2 or outpoints != ordered
                or self.trusted_outpoints_sha256 != trusted_crt_outpoint_manifest_sha256(ordered)
                or self.relation_evaluation_sha256 != covenant_relation_source_sha256(evaluation)
                or len(evaluation.observations) != 2):
            _fail()
        for definition, observation in zip(ordered, evaluation.observations):
            if any(getattr(definition, field) != getattr(observation, field) for field in (
                "subject_pubkey", "counterparty_pubkey", "direction", "txid", "vout",
                "amount_sats", "script_sha256", "descriptor_sha256")):
                _fail()
        object.__setattr__(self, "trusted_outpoints", ordered)
        object.__setattr__(self, "relation_evaluation", evaluation)


def _relation_payload(item: TrustedCrtObservedLineageRelation) -> dict:
    return {
        "depth": item.depth, "edge_id": item.edge_id, "edge_sha256": item.edge_sha256,
        "registration_id": item.registration_id, "registration_sha256": item.registration_sha256,
        "trusted_outpoints_sha256": item.trusted_outpoints_sha256,
        "relation_evaluation_sha256": item.relation_evaluation_sha256,
    }


def _snapshot_payload(snapshot: object) -> dict:
    return {
        "schema": snapshot.schema, "adapter_version": snapshot.adapter_version,
        "source_plan_manifest_sha256": snapshot.source_plan_manifest_sha256,
        "graph_or_protocol_id": snapshot.graph_or_protocol_id,
        "participant_id": snapshot.participant_id, "target_edge_id": snapshot.target_edge_id,
        "source_plan_depth": snapshot.source_plan_depth,
        "observed_block_height": snapshot.observed_block_height,
        "observed_best_block_hash": snapshot.observed_best_block_hash,
        "observation_started_at": _timestamp(snapshot.observation_started_at),
        "observation_completed_at": _timestamp(snapshot.observation_completed_at),
        "observed_relations": [_relation_payload(x) for x in snapshot.observed_relations],
        "explicit_non_claims": list(snapshot.explicit_non_claims),
        "human_interpretation_required": snapshot.human_interpretation_required,
    }


def _snapshot_bytes_unchecked(snapshot: object) -> bytes:
    return json.dumps(_snapshot_payload(snapshot), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


@dataclass(frozen=True, slots=True)
class TrustedCrtBitcoinObservationSnapshot:
    schema: str
    adapter_version: str
    source_plan_manifest_sha256: str
    source_plan: TrustedCrtAuthorizationSourcePlan
    graph_or_protocol_id: str
    participant_id: str
    target_edge_id: str
    source_plan_depth: int
    observed_block_height: int
    observed_best_block_hash: str
    observation_started_at: datetime
    observation_completed_at: datetime
    observed_relations: tuple[TrustedCrtObservedLineageRelation, ...]
    snapshot_sha256: str
    explicit_non_claims: tuple[str, ...]
    human_interpretation_required: bool

    def __post_init__(self):
        if (type(self) is not TrustedCrtBitcoinObservationSnapshot or self.schema != SCHEMA
                or self.adapter_version != ADAPTER_VERSION or type(self.graph_or_protocol_id) is not str
                or type(self.participant_id) is not str or type(self.target_edge_id) is not str
                or type(self.source_plan_depth) is not int or self.source_plan_depth < 1
                or type(self.observed_block_height) is not int or self.observed_block_height < 0
                or type(self.observed_relations) is not tuple or not self.observed_relations
                or self.explicit_non_claims != EXPLICIT_NON_CLAIMS
                or self.human_interpretation_required is not True):
            _fail()
        for value in (self.source_plan_manifest_sha256, self.observed_best_block_hash, self.snapshot_sha256):
            _digest(value)
        plan, plan_digest = _source_plan(self.source_plan)
        if (self.source_plan_manifest_sha256 != plan_digest
                or self.graph_or_protocol_id != plan.graph_or_protocol_id
                or self.participant_id != plan.participant_id
                or self.target_edge_id != plan.target_edge_id
                or self.source_plan_depth != plan.depth):
            _fail()
        started, completed = _utc(self.observation_started_at), _utc(self.observation_completed_at)
        if completed < started:
            _fail()
        if any(type(item) is not TrustedCrtObservedLineageRelation for item in self.observed_relations):
            _fail()
        relations = tuple(TrustedCrtObservedLineageRelation(*(getattr(x, f) for f in TrustedCrtObservedLineageRelation.__dataclass_fields__))
                          for x in self.observed_relations)
        required_sources = tuple(source for source in plan.lineage_sources if source.observation_required)
        if not required_sources or len(relations) != len(required_sources):
            _fail()
        global_identities: set[tuple[str, int]] = set()
        for relation, source in zip(relations, required_sources):
            if ((relation.depth, relation.edge_id, relation.edge_sha256,
                 relation.registration_id, relation.registration_sha256) !=
                    (source.depth, source.edge_id, source.edge_sha256,
                     source.registration_id, source.registration_sha256)):
                _fail()
            try:
                authoritative = tuple(sorted(
                    (_outpoint(item) for item in trusted_outpoints_from_registration(source.registration)),
                    key=lambda item: (item.txid, item.vout, item.direction.value),
                ))
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                _fail()
            if (len(authoritative) != 2 or relation.trusted_outpoints != authoritative
                    or relation.trusted_outpoints_sha256
                    != trusted_crt_outpoint_manifest_sha256(authoritative)
                    or relation.relation_evaluation.subject_pubkey
                    != source.registration.subject_xonly_pubkey
                    or relation.relation_evaluation.counterparty_pubkey
                    != source.registration.counterparty_xonly_pubkey
                    or relation.relation_evaluation.observed_block_height
                    != self.observed_block_height
                    or relation.relation_evaluation.observed_at != started
                    or relation.relation_evaluation_sha256
                    != covenant_relation_source_sha256(relation.relation_evaluation)):
                _fail()
            for item in authoritative:
                identity = (item.txid, item.vout)
                if identity in global_identities:
                    _fail()
                global_identities.add(identity)
        object.__setattr__(self, "source_plan", plan)
        object.__setattr__(self, "observation_started_at", started)
        object.__setattr__(self, "observation_completed_at", completed)
        object.__setattr__(self, "observed_relations", relations)
        if self.snapshot_sha256 != sha256(_snapshot_bytes_unchecked(self)).hexdigest():
            _fail()


def trusted_crt_bitcoin_observation_snapshot_bytes(snapshot: TrustedCrtBitcoinObservationSnapshot) -> bytes:
    if type(snapshot) is not TrustedCrtBitcoinObservationSnapshot:
        _fail()
    validated = TrustedCrtBitcoinObservationSnapshot(*(getattr(snapshot, f) for f in TrustedCrtBitcoinObservationSnapshot.__dataclass_fields__))
    return _snapshot_bytes_unchecked(validated)


def trusted_crt_bitcoin_observation_snapshot_sha256(snapshot: TrustedCrtBitcoinObservationSnapshot) -> str:
    return sha256(trusted_crt_bitcoin_observation_snapshot_bytes(snapshot)).hexdigest()


@dataclass(frozen=True, slots=True)
class TrustedCrtBitcoinObservationResolution:
    state: TrustedCrtBitcoinObservationState
    source_plan_manifest_sha256: str
    snapshot: TrustedCrtBitcoinObservationSnapshot | None

    def __post_init__(self):
        if type(self) is not TrustedCrtBitcoinObservationResolution or type(self.state) is not TrustedCrtBitcoinObservationState:
            _fail()
        _digest(self.source_plan_manifest_sha256)
        if self.state is TrustedCrtBitcoinObservationState.NOT_REQUIRED:
            if self.snapshot is not None:
                _fail()
        else:
            if type(self.snapshot) is not TrustedCrtBitcoinObservationSnapshot:
                _fail()
            snapshot = TrustedCrtBitcoinObservationSnapshot(*(
                getattr(self.snapshot, field)
                for field in TrustedCrtBitcoinObservationSnapshot.__dataclass_fields__
            ))
            if (snapshot.source_plan_manifest_sha256 != self.source_plan_manifest_sha256
                    or snapshot.source_plan.manifest_sha256 != self.source_plan_manifest_sha256):
                _fail()
            object.__setattr__(self, "snapshot", snapshot)


class _PinnedRpc:
    def __init__(self, rpc: object, height: int, best_hash: str):
        self.rpc, self.height, self.best_hash = rpc, height, best_hash

    def getblockcount(self):
        return self.height

    def getbestblockhash(self):
        return self.best_hash

    def gettxout(self, txid, vout, include_mempool):
        return self.rpc.gettxout(txid, vout, include_mempool)


def _height(value: object) -> int:
    if type(value) is not int or value < 0:
        _fail()
    return value


def _hash(value: object) -> str:
    _digest(value)
    return value


class TrustedCrtBitcoinObservationSnapshotAdapter:
    def __init__(self, *, rpc: object, clock: Callable[[], datetime] | None = None):
        if any(not callable(getattr(rpc, name, None)) for name in ("getblockcount", "getbestblockhash", "getblockhash", "gettxout")):
            _fail()
        if clock is not None and not callable(clock):
            _fail()
        self._rpc = rpc
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def observe(self, *, source_plan: TrustedCrtAuthorizationSourcePlan) -> TrustedCrtBitcoinObservationResolution:
        try:
            plan, manifest_digest = _source_plan(source_plan)
            selected: list[tuple[TrustedCrtLineageSource, tuple[TrustedCovenantOutpoint, ...]]] = []
            identities: set[tuple[str, int]] = set()
            for source in plan.lineage_sources:
                if source.observation_required:
                    outpoints = tuple(sorted((_outpoint(x) for x in trusted_outpoints_from_registration(source.registration)),
                                             key=lambda x: (x.txid, x.vout, x.direction.value)))
                    if len(outpoints) != 2:
                        _fail()
                    for item in outpoints:
                        if (item.txid, item.vout) in identities:
                            _fail()
                        identities.add((item.txid, item.vout))
                    selected.append((source, outpoints))
            if not selected:
                return TrustedCrtBitcoinObservationResolution(TrustedCrtBitcoinObservationState.NOT_REQUIRED, manifest_digest, None)
            started = _utc(self._clock())
            height = _height(self._rpc.getblockcount())
            best_hash = _hash(self._rpc.getbestblockhash())
            if _hash(self._rpc.getblockhash(height)) != best_hash:
                _fail()
            observer = TrustedBitcoinCovenantObservationAdapter(_PinnedRpc(self._rpc, height, best_hash), lambda: started)
            relations = []
            for source, outpoints in selected:
                evaluation = _evaluation(observer.observe(outpoints))
                if (evaluation.subject_pubkey != source.registration.subject_xonly_pubkey
                        or evaluation.counterparty_pubkey != source.registration.counterparty_xonly_pubkey
                        or evaluation.observed_at != started or evaluation.observed_block_height != height):
                    _fail()
                relations.append(TrustedCrtObservedLineageRelation(
                    source.depth, source.edge_id, source.edge_sha256, source.registration_id,
                    source.registration_sha256, outpoints, trusted_crt_outpoint_manifest_sha256(outpoints),
                    evaluation, covenant_relation_source_sha256(evaluation),
                ))
            end_height = _height(self._rpc.getblockcount())
            end_hash = _hash(self._rpc.getbestblockhash())
            if _hash(self._rpc.getblockhash(end_height)) != end_hash or end_height != height or end_hash != best_hash:
                _fail()
            completed = _utc(self._clock())
            if completed < started:
                _fail()
            values = dict(
                schema=SCHEMA, adapter_version=ADAPTER_VERSION,
                source_plan_manifest_sha256=manifest_digest,
                source_plan=plan,
                graph_or_protocol_id=plan.graph_or_protocol_id,
                participant_id=plan.participant_id, target_edge_id=plan.target_edge_id,
                source_plan_depth=plan.depth, observed_block_height=height,
                observed_best_block_hash=best_hash, observation_started_at=started,
                observation_completed_at=completed, observed_relations=tuple(relations),
                explicit_non_claims=EXPLICIT_NON_CLAIMS, human_interpretation_required=True,
            )
            digest = sha256(_snapshot_bytes_unchecked(SimpleNamespace(**values))).hexdigest()
            return TrustedCrtBitcoinObservationResolution(
                TrustedCrtBitcoinObservationState.OBSERVED, manifest_digest,
                TrustedCrtBitcoinObservationSnapshot(**values, snapshot_sha256=digest),
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except TrustedCrtBitcoinObservationUnavailable:
            raise
        except Exception:
            raise TrustedCrtBitcoinObservationUnavailable() from None
