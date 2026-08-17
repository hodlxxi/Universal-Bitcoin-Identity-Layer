"""Dormant read-only trusted CRT authorization source-plan adapter V1.

The adapter loads canonical stored source records.  It does not observe Bitcoin,
evaluate membership, compose a proof, authorize an action, or persist its plan.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
import re
import uuid
from typing import Protocol

from app.services.canonical_admission_edge import (
    GRAPH_ID,
    HUMAN_PROFILE,
    AdmissionEdgeLifecycle,
    CanonicalAdmissionEdge,
    SponsorBasisKind,
    canonical_admission_edge_bytes,
    canonical_admission_edge_sha256,
    parse_canonical_admission_edge,
)
from app.services.canonical_genesis_record import (
    COMPRESSED_KEY,
    PARTICIPANT_ID,
    XONLY_KEY,
    CanonicalGenesisRecord,
    canonical_genesis_record_bytes,
    canonical_genesis_record_sha256,
    parse_canonical_genesis_record,
)
from app.services.trusted_covenant_registration import (
    TrustedCovenantRegistration,
    TrustedCovenantRegistrationLifecycle,
    canonical_trusted_registration_bytes,
    trusted_outpoints_from_registration,
    trusted_registration_sha256,
)

SCHEMA = "hodlxxi.trusted_crt_authorization_source_plan.v1"
ADAPTER_VERSION = "hodlxxi.trusted_crt_authorization_source_plan_adapter.v1"
MAXIMUM_CANONICAL_CHILD_DEPTH = 2288
STATUS = (
    "IMPLEMENTED_DORMANT",
    "READ_ONLY_INJECTED_SOURCE_LOOKUP",
    "SOURCE_PLAN_ONLY",
    "NOT_BITCOIN_OBSERVED",
    "NOT_PROOF_GENERATION",
    "NOT_PRODUCTION_DB_WIRING",
    "NOT_RUNTIME_AUTHORIZATION",
    "NOT_DEPLOYED",
)
EXPLICIT_NON_CLAIMS = (
    "no Bitcoin RPC observation",
    "no claim of one global Bitcoin block snapshot",
    "no best-block-hash binding",
    "no current UTXO claim",
    "no proof generation",
    "no PR6.16 invocation",
    "no membership evaluation",
    "no FULL/LIMITED authorization decision",
    "no entitlement evidence write",
    "no current-entitlement integration",
    "no action-authorization integration",
    "no session mutation",
    "no role mutation",
    "no scope grant",
    "no administrator or operator grant",
    "no invite or sponsor permission",
    "no target-edge inference",
    "no participant-facing lookup",
    "no production database singleton",
    "no database write",
    "no migration application",
    "no HTTP route",
    "no MCP tool",
    "no paid job",
    "no CLI",
    "no scheduler",
    "no signing or issuer attestation",
    "no proof of private-key possession",
    "no authenticity claim from SHA-256 alone",
    "no replacement of legacy wallet-ratio authorization",
    "no deployment or production-enforcement claim",
)

_X_ONLY = re.compile(r"[0-9a-f]{64}\Z")
_DIGEST = _X_ONLY
_COMPRESSED = re.compile(r"(?:02|03)[0-9a-f]{64}\Z")


class InvalidTrustedCrtAuthorizationSourceRequest(ValueError):
    """The caller request is not one of the two exact V1 request shapes."""


class TrustedCrtAuthorizationSourceUnavailable(RuntimeError):
    """A required trusted source snapshot is unavailable or contradictory."""

    def __init__(self):
        super().__init__("trusted CRT authorization source unavailable")


class TrustedCrtSourceResolutionState(Enum):
    READY = "ready"
    NOT_FOUND = "not_found"


class TrustedCrtSubjectKind(Enum):
    GENESIS = "genesis"
    ORDINARY = "ordinary"


class CanonicalGenesisRepository(Protocol):
    def list_for_graph(self, graph_or_protocol_id: str) -> tuple[CanonicalGenesisRecord, ...]: ...


class CanonicalAdmissionEdgeRepository(Protocol):
    def get(self, edge_id: str) -> CanonicalAdmissionEdge | None: ...


class TrustedRegistrationRepository(Protocol):
    def get(self, registration_id: str) -> TrustedCovenantRegistration | None: ...


@dataclass(frozen=True, slots=True)
class TrustedCrtLineageSource:
    depth: int
    edge_id: str
    edge_sha256: str
    registration_id: str
    registration_sha256: str
    observation_required: bool
    edge: CanonicalAdmissionEdge
    registration: TrustedCovenantRegistration

    def __post_init__(self):
        if (
            type(self) is not TrustedCrtLineageSource
            or type(self.depth) is not int
            or not 1 <= self.depth <= MAXIMUM_CANONICAL_CHILD_DEPTH
            or type(self.edge_id) is not str
            or type(self.registration_id) is not str
            or type(self.edge_sha256) is not str
            or _DIGEST.fullmatch(self.edge_sha256) is None
            or type(self.registration_sha256) is not str
            or _DIGEST.fullmatch(self.registration_sha256) is None
            or type(self.observation_required) is not bool
            or type(self.edge) is not CanonicalAdmissionEdge
            or type(self.registration) is not TrustedCovenantRegistration
        ):
            raise TrustedCrtAuthorizationSourceUnavailable()
        try:
            edge_digest = canonical_admission_edge_sha256(self.edge)
            registration_digest = trusted_registration_sha256(self.registration)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise TrustedCrtAuthorizationSourceUnavailable() from None
        if (
            self.depth != self.edge.child_depth
            or self.edge_id != self.edge.edge_id
            or self.edge_sha256 != edge_digest
            or self.registration_id != self.registration.registration_id
            or self.registration_sha256 != registration_digest
            or self.edge.trusted_registration_id != self.registration_id
            or self.edge.trusted_registration_sha256 != self.registration_sha256
        ):
            raise TrustedCrtAuthorizationSourceUnavailable()
        expected_observation = (
            self.edge.lifecycle_state is AdmissionEdgeLifecycle.EFFECTIVE
            and self.registration.lifecycle_state is TrustedCovenantRegistrationLifecycle.ACTIVE
        )
        if self.observation_required is not expected_observation:
            raise TrustedCrtAuthorizationSourceUnavailable()


@dataclass(frozen=True, slots=True)
class TrustedCrtAuthorizationSourcePlan:
    schema: str
    adapter_version: str
    graph_or_protocol_id: str
    subject_kind: TrustedCrtSubjectKind
    participant_id: str
    compressed_public_key: str
    x_only_public_key: str
    depth: int
    target_edge_id: str | None
    target_edge_sha256: str | None
    genesis_records: tuple[CanonicalGenesisRecord, ...]
    lineage_sources: tuple[TrustedCrtLineageSource, ...]
    relevant_records: tuple[tuple[str, str], ...]
    manifest_sha256: str
    explicit_non_claims: tuple[str, ...]
    human_interpretation_required: bool

    def __post_init__(self):
        try:
            if (
                type(self) is not TrustedCrtAuthorizationSourcePlan
                or self.schema != SCHEMA
                or self.adapter_version != ADAPTER_VERSION
                or self.graph_or_protocol_id != GRAPH_ID
                or type(self.subject_kind) is not TrustedCrtSubjectKind
                or type(self.participant_id) is not str
                or type(self.compressed_public_key) is not str
                or _COMPRESSED.fullmatch(self.compressed_public_key) is None
                or type(self.x_only_public_key) is not str
                or _X_ONLY.fullmatch(self.x_only_public_key) is None
                or self.compressed_public_key[2:] != self.x_only_public_key
                or type(self.depth) is not int
                or type(self.genesis_records) is not tuple
                or type(self.lineage_sources) is not tuple
                or type(self.relevant_records) is not tuple
                or type(self.manifest_sha256) is not str
                or _DIGEST.fullmatch(self.manifest_sha256) is None
                or self.explicit_non_claims != EXPLICIT_NON_CLAIMS
                or self.human_interpretation_required is not True
            ):
                raise TrustedCrtAuthorizationSourceUnavailable()

            genesis_rows = []
            for record in self.genesis_records:
                if type(record) is not CanonicalGenesisRecord:
                    raise TrustedCrtAuthorizationSourceUnavailable()
                encoded = canonical_genesis_record_bytes(record)
                genesis_rows.append((record.record_id, canonical_genesis_record_sha256(record), encoded))
            if (
                genesis_rows != sorted(genesis_rows, key=lambda item: (item[0], item[1]))
                or len({item[0] for item in genesis_rows}) != len(genesis_rows)
                or len({item[1] for item in genesis_rows}) != len(genesis_rows)
            ):
                raise TrustedCrtAuthorizationSourceUnavailable()

            validated_sources = []
            for source in self.lineage_sources:
                if type(source) is not TrustedCrtLineageSource:
                    raise TrustedCrtAuthorizationSourceUnavailable()
                validated_sources.append(
                    TrustedCrtLineageSource(
                        *(getattr(source, field) for field in TrustedCrtLineageSource.__dataclass_fields__)
                    )
                )
            sources = tuple(validated_sources)
            if sources:
                if tuple(source.depth for source in sources) != tuple(range(1, self.depth + 1)):
                    raise TrustedCrtAuthorizationSourceUnavailable()
                if (
                    len({source.edge_id for source in sources}) != len(sources)
                    or len({source.edge_sha256 for source in sources}) != len(sources)
                    or len({source.edge.child_participant_id for source in sources}) != len(sources)
                ):
                    raise TrustedCrtAuthorizationSourceUnavailable()
                for parent, child in zip(sources, sources[1:]):
                    if (
                        child.edge.sponsor_basis_kind is not SponsorBasisKind.CANONICAL_ADMISSION_EDGE
                        or child.edge.sponsor_basis_record_id != parent.edge_id
                        or child.edge.sponsor_basis_record_sha256 != parent.edge_sha256
                        or child.edge.sponsor_depth != parent.edge.child_depth
                        or child.edge.sponsor_participant_id != parent.edge.child_participant_id
                        or child.edge.sponsor_compressed_public_key != parent.edge.child_compressed_public_key
                        or child.edge.sponsor_x_only_public_key != parent.edge.child_x_only_public_key
                        or child.edge.graph_or_protocol_id != parent.edge.graph_or_protocol_id
                        or child.edge.human_profile != parent.edge.human_profile
                    ):
                        raise TrustedCrtAuthorizationSourceUnavailable()
                root = sources[0].edge
                genesis_pairs = {(item[0], item[1]) for item in genesis_rows}
                if (
                    root.sponsor_basis_kind is not SponsorBasisKind.CANONICAL_GENESIS_RECORD
                    or (root.sponsor_basis_record_id, root.sponsor_basis_record_sha256) not in genesis_pairs
                ):
                    raise TrustedCrtAuthorizationSourceUnavailable()

            if self.subject_kind is TrustedCrtSubjectKind.GENESIS:
                if (
                    (self.participant_id, self.compressed_public_key, self.x_only_public_key, self.depth)
                    != (PARTICIPANT_ID, COMPRESSED_KEY, XONLY_KEY, 0)
                    or self.target_edge_id is not None
                    or self.target_edge_sha256 is not None
                    or sources
                ):
                    raise TrustedCrtAuthorizationSourceUnavailable()
            else:
                if (
                    self.participant_id != self.x_only_public_key
                    or not 1 <= self.depth <= MAXIMUM_CANONICAL_CHILD_DEPTH
                    or not sources
                ):
                    raise TrustedCrtAuthorizationSourceUnavailable()
                _canonical_source_uuid(self.target_edge_id)
                terminal = sources[-1]
                if (
                    self.participant_id != terminal.edge.child_participant_id
                    or self.compressed_public_key != terminal.edge.child_compressed_public_key
                    or self.x_only_public_key != terminal.edge.child_x_only_public_key
                    or self.depth != terminal.edge.child_depth
                    or self.target_edge_id != terminal.edge_id
                    or self.target_edge_sha256 != terminal.edge_sha256
                    or self.target_edge_sha256 != canonical_admission_edge_sha256(terminal.edge)
                ):
                    raise TrustedCrtAuthorizationSourceUnavailable()

            if any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or type(item[1]) is not str
                or _DIGEST.fullmatch(item[1]) is None
                for item in self.relevant_records
            ):
                raise TrustedCrtAuthorizationSourceUnavailable()
            expected_relevant = tuple(
                sorted(
                    [(item[0], item[1]) for item in genesis_rows]
                    + [(source.edge_id, source.edge_sha256) for source in sources]
                    + [(source.registration_id, source.registration_sha256) for source in sources]
                )
            )
            identifiers = [item[0] for item in expected_relevant]
            if len(set(identifiers)) != len(identifiers):
                raise TrustedCrtAuthorizationSourceUnavailable()
            if self.relevant_records != expected_relevant:
                raise TrustedCrtAuthorizationSourceUnavailable()
            if self.manifest_sha256 != _manifest_sha256_unchecked(self):
                raise TrustedCrtAuthorizationSourceUnavailable()
        except (KeyboardInterrupt, SystemExit):
            raise
        except TrustedCrtAuthorizationSourceUnavailable:
            raise
        except Exception:
            raise TrustedCrtAuthorizationSourceUnavailable() from None


@dataclass(frozen=True, slots=True)
class TrustedCrtAuthorizationSourceResolution:
    state: TrustedCrtSourceResolutionState
    participant_id: str
    target_edge_id: str | None
    plan: TrustedCrtAuthorizationSourcePlan | None

    def __post_init__(self):
        if (
            type(self) is not TrustedCrtAuthorizationSourceResolution
            or type(self.state) is not TrustedCrtSourceResolutionState
        ):
            raise TrustedCrtAuthorizationSourceUnavailable()
        if self.state is TrustedCrtSourceResolutionState.READY:
            if (
                type(self.plan) is not TrustedCrtAuthorizationSourcePlan
                or self.participant_id != self.plan.participant_id
                or self.target_edge_id != self.plan.target_edge_id
            ):
                raise TrustedCrtAuthorizationSourceUnavailable()
            TrustedCrtAuthorizationSourcePlan(
                *(getattr(self.plan, field) for field in TrustedCrtAuthorizationSourcePlan.__dataclass_fields__)
            )
            if self.plan.subject_kind is TrustedCrtSubjectKind.ORDINARY:
                _canonical_source_uuid(self.target_edge_id)
            elif self.target_edge_id is not None:
                raise TrustedCrtAuthorizationSourceUnavailable()
        elif (
            self.plan is not None
            or type(self.participant_id) is not str
            or _X_ONLY.fullmatch(self.participant_id) is None
        ):
            raise TrustedCrtAuthorizationSourceUnavailable()
        else:
            _canonical_source_uuid(self.target_edge_id)


def _manifest_payload(plan) -> dict:
    return {
        "adapter_version": plan.adapter_version,
        "compressed_public_key": plan.compressed_public_key,
        "depth": plan.depth,
        "explicit_non_claims": list(plan.explicit_non_claims),
        "genesis_records": [
            [record.record_id, canonical_genesis_record_sha256(record)] for record in plan.genesis_records
        ],
        "graph_or_protocol_id": plan.graph_or_protocol_id,
        "human_interpretation_required": plan.human_interpretation_required,
        "lineage_sources": [
            {
                "depth": source.depth,
                "edge_id": source.edge_id,
                "edge_sha256": source.edge_sha256,
                "observation_required": source.observation_required,
                "registration_id": source.registration_id,
                "registration_sha256": source.registration_sha256,
            }
            for source in plan.lineage_sources
        ],
        "participant_id": plan.participant_id,
        "relevant_records": [list(item) for item in plan.relevant_records],
        "schema": plan.schema,
        "subject_kind": plan.subject_kind.value,
        "target_edge_id": plan.target_edge_id,
        "target_edge_sha256": plan.target_edge_sha256,
        "x_only_public_key": plan.x_only_public_key,
    }


def _manifest_bytes_unchecked(plan) -> bytes:
    return json.dumps(
        _manifest_payload(plan),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _manifest_sha256_unchecked(plan) -> str:
    return sha256(_manifest_bytes_unchecked(plan)).hexdigest()


def trusted_crt_authorization_source_plan_manifest_bytes(
    plan: TrustedCrtAuthorizationSourcePlan,
) -> bytes:
    """Return canonical ASCII JSON binding every selected source digest."""
    if type(plan) is not TrustedCrtAuthorizationSourcePlan:
        raise InvalidTrustedCrtAuthorizationSourceRequest("plan type")
    try:
        validated = TrustedCrtAuthorizationSourcePlan(
            *(getattr(plan, field) for field in TrustedCrtAuthorizationSourcePlan.__dataclass_fields__)
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise TrustedCrtAuthorizationSourceUnavailable() from None
    return _manifest_bytes_unchecked(validated)


def trusted_crt_authorization_source_plan_manifest_sha256(
    plan: TrustedCrtAuthorizationSourcePlan,
) -> str:
    return sha256(trusted_crt_authorization_source_plan_manifest_bytes(plan)).hexdigest()


def _uuid(value: object) -> str:
    if type(value) is not str:
        raise InvalidTrustedCrtAuthorizationSourceRequest("target_edge_id")
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise InvalidTrustedCrtAuthorizationSourceRequest("target_edge_id") from None
    if value != canonical:
        raise InvalidTrustedCrtAuthorizationSourceRequest("target_edge_id")
    return value


def _canonical_source_uuid(value: object) -> str:
    if type(value) is not str:
        raise TrustedCrtAuthorizationSourceUnavailable()
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise TrustedCrtAuthorizationSourceUnavailable() from None
    if value != canonical:
        raise TrustedCrtAuthorizationSourceUnavailable()
    return value


def _edge_bytes(value: object) -> bytes:
    if type(value) is not CanonicalAdmissionEdge:
        raise TrustedCrtAuthorizationSourceUnavailable()
    try:
        return canonical_admission_edge_bytes(value)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise TrustedCrtAuthorizationSourceUnavailable() from None


def _detached_registration(
    value: object,
) -> tuple[TrustedCovenantRegistration, bytes]:
    if type(value) is not TrustedCovenantRegistration:
        raise TrustedCrtAuthorizationSourceUnavailable()
    try:
        detached = TrustedCovenantRegistration(
            *(deepcopy(getattr(value, field)) for field in TrustedCovenantRegistration.__dataclass_fields__)
        )
        encoded = canonical_trusted_registration_bytes(detached)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise TrustedCrtAuthorizationSourceUnavailable() from None
    return detached, encoded


class TrustedCrtAuthorizationSourcePlanAdapter:
    """Resolve exact injected trusted records into an immutable source plan."""

    def __init__(
        self,
        *,
        genesis_repository: CanonicalGenesisRepository,
        admission_edge_repository: CanonicalAdmissionEdgeRepository,
        trusted_registration_repository: TrustedRegistrationRepository,
    ):
        self._genesis_repository = genesis_repository
        self._admission_edge_repository = admission_edge_repository
        self._trusted_registration_repository = trusted_registration_repository

    def _genesis(self) -> tuple[tuple[CanonicalGenesisRecord, ...], tuple[bytes, ...]]:
        def read():
            try:
                values = self._genesis_repository.list_for_graph(GRAPH_ID)
                if type(values) is not tuple:
                    raise TrustedCrtAuthorizationSourceUnavailable()
                rows = []
                for value in values:
                    if type(value) is not CanonicalGenesisRecord:
                        raise TrustedCrtAuthorizationSourceUnavailable()
                    encoded = canonical_genesis_record_bytes(value)
                    detached = parse_canonical_genesis_record(encoded)
                    rows.append((detached.record_id, canonical_genesis_record_sha256(detached), encoded, detached))
                rows.sort(key=lambda item: (item[0], item[1]))
                if len({x[0] for x in rows}) != len(rows) or len({x[1] for x in rows}) != len(rows):
                    raise TrustedCrtAuthorizationSourceUnavailable()
                return tuple(rows)
            except (KeyboardInterrupt, SystemExit):
                raise
            except TrustedCrtAuthorizationSourceUnavailable:
                raise
            except Exception:
                raise TrustedCrtAuthorizationSourceUnavailable() from None

        first, second = read(), read()
        if tuple(x[2] for x in first) != tuple(x[2] for x in second):
            raise TrustedCrtAuthorizationSourceUnavailable()
        return tuple(x[3] for x in second), tuple(x[2] for x in first)

    def _edge(self, edge_id: str, *, absent_ok: bool = False):
        try:
            first = self._admission_edge_repository.get(edge_id)
            first_bytes = None if first is None else _edge_bytes(first)
            first_detached = None if first_bytes is None else parse_canonical_admission_edge(first_bytes)
            second = self._admission_edge_repository.get(edge_id)
            second_bytes = None if second is None else _edge_bytes(second)
            second_detached = None if second_bytes is None else parse_canonical_admission_edge(second_bytes)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise TrustedCrtAuthorizationSourceUnavailable() from None
        if first_bytes is None and second_bytes is None and absent_ok:
            return None, None
        if first_bytes is None or second_bytes is None or first_bytes != second_bytes:
            raise TrustedCrtAuthorizationSourceUnavailable()
        if first_detached is None or second_detached is None or second_detached.edge_id != edge_id:
            raise TrustedCrtAuthorizationSourceUnavailable()
        return second_detached, first_bytes

    def _registration(
        self,
        registration_id: str,
    ) -> tuple[TrustedCovenantRegistration, bytes]:
        try:
            first = self._trusted_registration_repository.get(registration_id)
            if first is None:
                raise TrustedCrtAuthorizationSourceUnavailable()
            first_detached, first_bytes = _detached_registration(first)
            second = self._trusted_registration_repository.get(registration_id)
            if second is None:
                raise TrustedCrtAuthorizationSourceUnavailable()
            second_detached, second_bytes = _detached_registration(second)
            if first_bytes != second_bytes:
                raise TrustedCrtAuthorizationSourceUnavailable()
            if second_detached.registration_id != registration_id:
                raise TrustedCrtAuthorizationSourceUnavailable()
            return second_detached, first_bytes
        except (KeyboardInterrupt, SystemExit):
            raise
        except TrustedCrtAuthorizationSourceUnavailable:
            raise
        except Exception:
            raise TrustedCrtAuthorizationSourceUnavailable() from None

    def _finish(self, **values) -> TrustedCrtAuthorizationSourcePlan:
        payload_source = type("_ManifestSource", (), values)()
        return TrustedCrtAuthorizationSourcePlan(**values, manifest_sha256=_manifest_sha256_unchecked(payload_source))

    def resolve(
        self,
        *,
        participant_id: str,
        target_edge_id: str | None = None,
    ) -> TrustedCrtAuthorizationSourceResolution:
        if type(participant_id) is not str:
            raise InvalidTrustedCrtAuthorizationSourceRequest("participant_id")
        genesis_mode = participant_id == PARTICIPANT_ID and target_edge_id is None
        if not genesis_mode:
            if _X_ONLY.fullmatch(participant_id) is None or target_edge_id is None:
                raise InvalidTrustedCrtAuthorizationSourceRequest("request shape")
            _uuid(target_edge_id)
        genesis, genesis_bytes = self._genesis()
        if genesis_mode:
            plan = self._finish(
                schema=SCHEMA,
                adapter_version=ADAPTER_VERSION,
                graph_or_protocol_id=GRAPH_ID,
                subject_kind=TrustedCrtSubjectKind.GENESIS,
                participant_id=PARTICIPANT_ID,
                compressed_public_key=COMPRESSED_KEY,
                x_only_public_key=XONLY_KEY,
                depth=0,
                target_edge_id=None,
                target_edge_sha256=None,
                genesis_records=genesis,
                lineage_sources=(),
                relevant_records=tuple(sorted((x.record_id, canonical_genesis_record_sha256(x)) for x in genesis)),
                explicit_non_claims=EXPLICIT_NON_CLAIMS,
                human_interpretation_required=True,
            )
            if self._genesis()[1] != genesis_bytes:
                raise TrustedCrtAuthorizationSourceUnavailable()
            return TrustedCrtAuthorizationSourceResolution(
                TrustedCrtSourceResolutionState.READY, participant_id, None, plan
            )

        target, target_bytes = self._edge(target_edge_id, absent_ok=True)
        if target is None:
            if self._genesis()[1] != genesis_bytes:
                raise TrustedCrtAuthorizationSourceUnavailable()
            return TrustedCrtAuthorizationSourceResolution(
                TrustedCrtSourceResolutionState.NOT_FOUND, participant_id, target_edge_id, None
            )
        if target.child_participant_id != participant_id or target.child_x_only_public_key != participant_id:
            raise TrustedCrtAuthorizationSourceUnavailable()
        if not 1 <= target.child_depth <= MAXIMUM_CANONICAL_CHILD_DEPTH:
            raise TrustedCrtAuthorizationSourceUnavailable()

        reverse = []
        current = target
        seen_ids, seen_digests, seen_children = set(), set(), set()
        while True:
            digest = canonical_admission_edge_sha256(current)
            if current.edge_id in seen_ids or digest in seen_digests or current.child_participant_id in seen_children:
                raise TrustedCrtAuthorizationSourceUnavailable()
            seen_ids.add(current.edge_id)
            seen_digests.add(digest)
            seen_children.add(current.child_participant_id)
            reverse.append(current)
            if current.child_depth == 1:
                if current.sponsor_basis_kind is not SponsorBasisKind.CANONICAL_GENESIS_RECORD:
                    raise TrustedCrtAuthorizationSourceUnavailable()
                break
            parent, _ = self._edge(current.sponsor_basis_record_id)
            if (
                current.sponsor_basis_kind is not SponsorBasisKind.CANONICAL_ADMISSION_EDGE
                or current.sponsor_basis_record_sha256 != canonical_admission_edge_sha256(parent)
                or parent.child_depth + 1 != current.child_depth
                or parent.child_participant_id != current.sponsor_participant_id
                or parent.child_compressed_public_key != current.sponsor_compressed_public_key
                or parent.child_x_only_public_key != current.sponsor_x_only_public_key
                or parent.graph_or_protocol_id != current.graph_or_protocol_id
                or parent.human_profile != current.human_profile
                or parent.graph_or_protocol_id != GRAPH_ID
                or parent.human_profile != HUMAN_PROFILE
            ):
                raise TrustedCrtAuthorizationSourceUnavailable()
            current = parent
        edges = tuple(reversed(reverse))
        genesis_pairs = {(x.record_id, canonical_genesis_record_sha256(x)) for x in genesis}
        root = edges[0]
        if (root.sponsor_basis_record_id, root.sponsor_basis_record_sha256) not in genesis_pairs:
            raise TrustedCrtAuthorizationSourceUnavailable()

        sources = []
        source_registration_bytes = []
        for edge in edges:
            registration, registration_bytes = self._registration(edge.trusted_registration_id)
            registration_digest = trusted_registration_sha256(registration)
            if registration_digest != edge.trusted_registration_sha256:
                raise TrustedCrtAuthorizationSourceUnavailable()
            required = (
                edge.lifecycle_state is AdmissionEdgeLifecycle.EFFECTIVE
                and registration.lifecycle_state is TrustedCovenantRegistrationLifecycle.ACTIVE
            )
            if required:
                try:
                    outpoints = trusted_outpoints_from_registration(registration)
                    if type(outpoints) is not tuple or len(outpoints) != 2:
                        raise TrustedCrtAuthorizationSourceUnavailable()
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception:
                    raise TrustedCrtAuthorizationSourceUnavailable() from None
            sources.append(
                TrustedCrtLineageSource(
                    edge.child_depth,
                    edge.edge_id,
                    canonical_admission_edge_sha256(edge),
                    registration.registration_id,
                    registration_digest,
                    required,
                    edge,
                    registration,
                )
            )
            source_registration_bytes.append(registration_bytes)

        if self._edge(target_edge_id)[1] != target_bytes:
            raise TrustedCrtAuthorizationSourceUnavailable()
        if self._genesis()[1] != genesis_bytes:
            raise TrustedCrtAuthorizationSourceUnavailable()
        for source, original_bytes in zip(sources, source_registration_bytes):
            if self._registration(source.registration_id)[1] != original_bytes:
                raise TrustedCrtAuthorizationSourceUnavailable()

        relevant = tuple(
            sorted(
                list(genesis_pairs)
                + [(x.edge_id, x.edge_sha256) for x in sources]
                + [(x.registration_id, x.registration_sha256) for x in sources]
            )
        )
        plan = self._finish(
            schema=SCHEMA,
            adapter_version=ADAPTER_VERSION,
            graph_or_protocol_id=GRAPH_ID,
            subject_kind=TrustedCrtSubjectKind.ORDINARY,
            participant_id=target.child_participant_id,
            compressed_public_key=target.child_compressed_public_key,
            x_only_public_key=target.child_x_only_public_key,
            depth=target.child_depth,
            target_edge_id=target.edge_id,
            target_edge_sha256=canonical_admission_edge_sha256(target),
            genesis_records=genesis,
            lineage_sources=tuple(sources),
            relevant_records=relevant,
            explicit_non_claims=EXPLICIT_NON_CLAIMS,
            human_interpretation_required=True,
        )
        return TrustedCrtAuthorizationSourceResolution(
            TrustedCrtSourceResolutionState.READY, participant_id, target_edge_id, plan
        )
