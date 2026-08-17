"""Dormant current CRT authorization-proof explicit-snapshot resolver V1.

"Current" is bounded to the exact immutable evidence snapshot supplied by the
caller and the one canonical ``evaluated_at`` used throughout composition.
This module performs no lookup, publication, authorization, or mutation.
"""

from datetime import datetime, timedelta
import re
import uuid

from app.services.canonical_genesis_record import (
    COMPRESSED_KEY,
    GRAPH_ID,
    PARTICIPANT_ID,
    XONLY_KEY,
    CanonicalGenesisRecord,
    evaluate_canonical_genesis,
)
from app.services.canonical_sponsor_lineage import (
    MAXIMUM_CANONICAL_CHILD_DEPTH,
    CanonicalSponsorLineageEdgeEvidence,
    evaluate_canonical_sponsor_lineage,
)
from app.services.canonical_crt_membership import evaluate_canonical_crt_membership
from app.services.canonical_crt_authorization_policy import (
    evaluate_canonical_crt_authorization,
)
from app.services.canonical_crt_authorization_proof import (
    CanonicalCrtAuthorizationProof,
    build_canonical_crt_authorization_proof,
    canonical_crt_authorization_proof_bytes,
    parse_canonical_crt_authorization_proof,
)

STATUS = (
    "IMPLEMENTED_DORMANT",
    "READ_ONLY_EXPLICIT_SNAPSHOT_COMPOSITION",
    "NOT_DEPLOYED",
    "NOT_LIVE_SOURCE_LOOKUP",
    "NOT_RUNTIME_AUTHORIZATION",
)

EXPLICIT_NON_CLAIMS = (
    "no automatic production database lookup",
    "no automatic admission-registry lookup",
    "no automatic trusted-registration lookup",
    "no automatic Bitcoin RPC observation",
    "no LND call",
    "no external network request",
    "no claim that the supplied evidence is live",
    "no claim that the supplied evidence is complete beyond lower-layer validation",
    "no claim that the proof remains current after evaluated_at",
    "no proof of private-key possession",
    "no signature or issuer attestation",
    "no authenticity claim from SHA-256 alone",
    "no action authorization grant",
    "no scope grant",
    "no session mutation",
    "no user-role mutation",
    "no entitlement write",
    "no administrator or operator status grant",
    "no invite or sponsor permission grant",
    "no automatic mapping to runtime IdentityClass",
    "no action_authorization integration",
    "no replacement of active legacy wallet-ratio authorization",
    "no public HTTP route",
    "no MCP tool",
    "no paid job",
    "no CLI",
    "no scheduler",
    "no deployment or production-enforcement claim",
)

_COMPRESSED_KEY = re.compile(r"(?:02|03)[0-9a-f]{64}\Z")
_X_ONLY_KEY = re.compile(r"[0-9a-f]{64}\Z")


class InvalidCanonicalCrtAuthorizationProofResolution(ValueError):
    """The explicit resolution request shape violates the V1 contract."""


def _canonical_uuid(value: object, name: str) -> None:
    if type(value) is not str:
        raise InvalidCanonicalCrtAuthorizationProofResolution(name)
    try:
        canonical = str(uuid.UUID(value))
    except ValueError:
        raise InvalidCanonicalCrtAuthorizationProofResolution(name) from None
    if value != canonical:
        raise InvalidCanonicalCrtAuthorizationProofResolution(name)


def _validate_request(
    *,
    participant_id: object,
    compressed_public_key: object,
    x_only_public_key: object,
    depth: object,
    evaluated_at: object,
    genesis_records: object,
    target_edge_id: object,
    edge_evidence: object,
) -> bool:
    if (
        type(participant_id) is not str
        or type(compressed_public_key) is not str
        or _COMPRESSED_KEY.fullmatch(compressed_public_key) is None
        or type(x_only_public_key) is not str
        or _X_ONLY_KEY.fullmatch(x_only_public_key) is None
        or compressed_public_key[2:] != x_only_public_key
        or type(depth) is not int
        or type(evaluated_at) is not datetime
        or evaluated_at.tzinfo is None
        or evaluated_at.utcoffset() != timedelta(0)
        or evaluated_at.microsecond
        or type(genesis_records) is not tuple
        or type(edge_evidence) is not tuple
    ):
        raise InvalidCanonicalCrtAuthorizationProofResolution("request primitives")
    if any(type(record) is not CanonicalGenesisRecord for record in genesis_records):
        raise InvalidCanonicalCrtAuthorizationProofResolution("genesis record type")
    if any(type(evidence) is not CanonicalSponsorLineageEdgeEvidence for evidence in edge_evidence):
        raise InvalidCanonicalCrtAuthorizationProofResolution("edge evidence type")

    genesis_mode = participant_id == PARTICIPANT_ID or depth == 0
    if genesis_mode:
        if (
            (participant_id, compressed_public_key, x_only_public_key, depth)
            != (PARTICIPANT_ID, COMPRESSED_KEY, XONLY_KEY, 0)
            or target_edge_id is not None
            or edge_evidence
        ):
            raise InvalidCanonicalCrtAuthorizationProofResolution("genesis request")
        return True

    if (
        depth < 1
        or depth > MAXIMUM_CANONICAL_CHILD_DEPTH
        or participant_id != x_only_public_key
        or target_edge_id is None
    ):
        raise InvalidCanonicalCrtAuthorizationProofResolution("ordinary request")
    _canonical_uuid(target_edge_id, "target edge")
    return False


def resolve_canonical_crt_authorization_proof_from_snapshot(
    *,
    participant_id: str,
    compressed_public_key: str,
    x_only_public_key: str,
    depth: int,
    evaluated_at: datetime,
    genesis_records: tuple[CanonicalGenesisRecord, ...],
    target_edge_id: str | None = None,
    edge_evidence: tuple[CanonicalSponsorLineageEdgeEvidence, ...] = (),
) -> CanonicalCrtAuthorizationProof:
    """Compose and reconstruct one authoritative proof from one snapshot."""
    genesis_mode = _validate_request(
        participant_id=participant_id,
        compressed_public_key=compressed_public_key,
        x_only_public_key=x_only_public_key,
        depth=depth,
        evaluated_at=evaluated_at,
        genesis_records=genesis_records,
        target_edge_id=target_edge_id,
        edge_evidence=edge_evidence,
    )
    genesis = evaluate_canonical_genesis(
        genesis_records,
        graph_or_protocol_id=GRAPH_ID,
        evaluated_at=evaluated_at,
    )
    membership_arguments = {
        "participant_id": participant_id,
        "compressed_public_key": compressed_public_key,
        "x_only_public_key": x_only_public_key,
        "depth": depth,
        "evaluated_at": evaluated_at,
        "target_edge_id": target_edge_id,
    }
    if genesis_mode:
        membership_arguments["genesis_evaluation"] = genesis
    else:
        lineage = evaluate_canonical_sponsor_lineage(
            target_edge_id,
            edge_evidence=edge_evidence,
            genesis_evaluation=genesis,
            evaluated_at=evaluated_at,
        )
        membership_arguments["lineage_evaluation"] = lineage
    membership = evaluate_canonical_crt_membership(**membership_arguments)
    authorization = evaluate_canonical_crt_authorization(membership)
    proof = build_canonical_crt_authorization_proof(authorization)
    return parse_canonical_crt_authorization_proof(canonical_crt_authorization_proof_bytes(proof))
