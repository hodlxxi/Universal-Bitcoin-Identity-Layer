"""Pure read-only publication of canonical CRT authorization proof fixtures."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from types import MappingProxyType

from app.services.canonical_crt_authorization_proof import (
    CanonicalCrtAuthorizationProof,
    InvalidCanonicalCrtAuthorizationProof,
    SCHEMA,
    VERIFICATION_RULE,
    canonical_crt_authorization_proof_bytes,
    canonical_crt_authorization_proof_sha256,
    parse_canonical_crt_authorization_proof,
)

PUBLICATION_SCHEMA = (
    "hodlxxi.canonical_crt_authorization_proof_publication.v1"
)
VERIFICATION_RESULT_SCHEMA = (
    "hodlxxi.canonical_crt_authorization_proof_verification_result.v1"
)
MAX_VERIFICATION_BODY_SIZE = 256 * 1024
ARTIFACT_STATUS = "reference_fixture_not_live"
PUBLICATION_NON_CLAIMS = (
    "no live Bitcoin evidence lookup",
    "no live admission registry lookup",
    "no automatic sponsor-lineage lookup",
    "no automatic membership evaluation",
    "no automatic authorization evaluation",
    "no action authorization grant",
    "no session or role mutation",
    "no entitlement write",
    "no administrator or operator status grant",
    "no invite or sponsor permission grant",
    "no proof of private-key possession",
    "no signature or issuer-attestation claim",
    "no authenticity claim from SHA-256 alone",
    "no claim that evidence remains current after evaluated_at",
    "no replacement of active legacy authorization",
    "no MCP publication in PR6.15",
    "no production deployment claim",
)

_ARTIFACT_DIRECTORY = (
    Path(__file__).resolve().parents[1]
    / "public_artifacts"
    / "canonical_crt_authorization_proof"
    / "v1"
)
_PINNED_DIGESTS = MappingProxyType({
    "depth-3-full":
        "48f1d49935e2f5a580fab0c56d350cba036c859bdb726c38a259ef6011ec0b98",
    "e923-full":
        "1e7508f12641f32e8813ddea1dd4b8bc9f0d5e862512773f36a4f414e7db4945",
    "unknown-ordinary-limited":
        "cf8aff59d98a2c0ec7bf62253fcfb1d0cce264517476ddecb6297153080e401c",
})


def _load_reference_artifacts():
    loaded = {}
    for artifact_id, pinned_digest in _PINNED_DIGESTS.items():
        path = _ARTIFACT_DIRECTORY / f"{artifact_id}.json"
        raw = path.read_bytes()
        proof = parse_canonical_crt_authorization_proof(raw)
        if canonical_crt_authorization_proof_bytes(proof) != raw:
            raise RuntimeError(f"noncanonical reference artifact: {artifact_id}")
        if canonical_crt_authorization_proof_sha256(proof) != pinned_digest:
            raise RuntimeError(f"canonical digest mismatch: {artifact_id}")
        if sha256(raw).hexdigest() != pinned_digest:
            raise RuntimeError(f"file digest mismatch: {artifact_id}")
        loaded[artifact_id] = (raw, proof)
    return MappingProxyType(loaded)


_REFERENCE_ARTIFACTS = _load_reference_artifacts()


def _proof_metadata(
    artifact_id: str,
    digest: str,
    proof: CanonicalCrtAuthorizationProof,
) -> MappingProxyType:
    return MappingProxyType({
        "artifact_id": artifact_id,
        "proof_sha256": digest,
        "proof_schema": proof.schema,
        "verification_rule": proof.verification_rule,
        "subject_kind": proof.subject_kind.value,
        "participant_id": proof.participant_id,
        "depth": proof.depth,
        "authorization_class": proof.authorization_class.value,
        "authorization_reason_code": proof.authorization_reason_code.value,
        "membership_state": proof.membership_state.value,
        "membership_reason_code": proof.membership_reason_code.value,
        "proof_conclusion": proof.proof_conclusion.value,
        "proof_basis": proof.proof_basis.value,
        "evaluated_at": proof.evaluated_at.isoformat().replace("+00:00", "Z"),
        "artifact_status": ARTIFACT_STATUS,
        "download_path": (
            f"/agent/crt/authorization-proofs/{artifact_id}.json"
        ),
    })


_CATALOG = tuple(
    _proof_metadata(artifact_id, _PINNED_DIGESTS[artifact_id], proof)
    for artifact_id, (_, proof) in _REFERENCE_ARTIFACTS.items()
)


def reference_artifact_catalog() -> tuple[MappingProxyType, ...]:
    """Return immutable, deterministic metadata for the three fixtures."""
    return _CATALOG


def reference_artifact_bytes(artifact_id: str) -> bytes | None:
    """Return exact checked-in bytes, without interpreting caller paths."""
    item = _REFERENCE_ARTIFACTS.get(artifact_id)
    return None if item is None else item[0]


def reference_artifact_digest(artifact_id: str) -> str | None:
    return _PINNED_DIGESTS.get(artifact_id)


def verify_submitted_proof(raw: bytes) -> MappingProxyType:
    """Validate exact caller bytes solely through the PR6.14 authority."""
    try:
        proof = parse_canonical_crt_authorization_proof(raw)
    except InvalidCanonicalCrtAuthorizationProof:
        raise
    digest = canonical_crt_authorization_proof_sha256(proof)
    return MappingProxyType({
        "schema": VERIFICATION_RESULT_SCHEMA,
        "valid": True,
        "proof_sha256": digest,
        "proof_schema": proof.schema,
        "verification_rule": proof.verification_rule,
        "participant_id": proof.participant_id,
        "subject_kind": proof.subject_kind.value,
        "depth": proof.depth,
        "authorization_class": proof.authorization_class.value,
        "authorization_reason_code": proof.authorization_reason_code.value,
        "membership_state": proof.membership_state.value,
        "membership_reason_code": proof.membership_reason_code.value,
        "proof_conclusion": proof.proof_conclusion.value,
        "proof_basis": proof.proof_basis.value,
        "evaluated_at": proof.evaluated_at.isoformat().replace("+00:00", "Z"),
        "source_authorization_evaluation_sha256":
            proof.source_authorization_evaluation_sha256,
        "source_membership_evaluation_sha256":
            proof.source_membership_evaluation_sha256,
        "explicit_non_claims": proof.explicit_non_claims,
        "human_interpretation_required": True,
        "authenticity_verified": False,
        "currentness_verified": False,
        "live_evidence_verified": False,
        "runtime_authorization_granted": False,
    })


def discovery_document() -> MappingProxyType:
    return MappingProxyType({
        "schema": PUBLICATION_SCHEMA,
        "canonical_proof_schema": SCHEMA,
        "canonical_verification_rule": VERIFICATION_RULE,
        "verification_result_schema": VERIFICATION_RESULT_SCHEMA,
        "publication_mode": "reference_artifacts_only",
        "reference_artifact_count": len(_CATALOG),
        "catalog_endpoint": "/agent/crt/authorization-proofs",
        "artifact_endpoint_template":
            "/agent/crt/authorization-proofs/<artifact_id>.json",
        "verification_endpoint": "/agent/crt/authorization-proofs/verify",
        "maximum_verification_body_size": MAX_VERIFICATION_BODY_SIZE,
        "live_membership_evaluation": False,
        "live_authorization_evaluation": False,
        "authenticity_verified_by_sha256": False,
        "runtime_authorization_granted": False,
        "human_interpretation_required": True,
        "signed_or_issuer_attested": False,
        "reference_artifacts_are_live_state": False,
        "explicit_non_claims": PUBLICATION_NON_CLAIMS,
        "description":
            "Read-only deterministic reference artifacts; not live membership "
            "state or current participant authorization.",
    })
