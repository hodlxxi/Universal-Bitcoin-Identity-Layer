from hashlib import sha256
from pathlib import Path

import pytest

from app.services.canonical_crt_authorization_proof import (
    MANDATORY_NON_CLAIMS,
    canonical_crt_authorization_proof_bytes,
    parse_canonical_crt_authorization_proof,
)
from app.services.canonical_crt_authorization_proof_publication import (
    MAX_VERIFICATION_BODY_SIZE,
    PUBLICATION_NON_CLAIMS,
    VERIFICATION_RESULT_SCHEMA,
    discovery_document,
    reference_artifact_bytes,
    reference_artifact_catalog,
    verify_submitted_proof,
)


EXPECTED = {
    "depth-3-full":
        "48f1d49935e2f5a580fab0c56d350cba036c859bdb726c38a259ef6011ec0b98",
    "e923-full":
        "1e7508f12641f32e8813ddea1dd4b8bc9f0d5e862512773f36a4f414e7db4945",
    "unknown-ordinary-limited":
        "cf8aff59d98a2c0ec7bf62253fcfb1d0cce264517476ddecb6297153080e401c",
}


def test_three_exact_immutable_reference_artifacts():
    catalog = reference_artifact_catalog()
    assert tuple(item["artifact_id"] for item in catalog) == tuple(EXPECTED)
    for item in catalog:
        artifact_id = item["artifact_id"]
        raw = reference_artifact_bytes(artifact_id)
        parsed = parse_canonical_crt_authorization_proof(raw)
        assert canonical_crt_authorization_proof_bytes(parsed) == raw
        assert parsed.explicit_non_claims == MANDATORY_NON_CLAIMS
        assert sha256(raw).hexdigest() == EXPECTED[artifact_id]
        assert item["proof_sha256"] == EXPECTED[artifact_id]
        assert item["artifact_status"] == "reference_fixture_not_live"
    with pytest.raises(TypeError):
        catalog[0]["artifact_id"] = "changed"


def test_unknown_ids_never_resolve_paths():
    for artifact_id in (
        "E923-full", "../e923-full", "%2e%2e%2fe923-full",
        "/e923-full", "e923-full.json", "e923-full/other",
    ):
        assert reference_artifact_bytes(artifact_id) is None


def test_discovery_is_bounded_and_truthful():
    document = discovery_document()
    assert document["publication_mode"] == "reference_artifacts_only"
    assert document["reference_artifact_count"] == 3
    assert document["maximum_verification_body_size"] == 256 * 1024
    assert document["live_membership_evaluation"] is False
    assert document["live_authorization_evaluation"] is False
    assert document["authenticity_verified_by_sha256"] is False
    assert document["runtime_authorization_granted"] is False
    assert document["human_interpretation_required"] is True
    assert document["explicit_non_claims"] is PUBLICATION_NON_CLAIMS
    assert document["explicit_non_claims"] == PUBLICATION_NON_CLAIMS
    assert len(document["explicit_non_claims"]) == 17


def test_verification_uses_exact_parser_result_and_is_deterministic():
    raw = reference_artifact_bytes("depth-3-full")
    first = dict(verify_submitted_proof(raw))
    second = dict(verify_submitted_proof(raw))
    assert first == second
    assert first["schema"] == VERIFICATION_RESULT_SCHEMA
    assert first["valid"] is True
    assert first["proof_sha256"] == EXPECTED["depth-3-full"]
    assert first["authenticity_verified"] is False
    assert first["currentness_verified"] is False
    assert first["live_evidence_verified"] is False
    assert first["runtime_authorization_granted"] is False
    proof = parse_canonical_crt_authorization_proof(raw)
    assert first["explicit_non_claims"] == proof.explicit_non_claims
    assert first["explicit_non_claims"] == MANDATORY_NON_CLAIMS
    assert MAX_VERIFICATION_BODY_SIZE == 262144


def test_artifact_files_are_only_the_registry_files():
    directory = (
        Path(__file__).parents[2] / "app/public_artifacts"
        / "canonical_crt_authorization_proof/v1"
    )
    assert {path.name for path in directory.iterdir()} == {
        f"{artifact_id}.json" for artifact_id in EXPECTED
    }
