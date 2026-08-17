from hashlib import sha256
import json

import pytest

from app.services.canonical_crt_authorization_proof import (
    MANDATORY_NON_CLAIMS,
    parse_canonical_crt_authorization_proof,
)
from app.services.canonical_crt_authorization_proof_publication import (
    MAX_VERIFICATION_BODY_SIZE,
    PUBLICATION_NON_CLAIMS,
    VERIFICATION_RESULT_SCHEMA,
    reference_artifact_bytes,
)

IDS = ("depth-3-full", "e923-full", "unknown-ordinary-limited")


def test_discovery_catalog_and_agent_discovery(client):
    discovery = client.get("/.well-known/crt-authorization-proof.json")
    assert discovery.status_code == 200
    assert discovery.get_json()["publication_mode"] == "reference_artifacts_only"
    assert discovery.get_json()["explicit_non_claims"] == list(PUBLICATION_NON_CLAIMS)
    assert len(discovery.get_json()["explicit_non_claims"]) == 17
    catalog = client.get("/agent/crt/authorization-proofs")
    assert catalog.status_code == 200
    assert [x["artifact_id"] for x in catalog.get_json()["artifacts"]] == list(IDS)
    assert catalog.get_json() == client.get("/agent/crt/authorization-proofs").get_json()
    agent = client.get("/agent/discovery").get_json()
    block = agent["crt_authorization_proof"]
    assert block["status"] == "IMPLEMENTED_SOURCE_ONLY"
    assert block["deployment"] == "NOT_DEPLOYED"
    assert block["live_membership_evaluation"] is False
    assert block["mcp_publication"] is False


@pytest.mark.parametrize("artifact_id", IDS)
def test_exact_artifact_download_with_safe_headers(client, artifact_id):
    response = client.get(f"/agent/crt/authorization-proofs/{artifact_id}.json")
    assert response.status_code == 200
    assert response.data == reference_artifact_bytes(artifact_id)
    assert response.mimetype == "application/json"
    assert response.headers["ETag"] == f'"{sha256(response.data).hexdigest()}"'
    assert response.headers["Content-Disposition"] == (f'inline; filename="{artifact_id}.json"')
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "immutable" in response.headers["Cache-Control"]


@pytest.mark.parametrize(
    "path",
    (
        "/agent/crt/authorization-proofs/nope.json",
        "/agent/crt/authorization-proofs/E923-full.json",
        "/agent/crt/authorization-proofs/e923-full.txt",
        "/agent/crt/authorization-proofs/%2e%2e%2fe923-full.json",
        "/agent/crt/authorization-proofs/%2Fe923-full.json",
    ),
)
def test_unknown_malformed_and_traversal_ids_are_404(client, path):
    assert client.get(path).status_code == 404


def test_valid_verification_is_stable_and_non_claiming(client):
    raw = reference_artifact_bytes("e923-full")
    first = client.post(
        "/agent/crt/authorization-proofs/verify",
        data=raw,
        content_type="application/json",
    )
    second = client.post(
        "/agent/crt/authorization-proofs/verify",
        data=raw,
        content_type="application/json",
    )
    assert first.status_code == 200
    assert first.get_json() == second.get_json()
    body = first.get_json()
    assert body["schema"] == VERIFICATION_RESULT_SCHEMA
    assert body["valid"] is True
    for field in (
        "authenticity_verified",
        "currentness_verified",
        "live_evidence_verified",
        "runtime_authorization_granted",
    ):
        assert body[field] is False
    proof = parse_canonical_crt_authorization_proof(raw)
    assert body["explicit_non_claims"] == list(proof.explicit_non_claims)
    assert body["explicit_non_claims"] == list(MANDATORY_NON_CLAIMS)


@pytest.mark.parametrize("artifact_id", IDS)
def test_all_artifacts_and_verification_preserve_proof_non_claims(
    client,
    artifact_id,
):
    raw = reference_artifact_bytes(artifact_id)
    proof = parse_canonical_crt_authorization_proof(raw)
    assert proof.explicit_non_claims == MANDATORY_NON_CLAIMS
    response = client.post(
        "/agent/crt/authorization-proofs/verify",
        data=raw,
        content_type="application/json",
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["explicit_non_claims"] == list(proof.explicit_non_claims)
    assert body["authenticity_verified"] is False
    assert body["currentness_verified"] is False
    assert body["live_evidence_verified"] is False
    assert body["runtime_authorization_granted"] is False


def _raw_data():
    return json.loads(reference_artifact_bytes("e923-full"))


def _canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=True).encode("ascii")


@pytest.mark.parametrize(
    "mutation",
    (
        "extra",
        "missing",
        "float",
        "boolean",
        "nan",
        "infinity",
        "offset",
        "microseconds",
        "source_digest",
        "conclusion",
        "basis",
        "explanation",
        "noncanonical",
    ),
)
def test_adversarial_noncanonical_matrix_fails_closed(client, mutation):
    data = _raw_data()
    if mutation == "extra":
        data["secret_token"] = "must-not-reflect"
    elif mutation == "missing":
        del data["proof_basis"]
    elif mutation == "float":
        data["depth"] = 0.0
    elif mutation == "boolean":
        data["depth"] = True
    elif mutation == "nan":
        data["depth"] = float("nan")
    elif mutation == "infinity":
        data["depth"] = float("inf")
    elif mutation == "offset":
        data["evaluated_at"] = data["evaluated_at"][:-1] + "+00:00"
    elif mutation == "microseconds":
        data["evaluated_at"] = data["evaluated_at"][:-1] + ".000001Z"
    elif mutation == "source_digest":
        data["source_authorization_evaluation_sha256"] = "0" * 64
    elif mutation == "conclusion":
        data["proof_conclusion"] = "limited_by_unknown_membership"
    elif mutation == "basis":
        data["proof_basis"] = "source_binding"
    elif mutation == "explanation":
        data["canonical_explanation"] = "secret_token=must-not-reflect"
    raw = (
        json.dumps(
            dict(reversed(tuple(data.items()))),
            separators=(",", ":"),
        ).encode()
        if mutation == "noncanonical"
        else _canonical(data)
    )
    response = client.post(
        "/agent/crt/authorization-proofs/verify",
        data=raw,
        content_type="application/json",
    )
    assert response.status_code == 400
    assert response.get_json() == {
        "schema": VERIFICATION_RESULT_SCHEMA,
        "valid": False,
        "error": "invalid_canonical_crt_authorization_proof",
    }
    assert b"must-not-reflect" not in response.data


@pytest.mark.parametrize("nested", (None, "authorization", "membership"))
def test_duplicate_keys_fail_closed(client, nested):
    raw = reference_artifact_bytes("e923-full").decode("ascii")
    if nested is None:
        raw = raw[:-1] + ',"schema":"duplicate"}'
    elif nested == "authorization":
        marker = '"source_authorization_evaluation":{'
        raw = raw.replace(marker, marker + '"schema":"duplicate",', 1)
    else:
        marker = '"source_membership_evaluation":{'
        raw = raw.replace(marker, marker + '"schema":"duplicate",', 1)
    response = client.post(
        "/agent/crt/authorization-proofs/verify",
        data=raw,
        content_type="application/json",
    )
    assert response.status_code == 400


def test_size_empty_and_media_type_boundaries(client):
    endpoint = "/agent/crt/authorization-proofs/verify"
    assert client.post(endpoint, data=b"", content_type="application/json").status_code == 400
    assert client.post(endpoint, data=b"{}", content_type="text/plain").status_code == 415
    assert (
        client.post(
            endpoint,
            data=b"x" * (MAX_VERIFICATION_BODY_SIZE + 1),
            content_type="application/json",
        ).status_code
        == 413
    )


def test_get_routes_do_not_modify_artifacts(client):
    from pathlib import Path

    directory = Path(__file__).parents[2] / "app/public_artifacts" / "canonical_crt_authorization_proof/v1"
    before = {p.name: (p.stat().st_mtime_ns, p.read_bytes()) for p in directory.iterdir()}
    client.get("/.well-known/crt-authorization-proof.json")
    client.get("/agent/crt/authorization-proofs")
    for artifact_id in IDS:
        client.get(f"/agent/crt/authorization-proofs/{artifact_id}.json")
    after = {p.name: (p.stat().st_mtime_ns, p.read_bytes()) for p in directory.iterdir()}
    assert after == before


def test_routes_are_isolated_from_database_rpc_network_and_writes(
    client,
    monkeypatch,
):
    def forbidden(*args, **kwargs):
        raise AssertionError("forbidden runtime dependency called")

    import app.database
    import app.utils
    import requests
    from pathlib import Path

    monkeypatch.setattr(app.database, "session_scope", forbidden)
    monkeypatch.setattr(app.utils, "get_rpc_connection", forbidden)
    monkeypatch.setattr(requests.sessions.Session, "request", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)

    assert client.get("/.well-known/crt-authorization-proof.json").status_code == 200
    assert client.get("/agent/crt/authorization-proofs").status_code == 200
    assert client.get("/agent/crt/authorization-proofs/e923-full.json").status_code == 200
    assert (
        client.post(
            "/agent/crt/authorization-proofs/verify",
            data=reference_artifact_bytes("e923-full"),
            content_type="application/json",
        ).status_code
        == 200
    )
