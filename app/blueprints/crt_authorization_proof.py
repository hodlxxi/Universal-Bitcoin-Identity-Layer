"""Public read-only canonical CRT authorization proof routes."""

from flask import Blueprint, Response, jsonify, request

from app.services.canonical_crt_authorization_proof_publication import (
    MAX_VERIFICATION_BODY_SIZE,
    VERIFICATION_RESULT_SCHEMA,
    discovery_document,
    reference_artifact_bytes,
    reference_artifact_catalog,
    reference_artifact_digest,
    verify_submitted_proof,
)
crt_authorization_proof_bp = Blueprint(
    "crt_authorization_proof",
    __name__,
)


@crt_authorization_proof_bp.get(
    "/.well-known/crt-authorization-proof.json"
)
def crt_authorization_proof_discovery():
    return jsonify(dict(discovery_document()))


@crt_authorization_proof_bp.get("/agent/crt/authorization-proofs")
def crt_authorization_proof_catalog():
    return jsonify({
        "schema": discovery_document()["schema"],
        "publication_mode": "reference_artifacts_only",
        "artifacts": [dict(item) for item in reference_artifact_catalog()],
    })


@crt_authorization_proof_bp.get(
    "/agent/crt/authorization-proofs/<artifact_id>.json",
    merge_slashes=False,
)
def crt_authorization_proof_artifact(artifact_id: str):
    raw = reference_artifact_bytes(artifact_id)
    digest = reference_artifact_digest(artifact_id)
    if raw is None or digest is None:
        return jsonify({"error": "unknown_reference_artifact"}), 404
    response = Response(raw, content_type="application/json")
    response.set_etag(digest)
    response.headers["Content-Disposition"] = (
        f'inline; filename="{artifact_id}.json"'
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return response


@crt_authorization_proof_bp.get(
    "/agent/crt/authorization-proofs//<path:artifact_id>.json",
    merge_slashes=False,
)
def crt_authorization_proof_reject_slash_artifact(artifact_id: str):
    return jsonify({"error": "unknown_reference_artifact"}), 404


def _invalid():
    return jsonify({
        "schema": VERIFICATION_RESULT_SCHEMA,
        "valid": False,
        "error": "invalid_canonical_crt_authorization_proof",
    }), 400


@crt_authorization_proof_bp.post("/agent/crt/authorization-proofs/verify")
def crt_authorization_proof_verify():
    if request.mimetype != "application/json":
        return jsonify({"error": "unsupported_media_type"}), 415
    if (
        request.content_length is not None
        and request.content_length > MAX_VERIFICATION_BODY_SIZE
    ):
        return jsonify({"error": "verification_body_too_large"}), 413
    raw = request.get_data(cache=False, as_text=False)
    if len(raw) > MAX_VERIFICATION_BODY_SIZE:
        return jsonify({"error": "verification_body_too_large"}), 413
    if not raw:
        return _invalid()
    try:
        result = verify_submitted_proof(raw)
    except (TypeError, ValueError):
        return _invalid()
    return jsonify(dict(result))
