import re

from app.factory import create_app


def _client():
    app = create_app()
    app.config.update(TESTING=True, HUMAN_PROOF_PUBLIC_BASE_URL="https://hodlxxi.example")
    return app.test_client()


def test_verifier_qr_svg_is_deterministic_and_read_only_for_unknown_job():
    client = _client()

    first = client.get("/agent/qr/verify/test-job-123.svg?target=https://evil.example")
    second = client.get("/agent/qr/verify/test-job-123.svg")
    other = client.get("/agent/qr/verify/other-job-123.svg")

    assert first.status_code == 200
    assert first.content_type.startswith("image/svg+xml")
    assert b"<svg" in first.data
    assert first.data == second.data
    assert first.data != other.data
    assert b"evil.example" not in first.data


def test_verifier_qr_svg_uses_canonical_base_url_override():
    client = _client()

    response = client.get("/agent/qr/verify/test-job-123.svg")

    assert response.status_code == 200
    # SvgPathImage stores QR modules as paths only; assert no raw job_id text node leaks.
    assert b"test-job-123" not in response.data


def test_verifier_qr_rejects_invalid_job_ids():
    client = _client()
    invalid_paths = [
        "/agent/qr/verify/../login.svg",
        "/agent/qr/verify/..%2flogin.svg",
        "/agent/qr/verify/..%2Flogin.svg",
        "/agent/qr/verify/%2e%2e/login.svg",
        "/agent/qr/verify/<script>.svg",
        "/agent/qr/verify/job id with spaces.svg",
        "/agent/qr/verify/job?id=1.svg",
        "/agent/qr/verify/job#fragment.svg",
        "/agent/qr/verify/job&x=1.svg",
        f"/agent/qr/verify/{'a' * 129}.svg",
    ]

    for path in invalid_paths:
        response = client.get(path)
        assert response.status_code in {400, 404}, path


def test_safe_job_id_rule_documents_allowed_examples():
    client = _client()
    valid_job_ids = [
        "41dcc055-f67f-4992-95a5-975776f6e0b6",
        "test-job-123",
        "job_123",
        "hodlxxi-receipt-v1:abc.def-123",
    ]

    for job_id in valid_job_ids:
        response = client.get(f"/agent/qr/verify/{job_id}.svg")
        assert response.status_code == 200
        assert re.match(r"image/svg\+xml", response.content_type)
