from pathlib import Path

SCRIPT = Path("scripts/smoke_human_proof_public_surfaces.sh")


def _script_text() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_human_proof_smoke_script_exists_and_is_executable():
    assert SCRIPT.exists()
    assert SCRIPT.stat().st_mode & 0o111


def test_human_proof_smoke_script_uses_public_read_only_get_contract():
    text = _script_text()
    for marker in [
        "set -Eeuo pipefail",
        "${BASE_URL:-https://hodlxxi.com}",
        "BASE_URL=",
        "read-only GET checks only",
        "creates no jobs, invoices, payments, or database mutations",
        "curl --silent --show-error --location --get",
        "head -c 500",
        "/demo",
        "/agent/verify",
        "/agent/capabilities",
        "/agent/attestations",
        "/agent/reputation",
        "/agent/chain/health",
        "/agent/verify/unknown-human-proof-mvp-job-id",
        "/agent/receipt-proof",
        "/.well-known/agent.json",
        "/agent/qr/verify/unknown-human-proof-smoke-token.svg",
        "image/svg+xml",
        "<svg",
        "SECRET|TOKEN|PASSWORD|PRIVATE|MACAROON|DATABASE_URL|REDIS_URL|LND",
    ]:
        assert marker in text


def test_human_proof_smoke_script_avoids_unsafe_calls_and_secret_dumping():
    text = _script_text()
    unsafe_markers = [
        "POST ",
        "curl -X POST",
        "/agent/request",
        "/api/challenge",
        "/api/verify",
        "/agent/jobs/",
        "/dev/",
        "operator",
        ".env",
        "printenv",
        "env |",
    ]
    for marker in unsafe_markers:
        assert marker not in text
