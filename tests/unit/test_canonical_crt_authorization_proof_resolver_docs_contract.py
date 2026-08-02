from pathlib import Path

from app.services.canonical_crt_authorization_proof_resolver import (
    EXPLICIT_NON_CLAIMS,
    STATUS,
)


DOC = Path("docs/CANONICAL_CRT_AUTHORIZATION_PROOF_RESOLVER_V1.md")


def test_status_non_claims_and_temporal_distinction_are_exact():
    text = DOC.read_text()
    assert len(STATUS) == 5
    assert len(EXPLICIT_NON_CLAIMS) == 28
    for item in STATUS + EXPLICIT_NON_CLAIMS:
        assert f"`{item}`" in text
    for required in (
        "2026-07-26T12:00:00Z",
        "2027-07-26T12:00:00Z",
        "source_time_mismatch",
        "3b08da361c571121895f97a4c0f2f74995aa4a335b454066906dab044ed0823b",
        "does not fabricate or naturally reproduce that mismatch",
        "trusted live source adapter",
        "production DB composition",
        "automatic Bitcoin observation",
        "participant-facing current-proof lookup",
        "HTTP current-proof route",
        "MCP current-proof tool",
        "signature or issuer",
        "human HTML verifier",
        "shadow authorization comparison",
        "runtime enforcement",
        "production deployment",
    ):
        assert required in text
