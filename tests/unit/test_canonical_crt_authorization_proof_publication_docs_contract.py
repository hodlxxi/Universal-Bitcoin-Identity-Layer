from pathlib import Path

ROOT = Path(__file__).parents[2]


def test_publication_document_contains_statuses_and_every_non_claim():
    text = (ROOT / "docs/CANONICAL_CRT_AUTHORIZATION_PROOF_PUBLICATION_V1.md").read_text()
    for required in (
        "IMPLEMENTED_SOURCE_ONLY",
        "READ_ONLY_REFERENCE_SURFACE",
        "NOT_DEPLOYED",
        "NOT_LIVE_MEMBERSHIP",
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
    ):
        assert required in text
    assert "hodlxxi.com is serving" not in text


def test_status_documents_reject_stale_pre_publication_language():
    status = (ROOT / "docs/CRT_MEMBERSHIP_IMPLEMENTATION_STATUS.md").read_text()
    index = (ROOT / "docs/README.md").read_text()
    assert "No public resolver or publication surface consumes it." not in status
    assert "public publication remains deferred to PR6.15" not in index
    assert "PR6.14 pure canonical proof" in status
    assert "IMPLEMENTED_DORMANT" in status
    assert "PR6.15 source-only reference publication service" in status
    assert "no live generation or deployment" in index
