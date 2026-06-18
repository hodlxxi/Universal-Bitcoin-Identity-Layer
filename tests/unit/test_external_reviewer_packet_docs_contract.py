from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKET_DOC = ROOT / "docs" / "EXTERNAL_REVIEWER_PACKET.md"


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_external_reviewer_packet_exists() -> None:
    assert PACKET_DOC.exists()


def test_external_reviewer_packet_contains_required_review_terms() -> None:
    text = PACKET_DOC.read_text(encoding="utf-8")

    required_terms = [
        "HODLXXI External Reviewer Packet",
        "external developers",
        "technical reviewers",
        "agent marketplace reviewers",
        "/.well-known/agent.json",
        "/agent/capabilities",
        "/agent/discovery",
        "/.well-known/hodlxxi-operator.json",
        "/agent/readiness/self-scan",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
        "/oauth/jwks.json",
        "/agent/reputation",
        "/agent/attestations",
        "/agent/chain/health",
        "scripts/smoke_public_agent_contract.sh",
        "scripts/verify_operator_continuity.sh",
        "scripts/verify_paid_receipt_evidence.sh",
        "docs/OIDC_INTEGRATION.md",
        "docs/READINESS_EVALUATION.md",
        "docs/RECEIPT_VERIFICATION.md",
        "docs/AGENT_RECEIPT_QUICKSTART.md",
        "docs/OPERATOR_CONTINUITY_E923.md",
        "E923",
        "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923",
        "02019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92",
        "1013ca86-f09e-40d3-b6ea-862620890b36",
        "PASS: paid receipt evidence verified",
        "does not prove legal identity",
        "does not prove KYC",
        "does not prove custody",
        "does not prove locked capital",
        "does not prove full OIDC certification",
        "does not require or reveal private keys",
        "BOLT11",
    ]

    for term in required_terms:
        assert term in text


def test_external_reviewer_packet_is_linked_from_primary_docs_index() -> None:
    linked_from_docs_readme = "EXTERNAL_REVIEWER_PACKET.md" in read("docs/README.md")
    linked_from_docs_map = "docs/EXTERNAL_REVIEWER_PACKET.md" in read("docs/DOCUMENTATION_MAP.md")

    assert linked_from_docs_readme or linked_from_docs_map


def test_external_reviewer_packet_does_not_include_sensitive_material() -> None:
    text = PACKET_DOC.read_text(encoding="utf-8")

    forbidden_terms = [
        "lnbc",
        "lntb",
        "lnbcrt",
        "macaroon",
        "seed phrase",
        "xprv",
        "BEGIN PRIVATE KEY",
    ]

    for term in forbidden_terms:
        assert term not in text
