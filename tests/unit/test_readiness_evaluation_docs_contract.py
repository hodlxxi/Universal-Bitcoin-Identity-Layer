from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
READINESS_DOC = ROOT / "docs" / "READINESS_EVALUATION.md"


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_readiness_evaluation_doc_exists() -> None:
    assert READINESS_DOC.exists()


def test_readiness_evaluation_links_from_primary_indexes() -> None:
    assert "docs/READINESS_EVALUATION.md" in read("README.md")
    assert "READINESS_EVALUATION.md" in read("docs/README.md")
    assert "docs/READINESS_EVALUATION.md" in read("docs/DOCUMENTATION_MAP.md")


def test_readiness_evaluation_contains_public_smoke_and_verifier_contract() -> None:
    text = READINESS_DOC.read_text(encoding="utf-8")

    required_terms = [
        "BASE=https://hodlxxi.com bash scripts/smoke_public_agent_contract.sh",
        "/.well-known/agent.json",
        "/agent/capabilities",
        "/agent/discovery",
        "/.well-known/hodlxxi-operator.json",
        "/agent/verify/<job_id>",
        "409",
        "no_receipt",
        "receipt_not_issued",
        "404",
        "not_found",
        "HODLXXIClient.verify_job",
        "does not prove locked capital",
        "does not prove legal identity",
        "does not print invoice strings",
        "does not require secrets",
    ]

    for term in required_terms:
        assert term in text


def test_readiness_evaluation_links_to_canonical_docs() -> None:
    text = READINESS_DOC.read_text(encoding="utf-8")

    required_links = [
        "docs/DOCUMENTATION_MAP.md",
        "AGENT_PROTOCOL.md",
        "docs/AGENT_RECEIPT_V1.md",
        "docs/OPERATOR_CONTINUITY_E923.md",
        "docs/ops/PUBLIC_AGENT_CONTRACT_SMOKE.md",
        "docs/sdk/README.md",
    ]

    for link in required_links:
        assert link in text
