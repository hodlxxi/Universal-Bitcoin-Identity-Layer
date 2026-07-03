from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MVP_DOC = REPO_ROOT / "docs" / "HUMAN_PROOF_MVP.md"
RUNBOOK_DOC = REPO_ROOT / "docs" / "ops" / "HUMAN_PROOF_MVP_RUNBOOK.md"


def _combined_docs() -> str:
    return "\n".join(
        [
            MVP_DOC.read_text(encoding="utf-8"),
            RUNBOOK_DOC.read_text(encoding="utf-8"),
        ]
    )


def test_human_proof_mvp_docs_exist():
    assert MVP_DOC.exists()
    assert RUNBOOK_DOC.exists()


def test_human_proof_mvp_docs_include_required_endpoint_inventory():
    docs = _combined_docs()
    required_endpoints = [
        "/demo",
        "/agent/verify",
        "/agent/verify/<job_id>",
        "/agent/receipts/<job_id>.json",
        "/agent/attestations",
        "/agent/reputation",
        "/agent/chain/health",
    ]
    for endpoint in required_endpoints:
        assert endpoint in docs


def test_human_proof_mvp_docs_include_bounded_claim_strings():
    docs = _combined_docs()
    required_claim_boundaries = [
        "not a token sale",
        "not an investment",
        "not KYC",
        "not legal identity",
        "not custody",
        "not a promise of profit",
        "not proof of moral trustworthiness",
        "not a guarantee of future performance",
        "not ownership of a network",
        "not global consensus",
        "not consent",
        "not authority",
    ]
    for boundary in required_claim_boundaries:
        assert boundary in docs


def test_human_proof_mvp_docs_include_requester_proof_storage_requirement():
    docs = _combined_docs()
    required_storage_terms = [
        "process-local memory",
        "single worker",
        "session affinity",
        "Redis or another shared TTL storage layer",
    ]
    for term in required_storage_terms:
        assert term in docs


def test_human_proof_mvp_runbook_includes_required_sections():
    runbook = RUNBOOK_DOC.read_text(encoding="utf-8")
    required_sections = [
        "Preflight checks",
        "Staging validation",
        "Production rollout boundary",
        "Smoke tests",
        "Manual browser validation",
        "Rollback",
        "Post-launch monitoring",
    ]
    for section in required_sections:
        assert f"## {section}" in runbook


def test_human_proof_mvp_runbook_links_safe_smoke_script():
    runbook = RUNBOOK_DOC.read_text(encoding="utf-8")
    for marker in [
        "scripts/smoke_human_proof_public_surfaces.sh",
        "BASE_URL=https://staging.hodlxxi.com",
        "BASE_URL=https://hodlxxi.com",
        "read-only",
        "does not create jobs, invoices, payments, or database mutations",
    ]:
        assert marker in runbook


def test_human_proof_mvp_docs_include_qr_verification_affordance_boundary():
    docs = _combined_docs()
    for marker in [
        "QR verification affordance",
        "QR verification affordance can carry the verifier URL",
        "QR does not replace receipt verification",
        "/agent/verify/<job_id> remains the verification authority",
        "signed receipt remains the proof artifact",
        "discovery/transport only",
    ]:
        assert marker in docs
