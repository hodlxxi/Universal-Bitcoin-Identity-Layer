from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "OIDC_INTEGRATION.md"


def test_oidc_integration_guide_exists_and_documents_contract_terms():
    assert DOC.exists()
    text = DOC.read_text(encoding="utf-8")

    required_terms = [
        "Sign in with HODLXXI",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
        "/oauth/authorize",
        "/oauth/token",
        "/oauth/jwks.json",
        "authorization_code",
        "S256",
        "PKCE",
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "client_id",
        "redirect_uri",
        "code_challenge",
        "code_verifier",
        "read",
        "write",
        "covenant_read",
        "covenant_create",
        "read_limited",
        "does not prove legal identity",
        "does not prove KYC",
        "does not prove custody",
        "does not prove locked capital",
        "paid receipt verifier",
        "scripts/verify_paid_receipt_evidence.sh",
    ]

    missing = [term for term in required_terms if term not in text]
    assert not missing


def test_oidc_integration_guide_is_linked_from_readme_or_docs_index():
    linked_from = [
        ROOT / "README.md",
        ROOT / "docs" / "README.md",
        ROOT / "docs" / "DOCUMENTATION_MAP.md",
    ]

    assert any(
        "docs/OIDC_INTEGRATION.md" in path.read_text(encoding="utf-8")
        or "OIDC_INTEGRATION.md" in path.read_text(encoding="utf-8")
        for path in linked_from
    )


def test_oidc_integration_guide_does_not_include_secret_or_invoice_material():
    text = DOC.read_text(encoding="utf-8")
    lowered = text.lower()

    forbidden_terms = [
        "client_secret=real",
        "macaroon",
        "lnbc",
        "lntb",
        "lnbcrt",
    ]
    forbidden_case_sensitive = [
        "BEGIN PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
    ]

    assert "private_key" not in lowered
    assert not any(term in lowered for term in forbidden_terms)
    assert not any(term in text for term in forbidden_case_sensitive)
