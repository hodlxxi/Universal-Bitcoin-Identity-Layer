from app.factory import create_app


def test_human_public_evidence_page_renders_public_evidence_map():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/agent/evidence", base_url="https://hodlxxi.com")
    text = response.get_data(as_text=True)

    assert response.status_code == 200

    for marker in [
        "HODLXXI Public Evidence",
        "human-readable map",
        "Operator continuity",
        "Paid receipt proof",
        "Readiness report",
        "Machine readiness JSON",
        "Reputation",
        "Attestations",
        "Chain health",
        "Agent discovery",
        "OIDC",
        "External reviewer packet",
        "/agent/receipt-proof",
        "/agent/readiness",
        "/agent/readiness/self-scan",
        "/.well-known/hodlxxi-operator.json",
        "/agent/reputation",
        "/agent/attestations",
        "/agent/chain/health",
        "/.well-known/agent.json",
        "/oidc",
        "docs/EXTERNAL_REVIEWER_PACKET.md",
        "Suggested review path",
        "What this evidence can support",
        "What this evidence does not prove",
        "does not prove legal identity",
        "does not prove KYC",
        "does not prove custody",
        "does not prove locked capital",
    ]:
        assert marker in text


def test_homepage_review_public_evidence_card_points_to_evidence_map():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/", base_url="https://hodlxxi.com")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "/agent/evidence" in text
    assert "Open evidence map" in text

    card_start = text.index("Review public evidence")
    card_end = text.index("Verify a paid agent receipt")
    review_card = text[card_start:card_end]

    assert "docs/EXTERNAL_REVIEWER_PACKET.md" not in review_card
    assert "github.com/hodlxxi/Universal-Bitcoin-Identity-Layer" not in review_card
