from app.factory import create_app


def test_human_demo_page_renders_interactive_paid_agent_flow():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/demo", base_url="https://hodlxxi.com")
    text = response.get_data(as_text=True)

    assert response.status_code == 200

    for marker in [
        "Human proof page",
        "Request",
        "Pay",
        "Result",
        "Verify",
        "21 sat",
        "requester_pubkey",
        "/agent/request",
        "/agent/jobs/",
        "/agent/verify/",
        "The requester key is proven by a compatible Nostr signer before the invoice is created",
        "This proves control of the signing key for this request",
        "It does not prove a legal name, government identity",
        "No private key is requested",
        "Prove key and create 21 sat request",
        "Hello from HODLXXI demo",
    ]:
        assert marker in text
