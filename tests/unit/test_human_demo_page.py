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
        "HODLXXI is a Bitcoin-native proof runtime: pay for an action, get a result, and verify the signed receipt later.",
        "I paid, I requested, I received, I can verify.",
        "What this proves",
        "What this does not prove",
        "not a token sale",
        "not an investment",
        "not KYC",
        "not legal identity",
        "not custody",
        "not a promise of profit",
        "not proof of moral trustworthiness",
        "not a guarantee of future performance",
        "not ownership of a network",
        "Requester key proof means key control for this request only.",
        "Request",
        "Pay",
        "Result",
        "Verify",
        "21 sat",
        "requester_pubkey",
        "/agent/request",
        "/agent/jobs/",
        "/agent/verify/",
        "/agent/receipts/",
        "Download receipt JSON",
        "receiptDownloadLink",
        "/agent/attestations",
        "/agent/reputation",
        "/agent/chain/health",
        "factual runtime surfaces",
        "not human trust scores",
        "not a human trust score",
        "local append-only continuity",
        "not global consensus",
        "not authority",
        "not consent",
        "not an investment signal",
        "not token ownership",
        "The requester key is proven by a compatible Nostr signer before the invoice is created",
        "This proves control of the signing key for this request",
        "It does not prove a legal name, government identity",
        "No private key is requested",
        "Prove key and create 21 sat request",
        "Hello from HODLXXI demo",
        "QR-ready receipt verifier link",
        "A QR code can carry this verifier URL; the deterministic QR image endpoint will be added separately.",
        "QR opens the public verifier",
        "QR code is not the proof",
        "signed receipt and verifier response are the proof",
        "not proof of payment by itself",
        "not proof of identity",
    ]:
        assert marker in text


def test_human_demo_no_nostr_shows_mobile_signer_chooser():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/demo", base_url="https://hodlxxi.com")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    for marker in [
        "No signer is available in this browser.",
        "On desktop, use a Nostr signer extension.",
        "On Android, open a compatible Nostr signer app.",
        "iPhone remote signing support is not available yet.",
        "Open Android signer",
        "Open this page on desktop with a NIP-07 signer.",
    ]:
        assert marker in text


def test_human_demo_android_nip55_contract_markers():
    from pathlib import Path

    text = Path("app/templates/agent/demo.html").read_text()
    for marker in [
        "nostrsigner:",
        "type",
        "sign_event",
        "returnType",
        "event",
        "callbackUrl",
        'callbackUrl.searchParams.set("event", "")',
        'params.get("result")',
        'signerUrl.searchParams.set("type", "sign_event")',
        'signerUrl.searchParams.set("returnType", "event")',
        'signerUrl.searchParams.set("compressionType", "none")',
        "agent_requester_proof_v1",
        "human_proof_v2",
        "sessionStorage",
        "mobile_proof",
    ]:
        assert marker in text
