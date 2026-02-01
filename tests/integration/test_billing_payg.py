import os


def test_demo_protected_requires_payment(client, oauth_client_token, monkeypatch):
    monkeypatch.setenv("HODLXXI_FREE_QUOTA_CALLS", "0")

    headers = {"Authorization": f"Bearer {oauth_client_token['access_token']}"}
    response = client.get("/api/demo/protected", headers=headers)

    assert response.status_code == 402
    data = response.get_json()
    assert data["error"] == "payment_required"
    assert data["code"] == "PAYMENT_REQUIRED"
    assert data["client_id"] == oauth_client_token["client_id"]
    assert "create_invoice_endpoint" in data


def test_invoice_topup_allows_paid_endpoint(client, oauth_client_token, monkeypatch):
    monkeypatch.setenv("TEST_INVOICE_PAID", "true")

    headers = {"Authorization": f"Bearer {oauth_client_token['access_token']}"}
    create_resp = client.post("/api/billing/agent/create-invoice", json={"amount_sats": 10}, headers=headers)
    assert create_resp.status_code == 200
    payload = create_resp.get_json()
    invoice_id = payload["invoice_id"]

    check_resp = client.post("/api/billing/agent/check-invoice", json={"invoice_id": invoice_id}, headers=headers)
    assert check_resp.status_code == 200
    check_payload = check_resp.get_json()
    assert check_payload["paid"] is True
    assert check_payload["sats_balance"] >= 10

    protected_resp = client.get("/api/demo/protected", headers=headers)
    assert protected_resp.status_code == 200

    monkeypatch.setenv("TEST_INVOICE_PAID", "false")
