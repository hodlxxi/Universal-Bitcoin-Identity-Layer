"""P50 contract: authenticated /app renders NIP-59 no-send UI status."""


def test_authenticated_app_renders_nip59_no_send_status_ui(client):
    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "02" + "a" * 64
        sess["access_level"] = "full"

    response = client.get("/app")

    assert response.status_code == 200
    html = response.get_data(as_text=True)

    assert "NIP-59 bundle" in html
    assert "NIP-59 send" in html
    assert "NIP-59 POST" in html
    assert "NIP-59 relay" in html
    assert "nip59BundleStatus" in html
    assert "nip59SendStatus" in html
    assert "nip59PostStatus" in html
    assert "nip59RelayStatus" in html
    assert "unexpected-enabled" in html


def test_authenticated_app_loads_nip59_bundle_but_not_delivery_endpoint(client):
    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "02" + "b" * 64
        sess["access_level"] = "full"

    response = client.get("/app")

    assert response.status_code == 200
    html = response.get_data(as_text=True)

    assert "/static/js/nip59_client_bundle.js" in html
    assert "window.HODLXXI_NIP59_CLIENT" in html
    assert "client.sendEnabled === false" in html
    assert "client.canPostEnvelope === false" in html
    assert "client.relayPublishing === false" in html
    assert "/api/messages/nip17/envelopes" not in html
    assert "SimplePool" not in html
    assert "relayInit" not in html
    assert "publish(" not in html


def test_unauthenticated_app_still_redirects_to_login(client):
    response = client.get("/app", follow_redirects=False)

    assert response.status_code in {302, 303}
    assert "/login?next=/app" in response.headers["Location"]
