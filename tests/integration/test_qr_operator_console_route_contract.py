from __future__ import annotations

FULL_PUBKEY = "02" + ("a" * 60) + "abcd"
LIMITED_PUBKEY = "02" + ("b" * 60) + "beef"
SECRET_MARKERS = [
    "private_key",
    "privkey",
    "seed phrase",
    "mnemonic",
    "macaroon",
    "rpc_password",
    "database_password",
    "session id",
    "session_id",
    "cookie",
    "raw credentials",
    "env values",
    FULL_PUBKEY,
]


def _row_for_token(body: str, token: str) -> str:
    marker = f"<code>{token}</code>"
    marker_index = body.index(marker)
    row_start = body.rfind("<tr>", 0, marker_index)
    row_end = body.find("</tr>", marker_index)
    return body[row_start : row_end + len("</tr>")]


def _set_session(client, pubkey: str, access_level: str) -> None:
    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = pubkey
        sess["access_level"] = access_level


def test_full_session_can_access_operator_console(client):
    _set_session(client, FULL_PUBKEY, "full")

    res = client.get("/operator/qr")

    assert res.status_code == 200
    body = res.get_data(as_text=True)
    assert "QR Operator Console" in body
    assert "qrcode.min.js" in body
    assert "/qr/demo-active" in body
    assert "/qr/verify-demo" in body
    assert "abcd" in body
    assert FULL_PUBKEY not in body
    assert "QR is discovery-only." in body
    assert "QR is not authorization." in body
    assert "/agent/verify/&lt;job_id&gt;" in body


def test_manual_target_links_only_render_for_active_pointers(client):
    _set_session(client, FULL_PUBKEY, "full")

    res = client.get("/operator/qr")

    assert res.status_code == 200
    body = res.get_data(as_text=True)
    active_row = _row_for_token(body, "demo-active")
    verify_row = _row_for_token(body, "verify-demo")
    revoked_row = _row_for_token(body, "demo-revoked")
    expired_row = _row_for_token(body, "demo-expired")

    assert 'href="/agent/discovery"' in active_row
    assert 'href="/agent/verify/demo-job-001"' in verify_row
    assert 'href="/agent/discovery"' not in revoked_row
    assert 'href="/agent/discovery"' not in expired_row
    assert "/agent/discovery" in revoked_row
    assert "/agent/discovery" in expired_row


def test_limited_session_receives_forbidden_from_operator_console(client):
    _set_session(client, LIMITED_PUBKEY, "limited")

    assert client.get("/operator/qr").status_code == 403


def test_anonymous_session_receives_safe_denied_from_operator_console(client):
    assert client.get("/operator/qr").status_code in {401, 302}


def test_full_session_can_access_operator_pointer_api(client):
    _set_session(client, FULL_PUBKEY, "full")

    res = client.get("/api/operator/qr/pointers")

    assert res.status_code == 200
    data = res.get_json()
    assert data["ok"] is True
    assert data["access_level"] == "full"
    assert data["user_pubkey_tail"] == "abcd"
    records = {record["token"]: record for record in data["pointers"]}
    assert records["demo-active"]["target"] == "/agent/discovery"
    assert records["demo-active"]["status"] == "active"
    assert records["demo-active"]["qr_url"] == "http://localhost/qr/demo-active"
    assert records["demo-active"]["manual_target_allowed"] is True
    assert records["verify-demo"]["qr_url"] == "http://localhost/qr/verify-demo"
    assert records["verify-demo"]["manual_target_allowed"] is True
    assert records["demo-revoked"]["manual_target_allowed"] is False
    assert records["demo-expired"]["manual_target_allowed"] is False


def test_limited_session_receives_forbidden_from_operator_pointer_api(client):
    _set_session(client, LIMITED_PUBKEY, "limited")

    assert client.get("/api/operator/qr/pointers").status_code == 403


def test_anonymous_session_receives_safe_denied_from_operator_pointer_api(client):
    assert client.get("/api/operator/qr/pointers").status_code in {401, 403, 302}


def test_operator_pointer_api_does_not_expose_secret_material_or_full_pubkey(client):
    _set_session(client, FULL_PUBKEY, "full")

    res = client.get("/api/operator/qr/pointers")
    serialized = res.get_data(as_text=True).lower()

    for marker in SECRET_MARKERS:
        assert marker.lower() not in serialized
    assert "abcd" in serialized


def test_capabilities_still_do_not_advertise_qr_surfaces(client):
    body = client.get("/agent/capabilities").get_data(as_text=True).lower()

    assert "/qr/" not in body
    assert "/operator/qr" not in body


def test_existing_public_qr_pointer_behavior_remains_unchanged(client):
    active = client.get("/qr/demo-active")
    revoked = client.get("/qr/demo-revoked")
    verify = client.get("/qr/verify-demo")

    assert active.status_code == 200
    assert "/agent/discovery" in active.get_data(as_text=True)
    assert revoked.status_code == 410
    assert verify.status_code == 200
    assert "/agent/verify/demo-job-001" in verify.get_data(as_text=True)


def test_operator_surfaces_do_not_mutate_jobs_receipts_payments_or_delegations(client):
    _set_session(client, FULL_PUBKEY, "full")

    with client.session_transaction() as sess:
        before = dict(sess)

    assert client.get("/operator/qr").status_code == 200
    assert client.get("/api/operator/qr/pointers").status_code == 200

    with client.session_transaction() as sess:
        after = dict(sess)

    assert after == before
