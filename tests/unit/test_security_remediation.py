import base64
import hashlib


def test_pkce_required_on_authorize(client):
    from app.storage import store_oauth_client

    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "02" + "a" * 64
    store_oauth_client("c1", {"client_id": "c1", "client_secret": "s1", "redirect_uris": ["http://localhost/cb"]})
    r = client.get(
        "/oauth/authorize",
        query_string={"response_type": "code", "client_id": "c1", "redirect_uri": "http://localhost/cb"},
    )
    assert r.status_code == 400


def test_pkce_s256_token_exchange(client):
    from app.db_storage import store_oauth_client

    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "02" + "a" * 64
    store_oauth_client(
        "c2",
        {
            "client_id": "c2",
            "client_secret": "s2",
            "client_name": "test",
            "redirect_uris": ["http://localhost/cb"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid profile",
            "token_endpoint_auth_method": "client_secret_post",
            "metadata": {"trust_class": "public_dynamic"},
        },
    )
    verifier = "verifier-1234567890-1234567890-1234567890"
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    a = client.get(
        "/oauth/authorize",
        query_string={
            "response_type": "code",
            "client_id": "c2",
            "redirect_uri": "http://localhost/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert a.status_code in (302, 303)
    code = a.location.split("code=")[1]
    bad = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost/cb",
            "client_id": "c2",
            "client_secret": "s2",
            "code_verifier": "wrong",
        },
    )
    assert bad.status_code == 400


def test_rpc_disallows_dangerous_command(client):
    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "02" + "a" * 64
        sess["access_level"] = "full"
    r = client.get("/rpc/stop")
    assert r.status_code in (400, 403)


def test_rpc_unknown_command_blocked(client):
    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "02" + "a" * 64
        sess["access_level"] = "full"
    r = client.get("/rpc/definitelynotreal")
    assert r.status_code in (400, 403)
