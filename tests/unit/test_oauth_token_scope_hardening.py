import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse

import jwt
from werkzeug.security import check_password_hash

from app.db_storage import get_canonical_jwt_record_by_jti, get_oauth_client


def _pair():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def test_dynamic_registration_policy_and_secret_hash(client):
    response = client.post(
        "/oauth/register",
        json={"client_name": "scope test", "redirect_uris": ["https://client.example/cb"]},
    )
    assert response.status_code == 201
    body = response.get_json()
    assert body["scope"] == "openid profile self:read"
    assert body["token_endpoint_auth_method"] == "client_secret_post"
    stored = get_oauth_client(body["client_id"])
    assert stored["metadata"]["trust_class"] == "public_dynamic"
    assert stored["client_secret"] != body["client_secret"]
    assert check_password_hash(stored["client_secret"], body["client_secret"])


def test_registration_rejects_privilege_and_metadata_escalation(client):
    base = {"client_name": "bad", "redirect_uris": ["https://client.example/cb"]}
    assert client.post("/oauth/register", json={**base, "scope": "job:create"}).status_code == 400
    assert (
        client.post("/oauth/register", json={**base, "metadata": {"trust_class": "operator_managed"}}).status_code
        == 400
    )
    assert client.post("/oauth/register", json={**base, "grant_types": ["refresh_token"]}).status_code == 400


def test_canonical_access_token_is_persisted_and_introspectable(client):
    registration = client.post(
        "/oauth/register",
        json={"client_name": "flow", "redirect_uris": ["https://client.example/cb"], "scope": "profile openid"},
    ).get_json()
    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "02" + "a" * 64
    verifier, challenge = _pair()
    authorization = client.get(
        "/oauth/authorize",
        query_string={
            "response_type": "code",
            "client_id": registration["client_id"],
            "redirect_uri": registration["redirect_uris"][0],
            "scope": "profile openid",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    code = parse_qs(urlparse(authorization.location).query)["code"][0]
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": registration["redirect_uris"][0],
        "client_id": registration["client_id"],
        "client_secret": registration["client_secret"],
        "code_verifier": verifier,
    }
    issued = client.post("/oauth/token", data=form)
    assert issued.status_code == 200
    token = issued.get_json()["access_token"]
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["scope"] == "openid profile"
    assert claims["token_use"] == "access"
    assert claims["token_contract"] == "hodlxxi.oauth.access-token.v1"
    record = get_canonical_jwt_record_by_jti(claims["jti"])
    assert record["digest"] == hashlib.sha256(token.encode()).hexdigest()
    assert record["digest"] != token
    active = client.post(
        "/oauth/introspect",
        data={"token": token, "client_id": registration["client_id"], "client_secret": registration["client_secret"]},
    ).get_json()
    assert active["active"] is True
    assert active["scope"] == "openid profile"
    assert client.post("/oauth/token", data=form).get_json()["error"] == "invalid_grant"
