"""Strict transport and real synthetic confidential credential boundaries."""

import json
import os
import time
import uuid
from dataclasses import replace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask
from jwt.algorithms import RSAAlgorithm

from app.blueprints.internal_social_mobile_authorization import internal_social_mobile_authorization_bp
from app.services.confidential_service_assertion_replay_storage import PostgresConfidentialServiceAssertionReplayStore
from app.services.confidential_service_credentials import (
    ConfidentialServiceConfig,
    CredentialDenied,
    verify_service_access_token,
)
from app.services.oauth_session_lifecycle import OAuthSessionAuthority, SqlAlchemyOAuthSessionLifecycle
from app.services.social_messaging_mobile_authorization_storage import SqlAlchemyMobileAuthorizationService
from app.services.social_mobile_authorization_ingress import (
    EXTENSION,
    MobileAuthorizationIngress,
    MobileIngressConfigurationError,
    install_mobile_ingress,
)
from app.services.social_mobile_authorization_ingress_schema import (
    COMMANDS,
    GROUPS,
    MAX_BODY_BYTES,
    PREFIX,
    PURPOSES,
    SCOPES,
    TOKEN_PATH,
    VIEWER_HEADER,
    InvalidMobileRequest,
    command_body,
)

ISSUER = "https://identity.example"
BACKEND = "synthetic-social-backend"
VIEWER_CLIENT = "synthetic-social"


@pytest.fixture(scope="module")
def material():
    client = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    service = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def public(key, kid):
        return dict(json.loads(RSAAlgorithm.to_jwk(key.public_key())), kid=kid, alg="RS256", use="sig")

    return client, service, public(client, "client-test"), public(service, "service-test")


def configurations(material):
    return tuple(
        ConfidentialServiceConfig(
            enabled=True,
            client_id=BACKEND,
            service_principal="service:social-mobile",
            issuer=ISSUER,
            token_endpoint_audience=ISSUER + TOKEN_PATH,
            service_resource_audience=ISSUER + PREFIX + "/" + group,
            client_jwks=(material[2],),
            service_jwks=(material[3],),
            service_scope=SCOPES[group],
            service_purpose=PURPOSES[group],
            clock_skew_seconds=0,
        )
        for group in GROUPS
    )


def runtime_for(material, factory, lifecycle=None, clock=None):
    lifecycle = lifecycle or SqlAlchemyOAuthSessionLifecycle(
        factory,
        client_id=VIEWER_CLIENT,
        token_config={"JWT_ISSUER": ISSUER, "JWKS_DIR": os.environ["JWKS_DIR"]},
    )
    return MobileAuthorizationIngress(
        configurations(material),
        material[1],
        "service-test",
        VIEWER_CLIENT,
        lifecycle,
        SqlAlchemyMobileAuthorizationService(factory, clock=clock),
        PostgresConfidentialServiceAssertionReplayStore(factory),
    )


def signed_service(material, group, **changes):
    now = int(time.time())
    config = configurations(material)[GROUPS.index(group)]
    claims = dict(
        iss=ISSUER,
        aud=config.service_resource_audience,
        sub=config.service_principal,
        azp=BACKEND,
        scope=config.service_scope,
        purpose=config.service_purpose,
        token_use="service_access",
        grant_type="client_credentials",
        iat=now,
        exp=now + 60,
        jti=uuid.uuid4().hex,
    )
    claims.update(changes)
    return jwt.encode(claims, material[1], algorithm="RS256", headers={"kid": "service-test"})


def client_assertion(material, **changes):
    now = int(time.time())
    claims = dict(
        iss=BACKEND,
        sub=BACKEND,
        aud=ISSUER + TOKEN_PATH,
        iat=now,
        exp=now + 60,
        jti=uuid.uuid4().hex,
        token_use="client_assertion",
        grant_type="client_credentials",
        purpose="service_client_authentication",
    )
    claims.update(changes)
    return jwt.encode(claims, material[0], algorithm="RS256", headers={"kid": "client-test"})


@pytest.fixture
def ingress(material):
    calls = []

    def factory():
        calls.append("database")
        raise RuntimeError("synthetic storage unavailable")

    runtime = runtime_for(material, factory)
    app = Flask(__name__)
    app.config["TESTING"] = True
    install_mobile_ingress(app, runtime, enabled=True)
    return app.test_client(), runtime, calls


def request_headers(material, group="desktop", viewer="synthetic.invalid.viewer"):
    headers = {"Authorization": "Bearer " + signed_service(material, group)}
    if group in {"desktop", "invalidate"}:
        headers[VIEWER_HEADER] = "Bearer " + viewer
    return headers


def test_default_factory_and_disabled_routes_are_absent(ingress):
    from app.factory import create_app

    app = create_app()
    assert all(not rule.rule.startswith(PREFIX) for rule in app.url_map.iter_rules())
    assert EXTENSION not in app.extensions
    app = Flask("disabled")
    assert install_mobile_ingress(app, ingress[1], enabled=False) is False
    assert app.test_client().post(PREFIX + "/qr/create", json={}).status_code == 404
    app = Flask("missing-composition")
    app.register_blueprint(internal_social_mobile_authorization_bp)
    response = app.test_client().post(PREFIX + "/qr/create", json={})
    assert response.status_code == 404
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "PUT"])
def test_only_explicit_post_methods(ingress, command, method):
    response = ingress[0].open(PREFIX + "/" + command, method=method)
    assert response.status_code == 405
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert not ingress[2]


@pytest.mark.parametrize(
    "raw",
    [
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":true}',
        b'{"x":1.5}',
        b'{"x":{}}',
        b'{"x":[]}',
        b"[]",
        b"null",
        b'"x"',
        b"\xff",
        b"\xef\xbb\xbf{}",
        b'{"subject":"' + b"a" * 64 + b'"}',
        b'{"session_id":"chosen"}',
        b'{"user_id":"chosen"}',
        b'{"desktopContext":"' + b"a" * 64 + b'"}',
        b'{"revision":"' + b"a" * 64 + b'"}',
        b'{"generation":"chosen"}',
        b'{"handoff":{}}',
        b"[" * 10000,
        b" " * MAX_BODY_BYTES + b"{}",
        b"{} trailing",
        rb'{"x":"\ud800"}',
    ],
)
def test_strict_schema_rejects_before_authority(ingress, raw):
    with pytest.raises(InvalidMobileRequest):
        command_body("qr/create", raw)
    response = ingress[0].post(PREFIX + "/qr/create", data=raw, content_type="application/json")
    assert response.status_code == 400
    assert response.get_json() == {"error": "invalid_request"}
    assert response.headers["Cache-Control"] == "no-store"
    assert not ingress[2]


@pytest.mark.parametrize(
    "changes",
    [
        {"scope": "social:full-directory:read"},
        {"scope": "*"},
        {"aud": ISSUER + "/internal/v1/social/full-directory"},
        {"purpose": "social_full_directory_read"},
        {"azp": "other-client"},
        {"sub": "other-service"},
        {"iss": "https://other.example"},
        {"token_use": "access"},
        {"exp": 1},
        {"iat": True},
    ],
)
def test_wrong_backend_claims_never_touch_database(ingress, material, changes):
    headers = request_headers(material)
    headers["Authorization"] = "Bearer " + signed_service(material, "desktop", **changes)
    response = ingress[0].post(PREFIX + "/qr/create", json={}, headers=headers)
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid_credential"}
    assert not ingress[2]


@pytest.mark.parametrize("group", GROUPS)
def test_mobile_tokens_cannot_be_full_directory_credentials(material, group):
    full = replace(
        configurations(material)[0],
        service_scope="social:full-directory:read",
        service_purpose="social_full_directory_read",
        service_resource_audience=ISSUER + "/internal/v1/social/full-directory",
    )
    with pytest.raises(CredentialDenied):
        verify_service_access_token(signed_service(material, group), config=full)


@pytest.mark.parametrize("command", COMMANDS)
def test_each_command_rejects_all_other_service_capabilities(ingress, material, command):
    for group in GROUPS:
        if group != COMMANDS[command][0]:
            with pytest.raises(CredentialDenied):
                ingress[1].authenticate(command, signed_service(material, group))
    assert not ingress[2]


@pytest.mark.parametrize("missing", ["Authorization", VIEWER_HEADER])
def test_both_credentials_required(ingress, material, missing):
    headers = request_headers(material)
    headers.pop(missing)
    response = ingress[0].post(PREFIX + "/qr/create", json={}, headers=headers)
    assert response.status_code == 401
    assert not ingress[2]


@pytest.mark.parametrize("change", ["query", "content-type", "encoding", "viewer-on-phone", "duplicate-header"])
def test_transport_ambiguity(ingress, material, change):
    path, body = PREFIX + "/qr/create", b"{}"
    headers = request_headers(material)
    content_type = "application/json"
    if change == "query":
        path += "?verifier=forbidden"
    elif change == "content-type":
        content_type = "text/plain"
    elif change == "encoding":
        headers["Content-Encoding"] = "gzip"
    elif change == "duplicate-header":
        headers["Authorization"] += ", duplicate"
    else:
        path = PREFIX + "/qr/offer"
        body = json.dumps({"qr": "hodlxxi-social-pair:v1:" + "a" * 64 + ":" + "b" * 64}).encode()
    response = ingress[0].post(path, data=body, content_type=content_type, headers=headers)
    assert response.status_code in {400, 401}
    assert not ingress[2]


def test_storage_failure_has_one_non_sensitive_contract(ingress, material):
    response = ingress[0].post(PREFIX + "/qr/create", json={}, headers=request_headers(material))
    assert response.status_code == 503
    assert response.get_json() == {"error": "mobile_authorization_unavailable"}
    assert response.headers["Cache-Control"] == "no-store"
    assert ingress[2] == ["database"]


def test_wrong_viewer_client_and_split_database_composition_fail_closed(ingress):
    with pytest.raises(MobileIngressConfigurationError):
        replace(ingress[1], viewer_client_id="other-client")
    with pytest.raises(MobileIngressConfigurationError):
        replace(ingress[1], mobile=SqlAlchemyMobileAuthorizationService(lambda: None))


def test_context_is_recovered_then_real_command_receives_same_context(ingress, material, monkeypatch):
    runtime = ingress[1]
    owner = OAuthSessionAuthority("internal-session", "a" * 64)
    monkeypatch.setattr(runtime.lifecycle, "resolve", lambda _value: owner)
    received = []

    def original(operation, **kwargs):
        received.append((operation, kwargs))
        return "b" * 64

    def status(operation, **kwargs):
        received.append((operation, kwargs))
        return '{"authorizationDigest":null,"status":"created"}'

    monkeypatch.setattr(runtime.mobile, "original_context", original)
    monkeypatch.setattr(runtime.mobile, "status", status)
    response = ingress[0].post(PREFIX + "/qr/status", json={"pairingId": "c" * 64}, headers=request_headers(material))
    assert response.status_code == 200
    assert received[0][1]["session_id"] == owner.session_id
    assert received[1][1]["context_id"] == "b" * 64
    assert set(response.get_json()) == {"status", "authorizationDigest"}


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize(
    "override",
    ["subject", "session_id", "user_id", "token_id", "browserGeneration", "loginContext", "desktopContext", "handoff"],
)
def test_every_operation_rejects_unsigned_authority_overrides(ingress, command, override):
    fields = COMMANDS[command][1]
    samples = dict(
        content="{}",
        source="{}",
        proof="{}",
        operationId="00000000-0000-4000-8000-000000000000",
        qr="hodlxxi-social-pair:v1:" + "a" * 64 + ":" + "b" * 64,
        humanCode="AAAA-BBBB-CCCC",
        status="cancelled",
    )
    body = {name: samples.get(name, "a" * 64) for name in fields}
    body[override] = "a" * 64
    response = ingress[0].post(PREFIX + "/" + command, json=body)
    assert response.status_code == 400
    assert not ingress[2]


def test_service_signature_and_viewer_cannot_substitute_for_backend(ingress, material):
    token = signed_service(material, "desktop")
    parts = token.split(".")
    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    headers = request_headers(material)
    for invalid in (".".join(parts), "synthetic.invalid.viewer"):
        headers["Authorization"] = "Bearer " + invalid
        response = ingress[0].post(PREFIX + "/qr/create", json={}, headers=headers)
        assert response.status_code == 401
    assert not ingress[2]


@pytest.mark.parametrize("change", ["audience", "client", "scope", "signature"])
def test_service_token_issuance_denies_before_replay_database(ingress, material, change):
    changes = {"aud": ISSUER + "/internal/v1/social/service-token"} if change == "audience" else {}
    if change == "client":
        changes["iss"] = "different-backend"
    assertion = client_assertion(material, **changes)
    if change == "signature":
        pieces = assertion.split(".")
        pieces[2] = ("A" if pieces[2][0] != "A" else "B") + pieces[2][1:]
        assertion = ".".join(pieces)
    response = ingress[0].post(
        TOKEN_PATH,
        data=dict(
            grant_type="client_credentials",
            client_id=BACKEND,
            client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion=assertion,
            scope="social:full-directory:read" if change == "scope" else SCOPES["desktop"],
        ),
    )
    assert response.status_code == 401
    assert not ingress[2]
