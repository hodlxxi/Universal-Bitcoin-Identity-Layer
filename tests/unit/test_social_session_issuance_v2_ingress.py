"""Real service crypto and Flask, explicit non-native owner/replay HTTP doubles."""

import json
import time
import uuid
from dataclasses import replace
from types import SimpleNamespace
from urllib.parse import urlencode

import jwt
import pytest
from flask import Flask

from app.services import social_session_issuance_v2_ingress as ingress
from app.services import social_session_issuance_v2_schema as schema
from app.services.confidential_service_assertion_replay_storage import PostgresConfidentialServiceAssertionReplayStore
from app.services.confidential_service_credentials import ConfidentialServiceConfig, CredentialDenied
from app.services.oauth_session_lifecycle import SqlAlchemyOAuthSessionLifecycle
from app.services.social_session_issuance_v2 import NativeV2SessionIssuer
from app.services.social_session_issuance_v2_contract import V2IssuanceUnavailable
from tests.unit.test_social_enrollment_v2_ingress import keys

ISSUER = "https://ubid.example"


def configs(keys):
    return tuple(
        ConfidentialServiceConfig(
            enabled=True,
            issuer=ISSUER,
            client_id="backend",
            service_principal="principal",
            token_endpoint_audience=ISSUER + schema.TOKEN_PATH,
            service_resource_audience=ISSUER + schema.PREFIX + "/" + name,
            client_jwks=(keys[2],),
            service_jwks=(keys[3],),
            service_scope=schema.SCOPES[name],
            service_purpose=schema.PURPOSES[name],
            clock_skew_seconds=0,
        )
        for name in schema.COMMANDS
    )


def signed(keys, command="offer", *, assertion=False, **changes):
    at = int(time.time())
    if assertion:
        payload = dict(
            iss="backend",
            sub="backend",
            aud=ISSUER + schema.TOKEN_PATH,
            token_use="client_assertion",
            purpose="service_client_authentication",
            grant_type="client_credentials",
        )
    else:
        payload = dict(
            iss=ISSUER,
            sub="principal",
            azp="backend",
            aud=ISSUER + schema.PREFIX + "/" + command,
            token_use="service_access",
            purpose=schema.PURPOSES[command],
            scope=schema.SCOPES[command],
            grant_type="client_credentials",
        )
    payload.update(iat=at, exp=at + 60, jti=uuid.uuid4().hex)
    payload.update(changes)
    return jwt.encode(
        payload,
        keys[0 if assertion else 1],
        algorithm="RS256",
        headers={"kid": "client-test" if assertion else "service-test"},
    )


def body(command):
    return {name: "{}" if name.endswith("Wire") else "a" * 64 for name in schema.COMMANDS[command]}


@pytest.fixture
def http(keys, monkeypatch):
    calls, used = [], set()

    def factory():
        raise AssertionError("HTTP-only fixture must never open a database")

    lifecycle = SqlAlchemyOAuthSessionLifecycle(
        factory, client_id="social-client", token_config={"JWT_ISSUER": ISSUER, "JWKS_DIR": "injected-only"}
    )
    owner = NativeV2SessionIssuer(lifecycle=lifecycle, backend_id="backend", principal="principal")
    replay = PostgresConfidentialServiceAssertionReplayStore(factory)

    def consume(_self, jti, deadline):
        if jti in used:
            return False
        used.add(jti)
        return True

    monkeypatch.setattr(PostgresConfidentialServiceAssertionReplayStore, "__call__", consume)
    for name, method in {
        "offer": "create_offer",
        "issue": "issue",
        "recover": "recover",
        "resolve": "resolve",
        "revoke": "revoke",
    }.items():

        def operation(_self, *args, _command=name, **kwargs):
            calls.append((_command, args, kwargs))
            return args[0] if _command == "offer" else dict(synthetic=True)

        monkeypatch.setattr(NativeV2SessionIssuer, method, operation)
    runtime = ingress.NativeV2SessionIngress(configs(keys), keys[1], "service-test", owner, replay)
    app = Flask("synthetic-native-session-ingress")
    app.config["TESTING"] = True
    assert ingress.install_native_v2_session_ingress(app, runtime, enabled=True)
    return SimpleNamespace(app=app, client=app.test_client(), runtime=runtime, calls=calls)


def post(http, keys, command, **options):
    headers = {"Authorization": "Bearer " + signed(keys, command)}
    if command in schema.VIEWER_COMMANDS:
        headers[schema.VIEWER_HEADER] = "Bearer original.exact.viewer"
    options.setdefault("headers", headers)
    options.setdefault("data", json.dumps(body(command)))
    options.setdefault("content_type", "application/json")
    return http.client.post(schema.PREFIX + "/" + command, **options)


@pytest.mark.parametrize("command", tuple(schema.COMMANDS))
def test_real_service_crypto_dispatches_exact_closed_command(http, keys, command):
    response = post(http, keys, command)
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    assert http.calls[-1][0] == command
    if command == "recover":
        assert "approver_bearer" not in http.calls[-1][2]


def test_service_assertion_replay_and_distinct_command_scope(http, keys):
    form = dict(
        grant_type="client_credentials",
        client_id="backend",
        client_assertion_type=schema.ASSERTION_TYPE,
        client_assertion=signed(keys, assertion=True),
        scope=schema.SCOPES["offer"],
    )
    response = http.client.post(
        schema.TOKEN_PATH, data=urlencode(form), content_type="application/x-www-form-urlencoded"
    )
    assert response.status_code == 200
    again = http.client.post(schema.TOKEN_PATH, data=urlencode(form), content_type="application/x-www-form-urlencoded")
    assert again.status_code == 503
    assert again.get_json() == {"error": "social_session_issuance_v2_unavailable"}
    assert again.headers["Cache-Control"] == "no-store"
    assert not http.calls
    token = response.get_json()["access_token"]
    assert (
        post(
            http,
            keys,
            "issue",
            headers={"Authorization": "Bearer " + token, schema.VIEWER_HEADER: "Bearer original.exact.viewer"},
        ).status_code
        == 401
    )
    assert not http.calls


def test_wrong_service_bearer_denies_before_any_participant_work(http, keys):
    assert (
        post(
            http,
            keys,
            "offer",
            headers={"Authorization": "Bearer bad.exact.token", schema.VIEWER_HEADER: "Bearer original.exact.viewer"},
        ).status_code
        == 401
    )
    assert not http.calls


def test_recover_rejects_extra_viewer_header_and_any_non_none_direct_value(http, keys):
    assert (
        post(
            http,
            keys,
            "recover",
            headers={
                "Authorization": "Bearer " + signed(keys, "recover"),
                schema.VIEWER_HEADER: "Bearer extra.exact.token",
            },
        ).status_code
        == 400
    )
    for extra in ("extra.exact.token", False, 0, {}):
        with pytest.raises(CredentialDenied):
            http.runtime.execute("recover", body("recover"), service_token=signed(keys, "recover"), viewer_token=extra)
    assert not http.calls


@pytest.mark.parametrize("command", tuple(schema.VIEWER_COMMANDS))
def test_missing_original_viewer_denies_before_owner(http, keys, command):
    assert post(http, keys, command, headers={"Authorization": "Bearer " + signed(keys, command)}).status_code == 401
    assert not http.calls


@pytest.mark.parametrize(
    "raw",
    [
        '{"authorizationWire":"{}","extra":"x"}',
        '{"authorizationWire":"{}","authorizationWire":"{}"}',
        '{"authorizationWire":1}',
        '{"authorizationWire":"\\n"}',
    ],
)
def test_ambiguous_or_request_selected_authority_denied(http, keys, raw):
    assert post(http, keys, "offer", data=raw).status_code == 400
    assert not http.calls


def test_installer_default_off_and_owner_factory_replacement_denies(http, keys):
    app = Flask("disabled-session-ingress")
    assert ingress.install_native_v2_session_ingress(app, None) is False
    assert len(app.url_map._rules) == 1
    http.runtime.owner.lifecycle._factory = lambda: None
    assert post(http, keys, "offer").status_code == 503
    assert not http.calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("clock_skew_seconds", 1),
        ("service_purpose", "other"),
        ("client_id", "other"),
        ("service_resource_audience", ISSUER + "/wrong"),
    ],
)
def test_config_cannot_mix_service_scopes_and_owner_identity(http, keys, field, value):
    altered = (replace(configs(keys)[0], **{field: value}), *configs(keys)[1:])
    with pytest.raises(V2IssuanceUnavailable):
        ingress.NativeV2SessionIngress(altered, keys[1], "service-test", http.runtime.owner, http.runtime.replay)


def test_service_expiry_after_owner_return_discards_delivery(http, keys, monkeypatch):
    token = signed(keys, "offer")
    original = NativeV2SessionIssuer.create_offer

    def delayed(owner, *args, **kwargs):
        value = original(owner, *args, **kwargs)
        monkeypatch.setattr(ingress.time, "time", lambda: jwt.decode(token, options={"verify_signature": False})["exp"])
        return value

    monkeypatch.setattr(NativeV2SessionIssuer, "create_offer", delayed)
    assert (
        post(
            http,
            keys,
            "offer",
            headers={"Authorization": "Bearer " + token, schema.VIEWER_HEADER: "Bearer original.exact.viewer"},
        ).status_code
        == 401
    )
    assert len(http.calls) == 1
