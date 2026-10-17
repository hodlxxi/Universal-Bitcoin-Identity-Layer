"""Real service signatures and Flask dispatch; native owners use explicit SQLite doubles."""

import ast
import json
import time
import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask
from jwt.algorithms import RSAAlgorithm

from app.services import social_enrollment_v2_ingress as ingress
from app.services import social_enrollment_v2_ingress_schema as schema
from app.services.confidential_service_assertion_replay_storage import PostgresConfidentialServiceAssertionReplayStore
from app.services.confidential_service_credentials import ConfidentialServiceConfig, CredentialDenied
from app.services.social_enrollment_v2_authenticated_composition import AuthenticatedEnrollmentV2Composition
from app.services.social_enrollment_v2_challenge import (
    CommittedEnrollmentChallenge,
    EnrollmentChallengeConfig,
    EnrollmentV2ChallengeComposition,
)
from app.services.social_enrollment_v2_runtime_composition import (
    CommittedFinalization,
    CommittedReservation,
    EnrollmentCompositionUnavailable,
    SocialEnrollmentV2Composition,
)
from tests.unit.test_social_enrollment_v2_ingress_schema import body

ISSUER = "https://ubid.example"


@pytest.fixture(scope="module")
def keys():
    client = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    service = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def public(key, kid):
        return dict(json.loads(RSAAlgorithm.to_jwk(key.public_key())), kid=kid, use="sig", alg="RS256")

    return client, service, public(client, "client-test"), public(service, "service-test")


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


def service_token(keys, command="challenge", **changed):
    at = int(time.time())
    cfg = configs(keys)[tuple(schema.COMMANDS).index(command)]
    claims = dict(
        iss=ISSUER,
        aud=cfg.service_resource_audience,
        sub=cfg.service_principal,
        azp=cfg.client_id,
        scope=cfg.service_scope,
        purpose=cfg.service_purpose,
        token_use="service_access",
        grant_type="client_credentials",
        iat=at,
        exp=at + 60,
        jti=uuid.uuid4().hex,
    )
    claims.update(changed)
    return jwt.encode(claims, keys[1], algorithm="RS256", headers={"kid": "service-test"})


def assertion(keys, **changed):
    at = int(time.time())
    claims = dict(
        iss="backend",
        sub="backend",
        aud=ISSUER + schema.TOKEN_PATH,
        iat=at,
        exp=at + 60,
        jti=uuid.uuid4().hex,
        token_use="client_assertion",
        grant_type="client_credentials",
        purpose="service_client_authentication",
    )
    claims.update(changed)
    return jwt.encode(claims, keys[0], algorithm="RS256", headers={"kid": "client-test"})


@pytest.fixture
def http(keys, monkeypatch):
    calls, consumed = [], set()

    def factory():
        calls.append("unexpected-database")
        raise AssertionError("no native database in HTTP-only fixture")

    # HTTP-only adapter doubles have the exact production port classes. Real
    # construction/owner and actual commits are covered separately below.
    challenge = object.__new__(EnrollmentV2ChallengeComposition)
    challenge.config = EnrollmentChallengeConfig(
        enabled=True,
        client_id="social-client",
        backend_id="backend",
        service_principal="principal",
        issuer=ISSUER,
        audience="https://social.example",
    )
    challenge._factory = factory
    operations = object.__new__(AuthenticatedEnrollmentV2Composition)
    ec = SimpleNamespace(client_id="social-client", service_principal="principal", issuer=ISSUER)
    operations.composition = SimpleNamespace(
        _config=SimpleNamespace(
            reservation_config=SimpleNamespace(
                evidence_config=ec, backend_id="backend", verification_audience="https://social.example"
            )
        )
    )
    replay = PostgresConfidentialServiceAssertionReplayStore(factory)

    def consume(_self, jti, deadline):
        if jti in consumed:
            return False
        consumed.add(jti)
        calls.append("assertion-consumed")
        return True

    monkeypatch.setattr(PostgresConfidentialServiceAssertionReplayStore, "__call__", consume)
    runtime = ingress.EnrollmentV2Ingress(configs(keys), keys[1], "service-test", challenge, operations, replay)

    def challenged(_self, issuance_id, *, viewer_bearer):
        calls.append(("challenge", issuance_id, viewer_bearer))
        return CommittedEnrollmentChallenge("context", "enrollment", "approval", 10, 20)

    def reserved(_self, input_wire, *, issuance_id, viewer_bearer):
        calls.append(("reserve", input_wire, issuance_id, viewer_bearer))
        return CommittedReservation("evidence", "b" * 64, 10, 20)

    def finalized(_self, *, viewer_bearer, **arguments):
        calls.append(("finalize", arguments, viewer_bearer))
        return CommittedFinalization("receipt", True)

    monkeypatch.setattr(EnrollmentV2ChallengeComposition, "challenge", challenged)
    monkeypatch.setattr(AuthenticatedEnrollmentV2Composition, "reserve", reserved)
    monkeypatch.setattr(AuthenticatedEnrollmentV2Composition, "finalize", finalized)
    app = Flask("synthetic-enrollment-ingress")
    app.config["TESTING"] = True
    ingress.install_enrollment_v2_ingress(app, runtime, enabled=True)
    return SimpleNamespace(client=app.test_client(), app=app, runtime=runtime, calls=calls, consumed=consumed)


def headers(keys, command="challenge", **changes):
    value = {
        "Authorization": "Bearer " + service_token(keys, command),
        schema.VIEWER_HEADER: "Bearer phone.exact.token",
    }
    value.update(changes)
    return value


def post(http, keys, command="challenge", **options):
    options.setdefault("headers", headers(keys, command))
    options.setdefault("data", json.dumps(body(command)))
    options.setdefault("content_type", "application/json")
    return http.client.post(schema.PREFIX + "/" + command, **options)


def test_default_off_installs_nothing_and_literal_enable_required(http):
    app = Flask("disabled-enrollment")
    assert ingress.install_enrollment_v2_ingress(app, None) is False
    assert ingress.EXTENSION not in app.extensions
    assert not any(rule.rule.startswith(schema.PREFIX) for rule in app.url_map.iter_rules())
    for enabled in (1, "true", None):
        with pytest.raises(ingress.EnrollmentIngressUnavailable):
            ingress.install_enrollment_v2_ingress(app, http.runtime, enabled=enabled)
    with pytest.raises(ingress.EnrollmentIngressUnavailable):
        ingress.install_enrollment_v2_ingress(http.app, http.runtime, enabled=True)


def test_default_factory_has_no_enrollment_install_or_import():
    root = Path(__file__).resolve().parents[2]
    tree = ast.parse((root / "app/factory.py").read_text())
    imports = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert all("social_enrollment_v2" not in name for name in imports)
    assert not ingress.RUNTIME_ENABLED and not ingress.DM_TRANSPORT_ENABLED


def test_real_service_tokens_dispatch_all_three_exact_payloads(http, keys):
    for command in schema.COMMANDS:
        response = post(http, keys, command)
        assert response.status_code == 200
        result = response.get_json()
        assert result["publicationStatus"] == "committed" and result["finalAdmission"] == "denied"
        assert result["bearerAuthority"] == "none"
        assert "access_token" not in result
        assert response.headers["Cache-Control"] == "no-store" and response.headers["Pragma"] == "no-cache"
    assert len(http.calls) == 3
    assert http.calls[1][1] == body("reserve")["verificationInputWire"]
    assert http.calls[2][1]["reservation_revision"] == 1


def test_service_scope_cannot_cross_commands(http, keys):
    for source in schema.COMMANDS:
        for target in schema.COMMANDS:
            if source != target:
                assert post(http, keys, target, headers=headers(keys, source)).status_code == 401
    assert not http.calls


def test_wrong_service_identity_audience_purpose_signature_or_expiry_before_database(http, keys):
    for changes in (
        {"aud": ISSUER + "/other"},
        {"purpose": "other"},
        {"azp": "other"},
        {"sub": "other"},
        {"iss": "https://other.example"},
        {"exp": int(time.time()), "iat": int(time.time()) - 1},
    ):
        h = headers(keys)
        h["Authorization"] = "Bearer " + service_token(keys, **changes)
        assert post(http, keys, headers=h).status_code == 401
    h = headers(keys)
    token = h["Authorization"]
    offset = token.rfind(".") + 1
    h["Authorization"] = token[:offset] + ("a" if token[offset] != "a" else "b") + token[offset + 1 :]
    assert post(http, keys, headers=h).status_code == 401
    assert not http.calls


def test_phone_header_is_required_and_no_ambiguous_bearer(http, keys):
    for value in (None, "", "Bearer x,y", "Bearer  x", "Bearer x y"):
        h = headers(keys)
        if value is None:
            del h[schema.VIEWER_HEADER]
        else:
            h[schema.VIEWER_HEADER] = value
        assert post(http, keys, headers=h).status_code == 401
    assert not http.calls


def test_query_media_encoding_and_transfer_ambiguity_denied_without_dispatch(http, keys):
    for options in (
        {"query_string": "clock=1"},
        {"content_type": "application/json; charset=utf-8"},
        {"headers": headers(keys, **{"Content-Encoding": "gzip"})},
        {"headers": headers(keys, **{"Transfer-Encoding": "chunked"})},
    ):
        assert post(http, keys, **options).status_code == 400
    assert not http.calls


def test_bad_body_cannot_select_identity_clock_profile_or_revision(http, keys):
    for command, raw in (
        ("challenge", dict(body("challenge"), clock="1")),
        ("reserve", dict(body("reserve"), subject="chosen")),
        ("finalize", dict(body("finalize"), reservationRevision="2")),
    ):
        assert post(http, keys, command, data=json.dumps(raw)).status_code == 400
    assert not http.calls


def test_get_head_options_redirect_and_unknown_routes_are_not_commands(http, keys):
    for name in (*schema.COMMANDS, "service-token"):
        for method in ("GET", "HEAD", "OPTIONS", "PUT"):
            response = http.client.open(schema.PREFIX + "/" + name, method=method)
            assert response.status_code == 405 and response.headers["Cache-Control"] == "no-store"
    for suffix in ("/chosen", "/challenge/"):
        response = http.client.post(schema.PREFIX + suffix, follow_redirects=False)
        assert response.status_code == 404 and response.headers["Cache-Control"] == "no-store"
    assert not http.calls


def test_response_errors_are_non_sensitive_and_never_cacheable(http, keys, monkeypatch):
    def failed(*args, **kwargs):
        raise RuntimeError("synthetic-private-marker")

    monkeypatch.setattr(EnrollmentV2ChallengeComposition, "challenge", failed)
    response = post(http, keys)
    assert response.status_code == 503 and "synthetic-private-marker" not in response.get_data(as_text=True)
    assert response.headers["Cache-Control"] == "no-store"


def test_uncommitted_or_untyped_result_never_published(http, keys, monkeypatch):
    monkeypatch.setattr(EnrollmentV2ChallengeComposition, "challenge", lambda *a, **kw: {"committed": True})
    assert post(http, keys).status_code == 503


def test_missing_extension_denies_even_if_blueprint_registered():
    from app.blueprints.internal_social_enrollment_v2 import internal_social_enrollment_v2_bp

    app = Flask("missing-enrollment-runtime")
    app.register_blueprint(internal_social_enrollment_v2_bp)
    response = app.test_client().post(schema.PREFIX + "/challenge", json=body("challenge"))
    assert response.status_code == 404 and response.headers["Cache-Control"] == "no-store"


def token_fields(keys, **changes):
    value = dict(
        grant_type="client_credentials",
        client_id="backend",
        client_assertion_type=schema.ASSERTION_TYPE,
        client_assertion=assertion(keys),
        scope=schema.SCOPES["challenge"],
    )
    value.update(changes)
    return value


def test_real_private_key_assertion_and_replay_consumer_issue_scoped_service_token(http, keys):
    fields = token_fields(keys)
    first = http.client.post(
        schema.TOKEN_PATH, data=urlencode(fields), content_type="application/x-www-form-urlencoded"
    )
    assert first.status_code == 200
    encoded = first.get_json()["access_token"]
    http.runtime.authenticate("challenge", encoded)
    with pytest.raises(CredentialDenied):
        http.runtime.authenticate("finalize", encoded)
    again = http.client.post(
        schema.TOKEN_PATH, data=urlencode(fields), content_type="application/x-www-form-urlencoded"
    )
    assert again.status_code == 503 and len(http.consumed) == 1


def test_invalid_assertion_scope_or_mixed_credential_never_consumes_replay(http, keys):
    cases = [
        (token_fields(keys, client_assertion=assertion(keys, aud=ISSUER + "/other")), {}),
        (token_fields(keys, scope="other"), {}),
        (token_fields(keys), {schema.VIEWER_HEADER: "Bearer phone.token.value"}),
        (token_fields(keys), {"Authorization": "Bearer extra.credential.value"}),
    ]
    for fields, h in cases:
        response = http.client.post(
            schema.TOKEN_PATH, data=urlencode(fields), content_type="application/x-www-form-urlencoded", headers=h
        )
        assert response.status_code in (400, 401)
    assert not http.consumed and not http.calls


def test_configuration_rejects_conflicting_principal_purpose_replay_and_zero_skew(http):
    first = http.runtime.service_configs[0]
    for changed in (
        replace(first, service_principal="other"),
        replace(first, service_purpose="other"),
        replace(first, clock_skew_seconds=1),
    ):
        with pytest.raises(ingress.EnrollmentIngressUnavailable):
            replace(http.runtime, service_configs=(changed, *http.runtime.service_configs[1:]))
    with pytest.raises(ingress.EnrollmentIngressUnavailable):
        replace(http.runtime, replay=PostgresConfidentialServiceAssertionReplayStore(lambda: None))


def test_service_expiry_during_completed_operation_does_not_publish(http, keys, monkeypatch):
    start = int(time.time())
    at = [start]
    monkeypatch.setattr(ingress.time, "time", lambda: at[0])
    original = EnrollmentV2ChallengeComposition.challenge

    def completed(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        at[0] = start + 60
        return result

    monkeypatch.setattr(EnrollmentV2ChallengeComposition, "challenge", completed)
    response = post(http, keys)
    assert response.status_code == 401 and len(http.calls) == 1


def test_schema_bounds_match_the_real_signed_protocol_consumers():
    from app.services import social_messaging_device_verification_deadline_evidence_v1 as evidence
    from app.services import social_messaging_mobile_pre_enrollment_v2 as v2
    from app.services import social_preaccepted_enrollment_verification_statement_v2 as statement

    assert schema.WIRE_LIMITS == {
        "verificationInputWire": v2.MAX_VERIFICATION_INPUT_BYTES,
        "evidenceCompactJws": evidence.MAX_EVIDENCE_BYTES,
        "statementCompactJws": statement.MAX_STATEMENT_BYTES,
    }


def real_operations(graph):
    from app.services.social_enrollment_v2_reservation_signer import DedicatedRS256EvidenceSigner
    from tests.unit.test_social_enrollment_v2_finalization import FinalSession

    def factory():
        return FinalSession(graph)

    phone = graph.issue()["viewerAccessToken"]
    graph.lifecycle._factory = factory
    composition = SocialEnrollmentV2Composition(
        session_factory=factory,
        signer=DedicatedRS256EvidenceSigner(private_key=graph.evidence_key, config=graph.config),
        config=graph.final_config,
        clock=lambda: int(graph.now.timestamp() * 1000),
    )
    return AuthenticatedEnrollmentV2Composition(composition=composition, lifecycle=graph.lifecycle), phone


def test_real_reservation_phone_binding_and_byte_identical_retry(monkeypatch):
    from tests.unit.test_social_enrollment_v2_runtime_composition import _real_graph

    with _real_graph(monkeypatch) as graph:
        operations, phone = real_operations(graph)
        first = operations.reserve(graph.input_wire, issuance_id=graph.issuance_id, viewer_bearer=phone)
        again = operations.reserve(graph.input_wire, issuance_id=graph.issuance_id, viewer_bearer=phone)
        assert first == again and first.evidence_compact_jws == graph.reservation.evidence_compact_jws
        with pytest.raises(EnrollmentCompositionUnavailable):
            operations.reserve(graph.input_wire, issuance_id=graph.issuance_id, viewer_bearer=graph.desktop)
        assert len(graph.rows()) == 1


def test_real_http_reservation_finalization_checks_phone_and_recovers_original(monkeypatch, keys):
    from copy import copy

    from tests.unit.test_social_enrollment_v2_finalization import FinalSession
    from tests.unit.test_social_enrollment_v2_runtime_composition import _real_graph

    with _real_graph(monkeypatch) as graph:
        operations, phone = real_operations(graph)
        writer_lifecycle = copy(graph.lifecycle)

        def writer_factory():
            return FinalSession(graph)

        writer_lifecycle._factory = writer_factory
        cc = EnrollmentChallengeConfig(
            enabled=True,
            client_id=graph.config.evidence_config.client_id,
            backend_id=graph.config.backend_id,
            service_principal=graph.config.evidence_config.service_principal,
            issuer=graph.config.evidence_config.issuer,
            audience=graph.config.verification_audience,
        )
        challenge = EnrollmentV2ChallengeComposition(
            lifecycle=writer_lifecycle, config=cc, clock=lambda: int(graph.now.timestamp() * 1000)
        )
        runtime = ingress.EnrollmentV2Ingress(
            configs(keys),
            keys[1],
            "service-test",
            challenge,
            operations,
            PostgresConfidentialServiceAssertionReplayStore(writer_factory),
        )
        app = Flask("real-owners-through-http")
        ingress.install_enrollment_v2_ingress(app, runtime, enabled=True)
        client = app.test_client()
        raw = dict(
            issuanceId=graph.issuance_id,
            reservationId=graph.reservation.reservation_id,
            reservationRevision="1",
            verificationInputWire=graph.input_wire,
            evidenceCompactJws=graph.reservation.evidence_compact_jws,
            statementCompactJws=graph.statement,
        )

        def send(bearer):
            h = headers(keys, "finalize")
            h[schema.VIEWER_HEADER] = "Bearer " + bearer
            return client.post(
                schema.PREFIX + "/finalize", data=json.dumps(raw), content_type="application/json", headers=h
            )

        assert send(graph.desktop).status_code == 503
        assert not graph.calls and graph.rows()[0]._mapping["state"] == "pending"
        h = headers(keys, "reserve")
        h[schema.VIEWER_HEADER] = "Bearer " + phone
        pending = client.post(
            schema.PREFIX + "/reserve",
            data=json.dumps(dict(issuanceId=graph.issuance_id, verificationInputWire=graph.input_wire)),
            content_type="application/json",
            headers=h,
        )
        assert pending.status_code == 200
        assert pending.get_json()["evidenceCompactJws"] == graph.reservation.evidence_compact_jws
        first = send(phone)
        assert first.status_code == 200
        original_effects = tuple(graph.calls)
        retry = send(phone)
        assert retry.status_code == 200
        first, retry = first.get_json(), retry.get_json()
        assert not first["historicalRecovery"] and retry["historicalRecovery"]
        assert first["receiptWire"] == retry["receiptWire"] and tuple(graph.calls) == original_effects
        assert retry["finalAdmission"] == "denied"


def test_real_invalid_phone_or_wrong_issuance_never_commits_effects(monkeypatch):
    from tests.unit.test_social_enrollment_v2_runtime_composition import _real_graph

    with _real_graph(monkeypatch) as graph:
        operations, phone = real_operations(graph)
        for bearer, issuance in (("invalid", graph.issuance_id), (phone, "f" * 64)):
            arguments = dict(graph.arguments(), issuance_id=issuance)
            with pytest.raises(EnrollmentCompositionUnavailable):
                operations.finalize(viewer_bearer=bearer, **arguments)
        assert not graph.calls and graph.rows()[0]._mapping["state"] == "pending"


def test_real_phone_revocation_after_effects_rolls_back_all_writes(monkeypatch):
    from sqlalchemy import select, update

    from app.models import OAuthToken
    from app.services import social_messaging_device_verification_deadline_evidence_v1 as evidence
    from tests.unit.test_social_enrollment_v2_runtime_composition import _real_graph

    with _real_graph(monkeypatch) as graph:
        operations, phone = real_operations(graph)
        authentic = evidence.verify_messaging_device_verification_deadline_evidence_v1(
            graph.reservation.evidence_compact_jws,
            config=graph.config.evidence_config,
            expected_input_wire=graph.input_wire,
            now=graph.reservation.observed_at,
        )
        token_id = authentic.claims.social_session_token_id
        original = operations._evidence_phone
        calls = [0]

        def revoke(authority, *args, **kwargs):
            calls[0] += 1
            if calls[0] == 2:
                authority.guard.connection.execute(
                    update(OAuthToken).where(OAuthToken.id == token_id).values(is_revoked=True)
                )
            return original(authority, *args, **kwargs)

        monkeypatch.setattr(operations, "_evidence_phone", revoke)
        with pytest.raises(EnrollmentCompositionUnavailable):
            operations.finalize(viewer_bearer=phone, **graph.arguments())
        assert graph.rows()[0]._mapping["state"] == "pending"
        with graph.engine.connect() as connection:
            assert (
                connection.execute(select(OAuthToken.is_revoked).where(OAuthToken.id == token_id)).scalar_one() is False
            )


def test_real_phone_expiry_has_no_leeway_at_publication(monkeypatch):
    from app.services.oauth_bearer_validation import BearerPrincipal
    from tests.unit.test_social_enrollment_v2_runtime_composition import _real_graph

    with _real_graph(monkeypatch) as graph:
        operations, phone = real_operations(graph)
        original = graph.lifecycle._validate

        def exclusive(port, bearer):
            viewer = original(port, bearer)
            assert type(viewer) is BearerPrincipal
            return replace(viewer, expires_at=graph.now.replace(tzinfo=None))

        monkeypatch.setattr(graph.lifecycle, "_validate", exclusive)
        with pytest.raises(EnrollmentCompositionUnavailable):
            operations.finalize(viewer_bearer=phone, **graph.arguments())
        assert not graph.calls


def test_real_authenticated_composition_cannot_mix_session_factories(monkeypatch):
    from tests.unit.test_social_enrollment_v2_finalization import FinalSession
    from tests.unit.test_social_enrollment_v2_runtime_composition import _real_graph

    with _real_graph(monkeypatch) as graph:
        operations, _phone = real_operations(graph)
        graph.lifecycle._factory = lambda: FinalSession(graph)
        with pytest.raises(EnrollmentCompositionUnavailable):
            AuthenticatedEnrollmentV2Composition(composition=operations.composition, lifecycle=graph.lifecycle)
