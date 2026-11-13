"""Trusted assembly, real RSA/public registries, direct-role pin and installation."""

import json
import os
from copy import deepcopy
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask
from jwt.algorithms import RSAAlgorithm
from sqlalchemy.engine import Engine

from app.services import social_enrollment_v2_runtime as runtime
from app.services import social_messaging_device_verification_deadline_evidence_v1 as evidence
from app.services.social_enrollment_v2_reservation_contract import dedicated_reservation_key_id


@pytest.fixture(scope="module")
def keys():
    return tuple(rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(5))


@pytest.fixture
def configured(tmp_path, monkeypatch, keys):
    evidence_key, statement, client, service, token = keys

    def public(key, kid):
        value = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
        return {"kty": value["kty"], "n": value["n"], "e": value["e"], "kid": kid, "alg": "RS256", "use": "sig"}

    def pem(key, name):
        path = tmp_path / name
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
        path.chmod(0o600)
        return str(path)

    def jwks(key, kid, name):
        path = tmp_path / name
        path.mkdir()
        (path / "jwks.json").write_text(json.dumps({"keys": [public(key, kid)]}))
        return str(path)

    before, after = 1_000_000_000_000, 2_000_000_000_000
    ej = public(evidence_key, "temporary")
    ej["kid"] = dedicated_reservation_key_id(
        key_fingerprint=evidence._public_key(ej).fingerprint, trust_revision=1, not_before=before, not_after=after
    )
    credentials_path = str(tmp_path / "credentials.json")
    credentials = dict(
        schema=runtime.CREDENTIAL_SCHEMA,
        database="synthetic_runtime",
        host="127.0.0.1",
        port=55444,
        roles={
            name: dict(username=name, password="synthetic-password-no-connection-" + name)
            for name in ("synthetic_writer", "synthetic_finalizer")
        },
    )
    monkeypatch.setattr(
        runtime,
        "read_operator_json",
        lambda path: deepcopy(credentials) if path == credentials_path else pytest.fail("unexpected credential path"),
    )
    monkeypatch.setattr(
        Engine, "connect", lambda *_args, **_kwargs: pytest.fail("assembly opened a database connection")
    )
    cfg = dict(
        JWT_ISSUER="https://identity.example",
        JWKS_DIR=jwks(token, "viewer", "viewer"),
        SOCIAL_MOBILE_AUTHORIZATION_VIEWER_OAUTH_CLIENT_ID="viewer-client",
        SOCIAL_SESSION_ISSUANCE_BACKEND_ID="social-backend",
        SOCIAL_SESSION_ISSUANCE_SERVICE_PRINCIPAL="service:social",
    )
    manifest = dict(
        schema=runtime.SCHEMA,
        version=1,
        enabled=True,
        databaseCredentialsPath=credentials_path,
        challengeWriter=dict(roleName="synthetic_writer", roleOid=20001),
        finalizer=dict(roleName="synthetic_finalizer", roleOid=20002),
        socialOrigin="https://social.example",
        service=dict(
            clientJwksDir=jwks(client, "client", "client"),
            serviceJwksDir=jwks(service, "service", "service"),
            signingKeyId="service",
            signingKeyPath=pem(service, "service.pem"),
        ),
        evidenceSigningKeyPath=pem(evidence_key, "evidence.pem"),
        deadlineTrustRecords=[
            dict(public_jwk=ej, trust_revision=1, not_before=before, not_after=after, revoked_at=None)
        ],
        selectedEvidenceKid=ej["kid"],
        selectedEvidenceRevision=1,
        statementTrustRecords=[
            dict(
                public_jwk=public(statement, "statement"),
                revision=1,
                not_before=before,
                not_after=after,
                revoked_at=None,
            )
        ],
    )
    return cfg, manifest


def test_disabled_has_no_key_credential_or_engine_access(monkeypatch):
    monkeypatch.setattr(runtime, "read_operator_json", lambda *_: pytest.fail("file access"))
    assert runtime.build_enrollment_application_runtime({}, None) is None
    assert runtime.build_enrollment_application_runtime({}, {"enabled": False}) is None


def test_real_assembly_keeps_two_factories_and_shared_writer_replay(configured):
    cfg, manifest = configured
    result = runtime.build_enrollment_application_runtime(cfg, manifest)
    try:
        writer = result.issuance.owner.lifecycle._factory
        finalizer = result.enrollment.operations.composition._factory
        assert writer is result.enrollment.challenge._factory
        assert writer is result.issuance.replay._session_factory is result.enrollment.replay._session_factory
        assert finalizer is result.enrollment.operations.lifecycle._factory and finalizer is not writer
        assert [e.url.username for e in result.engines] == ["synthetic_writer", "synthetic_finalizer"]
        assert "synthetic-password" not in repr(result)
        channels = (*result.enrollment.service_configs, *result.issuance.service_configs)
        assert len(channels) == 8
        assert all(config.clock_skew_seconds == 0 for config in channels)
        assert all(
            config.clock_skew_seconds == 0
            for ingress in (result.enrollment, result.issuance)
            for config in ingress._configs.values()
        )
        app = Flask("native-runtime-assembly")
        assert runtime.install_enrollment_application_runtime(app, result) is True
        paths = {rule.rule for rule in app.url_map.iter_rules()}
        assert len([p for p in paths if p.startswith("/internal/v2/social/")]) == 10
        before = tuple(app.url_map.iter_rules())
        with pytest.raises(runtime.EnrollmentRuntimeConfigurationError):
            runtime.install_enrollment_application_runtime(app, result)
        assert tuple(app.url_map.iter_rules()) == before
    finally:
        result.close()


@pytest.mark.parametrize(
    "change", ["extra_field", "literal_enabled", "same_role", "wrong_key", "wrong_trust_revision", "relative_key"]
)
def test_incomplete_or_mismatched_configuration_never_installs(configured, change):
    cfg, original = configured
    m = deepcopy(original)
    if change == "extra_field":
        m["requestClock"] = 123
    elif change == "literal_enabled":
        m["enabled"] = "true"
    elif change == "same_role":
        m["finalizer"] = m["challengeWriter"]
    elif change == "wrong_key":
        m["evidenceSigningKeyPath"] = m["service"]["signingKeyPath"]
    elif change == "wrong_trust_revision":
        m["selectedEvidenceRevision"] = 2
    else:
        m["evidenceSigningKeyPath"] = "relative.pem"
    with pytest.raises(runtime.EnrollmentRuntimeConfigurationError):
        runtime.build_enrollment_application_runtime(cfg, m)


@pytest.mark.parametrize(
    "row",
    [
        ("wrong", "writer", "writer", 20001, 160015),
        ("db", "writer", "other", 20001, 160015),
        ("db", "writer", "writer", 20002, 160015),
        ("db", "writer", "writer", 20001, 170000),
        None,
    ],
)
def test_direct_database_identity_is_pinned_before_owner_work(row):
    calls = []
    cursor = SimpleNamespace(
        execute=lambda sql: calls.append(sql), fetchone=lambda: row, close=lambda: calls.append("close")
    )
    connection = SimpleNamespace(cursor=lambda: cursor, rollback=lambda: calls.append("rollback"))
    with pytest.raises(runtime.EnrollmentRuntimeConfigurationError):
        runtime._verify_direct_role_connection(connection, database="db", role="writer", role_oid=20001)
    assert calls[-2:] == ["close", "rollback"]
    assert calls[0].startswith("SELECT current_database()")


def test_direct_role_identity_success_leaves_no_initialization_transaction():
    calls = []
    cursor = SimpleNamespace(
        execute=lambda _: None,
        fetchone=lambda: ("db", "writer", "writer", 20001, 160015),
        close=lambda: calls.append("close"),
    )
    runtime._verify_direct_role_connection(
        SimpleNamespace(cursor=lambda: cursor, rollback=lambda: calls.append("rollback")),
        database="db",
        role="writer",
        role_oid=20001,
    )
    assert calls == ["close", "rollback"]


def test_operator_json_rejects_duplicate_fields_and_symlinks(tmp_path, monkeypatch):
    path = tmp_path / "manifest.json"
    path.write_text('{"enabled":true,"enabled":false}')
    path.chmod(0o600)
    original = os.fstat
    monkeypatch.setattr(
        runtime.os,
        "fstat",
        lambda fd: SimpleNamespace(st_mode=original(fd).st_mode, st_size=original(fd).st_size, st_uid=0),
    )
    with pytest.raises(runtime.EnrollmentRuntimeConfigurationError):
        runtime.read_operator_json(str(path))
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(OSError):
        runtime.read_operator_json(str(link))
