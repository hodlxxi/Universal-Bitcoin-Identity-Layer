"""Offline trusted composition checks; no SQL, sockets, or private key files."""

import ast
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask
from jwt.algorithms import RSAAlgorithm

from app.services import social_mobile_session_runtime as wiring
from app.services.confidential_service_credentials import RSA_PRIVATE_PARAMETERS
from app.services.social_session_issuance import SessionIssuanceUnavailable
from app.services.social_session_issuance_ingress import install_session_issuance

# Environment identities are fixtures, never source authorization constants.
STAGING_IDENTITIES = {
    "SOCIAL_MOBILE_AUTHORIZATION_VIEWER_OAUTH_CLIENT_ID": "client_HcWQhI45Cm92N_tRWHGRb-O3pdZKDDAdVnk4_1TVrtY",
    "SOCIAL_SESSION_ISSUANCE_BACKEND_ID": "social-staging-session-issuance-service-v1",
    "SOCIAL_SESSION_ISSUANCE_SERVICE_PRINCIPAL": "service:social-staging-session-issuance-v1",
}
ALTERNATE_IDENTITIES = {
    "SOCIAL_MOBILE_AUTHORIZATION_VIEWER_OAUTH_CLIENT_ID": "client_social_production_v1",
    "SOCIAL_SESSION_ISSUANCE_BACKEND_ID": "social-production-session-issuance-service-v1",
    "SOCIAL_SESSION_ISSUANCE_SERVICE_PRINCIPAL": "service:social-production-session-issuance-v1",
}


def no_database():
    pytest.fail("composition attempted a database operation")


@pytest.fixture(scope="module")
def keys():
    # Synthetic infrastructure objects stay in memory, never PEM or key files.
    return tuple(rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(2))


@pytest.fixture
def configured(tmp_path, monkeypatch, keys):
    client, service = keys

    def public(key, kid):
        return dict(json.loads(RSAAlgorithm.to_jwk(key.public_key())), kid=kid, alg="RS256", use="sig")

    documents = {}
    config = {
        **dict.fromkeys(wiring.ENABLE_FLAGS, True),
        "JWT_ISSUER": "https://identity.example",
        "JWKS_DIR": str(tmp_path),
        "SOCIAL_MOBILE_AUTHORIZATION_VIEWER_OAUTH_CLIENT_ID": STAGING_IDENTITIES[
            "SOCIAL_MOBILE_AUTHORIZATION_VIEWER_OAUTH_CLIENT_ID"
        ],
        "SOCIAL_SESSION_ISSUANCE_BACKEND_ID": STAGING_IDENTITIES["SOCIAL_SESSION_ISSUANCE_BACKEND_ID"],
        "SOCIAL_SESSION_ISSUANCE_SERVICE_PRINCIPAL": STAGING_IDENTITIES["SOCIAL_SESSION_ISSUANCE_SERVICE_PRINCIPAL"],
        "SOCIAL_SESSION_ISSUANCE_SCOPE": wiring.issuance.SCOPE,
        "SOCIAL_SESSION_ISSUANCE_PURPOSE": wiring.issuance.PURPOSE,
        "SOCIAL_MOBILE_AUTHORIZATION_BACKEND_ID": "synthetic-mobile-backend",
        "SOCIAL_MOBILE_AUTHORIZATION_SERVICE_PRINCIPAL": "service:synthetic-mobile",
    }
    for prefix in ("SOCIAL_MOBILE_AUTHORIZATION", "SOCIAL_SESSION_ISSUANCE"):
        for side, key, kid in (("CLIENT", client, "client-test"), ("SERVICE", service, "service-test")):
            directory = tmp_path / (prefix + side)
            directory.mkdir()
            doc = {"keys": [public(key, kid)]}
            (directory / "jwks.json").write_text(json.dumps(doc))
            documents[prefix + side] = directory / "jwks.json"
            config[prefix + "_" + side + "_JWKS_DIR"] = str(directory)
        config[prefix + "_SERVICE_SIGNING_KEY_ID"] = "service-test"
        config[prefix + "_SERVICE_SIGNING_KEY_PATH"] = str(tmp_path / "not-a-real-key.pem")
    monkeypatch.setattr(wiring, "_read_signing_key", lambda path: service)
    return config, documents


@pytest.mark.parametrize("config", [{}, dict.fromkeys(wiring.ENABLE_FLAGS, False)])
def test_disabled_never_loads_keys_or_installs_routes(config, monkeypatch):
    monkeypatch.setattr(wiring, "_read_signing_key", lambda *a: pytest.fail("private key read"))
    monkeypatch.setattr(wiring, "load_jwks_document", lambda *a: pytest.fail("public key read"))
    app = Flask(__name__)
    before = tuple(app.url_map.iter_rules())
    assert wiring.configure_social_mobile_session(app, config) is False
    assert tuple(app.url_map.iter_rules()) == before
    assert app.extensions == {}
    for prefix in ("mobile-authorization", "session-issuance", "device-binding-authorization"):
        assert app.test_client().post("/internal/v1/social/" + prefix + "/service-token").status_code == 404
    assert (
        app.test_client().post("/internal/v1/social/messaging/device-binding-authorization-service-token").status_code
        == 404
    )


@pytest.mark.parametrize("flag", wiring.ENABLE_FLAGS)
def test_partial_flags_fail_before_install(flag):
    app = Flask(__name__)
    with pytest.raises(wiring.MobileSessionConfigurationError):
        wiring.configure_social_mobile_session(app, {flag: True}, session_factory=no_database)
    assert not app.extensions
    assert len(list(app.url_map.iter_rules())) == 1


@pytest.mark.parametrize("flag", [None, "true", 1, "false", "yes"])
def test_builder_requires_exact_booleans(flag):
    with pytest.raises(wiring.MobileSessionConfigurationError):
        wiring.build_social_mobile_session_runtime(dict.fromkeys(wiring.ENABLE_FLAGS, flag))


def test_complete_runtime_shares_exact_owners_and_explicit_install(configured):
    config, _ = configured
    runtime = wiring.build_social_mobile_session_runtime(config, session_factory=no_database)
    assert runtime.issuance.service.mobile is runtime.mobile.mobile
    assert runtime.issuance.service.lifecycle is runtime.lifecycle is runtime.mobile.lifecycle
    assert runtime.issuance.replay is runtime.mobile.replay
    assert (
        runtime.lifecycle._factory
        is runtime.mobile.mobile._factory
        is runtime.issuance.replay._session_factory
        is no_database
    )
    assert (
        runtime.lifecycle.client_id
        == runtime.mobile.mobile._issuance_client_id
        == STAGING_IDENTITIES["SOCIAL_MOBILE_AUTHORIZATION_VIEWER_OAUTH_CLIENT_ID"]
    )
    assert runtime.issuance.config.client_id == STAGING_IDENTITIES["SOCIAL_SESSION_ISSUANCE_BACKEND_ID"]
    assert runtime.issuance.config.service_principal == STAGING_IDENTITIES["SOCIAL_SESSION_ISSUANCE_SERVICE_PRINCIPAL"]
    assert set(runtime.lifecycle._config) == {"JWT_ISSUER", "JWKS_DIR"}
    assert "PRIVATE" not in repr(runtime)
    app = Flask(__name__)
    assert install_session_issuance(app, runtime.issuance) is False
    assert wiring.configure_social_mobile_session(app, config, session_factory=no_database) is True
    assert (
        app.extensions[wiring.LIFECYCLE_EXTENSION].client_id
        == STAGING_IDENTITIES["SOCIAL_MOBILE_AUTHORIZATION_VIEWER_OAUTH_CLIENT_ID"]
    )
    assert wiring.issuance.TOKEN_PATH in {rule.rule for rule in app.url_map.iter_rules()}
    assert wiring.TOKEN_PATH in {rule.rule for rule in app.url_map.iter_rules()}
    with pytest.raises(wiring.MobileSessionConfigurationError):
        wiring.configure_social_mobile_session(app, config, session_factory=no_database)
    with pytest.raises(SessionIssuanceUnavailable):
        install_session_issuance(app, runtime.issuance, enabled=True)


def test_every_required_field_is_fail_closed(configured):
    config, _ = configured
    for name in config:
        incomplete = {key: value for key, value in config.items() if key != name}
        app = Flask(__name__)
        with pytest.raises(wiring.MobileSessionConfigurationError):
            wiring.configure_social_mobile_session(app, incomplete, session_factory=no_database)
        assert not app.extensions
        assert len(list(app.url_map.iter_rules())) == 1


@pytest.mark.parametrize("identities", [STAGING_IDENTITIES, ALTERNATE_IDENTITIES], ids=["staging", "production-style"])
def test_explicit_environment_identities_compose(configured, identities):
    config = {**configured[0], **identities}
    runtime = wiring.build_social_mobile_session_runtime(config, session_factory=no_database)
    viewer = identities["SOCIAL_MOBILE_AUTHORIZATION_VIEWER_OAUTH_CLIENT_ID"]
    backend = identities["SOCIAL_SESSION_ISSUANCE_BACKEND_ID"]
    principal = identities["SOCIAL_SESSION_ISSUANCE_SERVICE_PRINCIPAL"]
    assert runtime.lifecycle.client_id == runtime.mobile.viewer_client_id == viewer
    assert runtime.mobile.mobile._issuance_client_id == runtime.issuance.service.client_id == viewer
    assert runtime.issuance.config.client_id == runtime.issuance.service.backend_id == backend
    assert runtime.issuance.config.service_principal == runtime.issuance.service.service_principal == principal
    assert runtime.issuance.config.issuer == config["JWT_ISSUER"]
    assert runtime.issuance.config.service_scope == wiring.issuance.SCOPE
    assert runtime.issuance.config.service_purpose == wiring.issuance.PURPOSE
    assert runtime.issuance.config.token_endpoint_audience == config["JWT_ISSUER"] + wiring.issuance.TOKEN_PATH
    assert runtime.issuance.config.service_resource_audience == config["JWT_ISSUER"] + wiring.issuance.PREFIX


@pytest.mark.parametrize("name", STAGING_IDENTITIES)
@pytest.mark.parametrize("value", [None, "", " bad", "bad ", "bad/name", "bad name", "bad\nname", "é", "a" * 256, True])
def test_malformed_environment_identity_fails_before_loading_keys(configured, monkeypatch, name, value):
    reads = []
    monkeypatch.setattr(wiring, "_read_signing_key", lambda path: reads.append(path))
    with pytest.raises(wiring.MobileSessionConfigurationError):
        wiring.build_social_mobile_session_runtime({**configured[0], name: value}, session_factory=no_database)
    assert not reads


@pytest.mark.parametrize("name", STAGING_IDENTITIES)
def test_no_environment_identity_default(configured, name):
    config = dict(configured[0])
    del config[name]
    app = Flask(__name__)
    with pytest.raises(wiring.MobileSessionConfigurationError):
        wiring.configure_social_mobile_session(app, config, session_factory=no_database)
    assert not app.extensions


@pytest.mark.parametrize("change", [None, "missing", "client_id", "backend_id", "service_principal", "inactive"])
def test_persisted_issuer_remains_authoritative_without_database_access(configured, change):
    from app.services.social_session_issuance import SocialSessionIssuer

    config = {**configured[0], **ALTERNATE_IDENTITIES}
    service = wiring.build_social_mobile_session_runtime(config, session_factory=no_database).issuance.service
    row = SimpleNamespace(
        client_id=service.client_id,
        backend_id=service.backend_id,
        service_principal=service.service_principal,
        is_active=True,
    )
    if change in {"client_id", "backend_id", "service_principal"}:
        setattr(row, change, "different-explicit-identity")
    if change == "inactive":
        row.is_active = False
    reads = []

    def get(model, client_id, **options):
        assert model is SocialSessionIssuer
        assert options == {"with_for_update": True, "populate_existing": True}
        reads.append(client_id)
        return row if change != "missing" and client_id == row.client_id else None

    db = SimpleNamespace(get=get)
    if change is None:
        assert service._issuer(db, active=True) is row
    else:
        with pytest.raises(ValueError):
            service._issuer(db, active=True)
    assert reads == [service.client_id]


@pytest.mark.parametrize(
    "field", ["clientId", "backendId", "servicePrincipal", "client_id", "backend_id", "service_principal"]
)
def test_http_request_cannot_override_trusted_identity(configured, field):
    config = {**configured[0], **ALTERNATE_IDENTITIES}
    app = Flask(__name__)
    wiring.configure_social_mobile_session(app, config, session_factory=no_database)
    client = app.test_client()
    body = dict.fromkeys(wiring.issuance.COMMANDS["issue"], "a" * 64)
    body[field] = "request-selected-identity"
    assert client.post(wiring.issuance.PREFIX + "/issue", json=body).status_code == 400
    assert client.post(wiring.PREFIX + "/qr/create", json={field: "request-selected-identity"}).status_code == 400
    assert app.extensions[wiring.ISSUANCE_EXTENSION].config.client_id == config["SOCIAL_SESSION_ISSUANCE_BACKEND_ID"]


def test_http_service_token_client_id_must_match_trusted_configuration(configured):
    app = Flask(__name__)
    wiring.configure_social_mobile_session(app, configured[0], session_factory=no_database)
    response = app.test_client().post(
        wiring.issuance.TOKEN_PATH,
        data={
            "grant_type": "client_credentials",
            "client_id": "request-selected-backend",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": "synthetic.invalid.assertion",
            "scope": wiring.issuance.SCOPE,
        },
    )
    assert response.status_code == 401


@pytest.mark.parametrize(
    "name,value",
    [
        ("JWT_ISSUER", "https://identity.example/path"),
        ("JWT_ISSUER", "http://identity.example"),
        ("SOCIAL_SESSION_ISSUANCE_ISSUER", "https://wrong.example"),
        ("SOCIAL_SESSION_ISSUANCE_TOKEN_ENDPOINT_AUDIENCE", "urn:old:token"),
        ("SOCIAL_SESSION_ISSUANCE_RESOURCE_AUDIENCE", "urn:old:resource"),
        ("SOCIAL_SESSION_ISSUANCE_SCOPE", "openid profile"),
        ("SOCIAL_SESSION_ISSUANCE_PURPOSE", "social_full_directory_read"),
        ("SOCIAL_SESSION_ISSUANCE_SERVICE_SIGNING_KEY_ID", "missing-kid"),
    ],
)
def test_wrong_identity_or_contract_rejected(configured, name, value):
    config, _ = configured
    with pytest.raises(wiring.MobileSessionConfigurationError):
        wiring.build_social_mobile_session_runtime({**config, name: value}, session_factory=no_database)


@pytest.mark.parametrize("side", ["CLIENT", "SERVICE"])
@pytest.mark.parametrize("field", RSA_PRIVATE_PARAMETERS)
def test_private_jwk_fields_rejected(configured, side, field):
    config, documents = configured
    path = documents["SOCIAL_SESSION_ISSUANCE" + side]
    doc = json.loads(path.read_text())
    doc["keys"][0][field] = "synthetic-forbidden-field"
    path.write_text(json.dumps(doc))
    with pytest.raises(wiring.MobileSessionConfigurationError):
        wiring.build_social_mobile_session_runtime(config, session_factory=no_database)


def test_same_rsa_key_rejected_before_private_read(configured, monkeypatch):
    config, documents = configured
    documents["SOCIAL_SESSION_ISSUANCECLIENT"].write_text(documents["SOCIAL_SESSION_ISSUANCESERVICE"].read_text())
    monkeypatch.setattr(wiring, "_read_signing_key", lambda *a: pytest.fail("private read before validation"))
    with pytest.raises(wiring.MobileSessionConfigurationError):
        wiring.build_social_mobile_session_runtime(config, session_factory=no_database)


def test_signer_must_match_public_document(configured, monkeypatch, keys):
    config, _ = configured
    monkeypatch.setattr(wiring, "_read_signing_key", lambda path: keys[0])
    with pytest.raises(wiring.MobileSessionConfigurationError):
        wiring.build_social_mobile_session_runtime(config, session_factory=no_database)


def test_no_implicit_database_factory(configured):
    config, _ = configured
    for factory in (None, "postgresql://forbidden", object()):
        with pytest.raises(wiring.MobileSessionConfigurationError):
            wiring.build_social_mobile_session_runtime(config, session_factory=factory)


@pytest.mark.parametrize(
    "field,value",
    [
        ("issuer", "https://wrong.example"),
        ("token_endpoint_audience", "urn:wrong"),
        ("service_resource_audience", "urn:wrong"),
        ("service_scope", "openid"),
        ("service_purpose", "wrong"),
    ],
)
def test_real_ingress_enforces_derived_contract(configured, field, value):
    runtime = wiring.build_social_mobile_session_runtime(configured[0], session_factory=no_database)
    with pytest.raises(SessionIssuanceUnavailable):
        replace(runtime.issuance, config=replace(runtime.issuance.config, **{field: value}))


def test_new_factory_is_separate_from_ordinary_factory():
    tree = ast.parse(Path("app/factory.py").read_text())
    ordinary = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "create_app")
    names = {node.id for node in ast.walk(ordinary) if isinstance(node, ast.Name)}
    assert "configure_social_mobile_session" not in names
    assert "create_social_mobile_app" not in names


def isolated_factory(create_app):
    # Execute the exact opt-in factory body with an offline ordinary factory.
    # Importing the ordinary factory itself has unrelated infrastructure hooks.
    tree = ast.parse(Path("app/factory.py").read_text())
    function = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "create_social_mobile_app"
    )
    module = ast.Module(
        body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), function],
        type_ignores=[],
    )
    namespace = {"create_app": create_app, "get_config": lambda: {}}
    exec(compile(ast.fix_missing_locations(module), "app/factory.py", "exec"), namespace)
    return namespace["create_social_mobile_app"]


def test_opt_in_factory_off_delegates_without_mobile_dependencies():
    app = Flask(__name__)
    seen = []

    def ordinary(cfg):
        seen.append(cfg)
        return app

    assert isolated_factory(ordinary)({"SOCIAL_SESSION_ISSUANCE_ENABLED": False}) is app
    assert seen == [{"SOCIAL_SESSION_ISSUANCE_ENABLED": False}]
    assert not app.extensions


def test_opt_in_factory_uses_initialized_postgresql_owner(configured, monkeypatch):
    from app import database

    monkeypatch.setattr(database, "_engine", SimpleNamespace(dialect=SimpleNamespace(name="postgresql")))
    monkeypatch.setattr(database, "get_session", no_database)
    app = Flask(__name__)
    result = isolated_factory(lambda cfg: app)(configured[0])
    assert result is app
    assert app.extensions[wiring.LIFECYCLE_EXTENSION]._factory is no_database


@pytest.mark.parametrize("dialect", [None, "sqlite"])
def test_opt_in_factory_never_falls_back_to_another_database(configured, monkeypatch, dialect):
    from app import database

    monkeypatch.setattr(
        database, "_engine", None if dialect is None else SimpleNamespace(dialect=SimpleNamespace(name=dialect))
    )
    app = Flask(__name__)
    with pytest.raises(wiring.MobileSessionConfigurationError):
        isolated_factory(lambda cfg: app)(configured[0])
    assert not app.extensions


@pytest.mark.parametrize("kind", ["empty", "duplicate", "wrong-algorithm"])
def test_invalid_public_document_fails_before_signer_read(configured, monkeypatch, kind):
    config, documents = configured
    path = documents["SOCIAL_SESSION_ISSUANCECLIENT"]
    doc = json.loads(path.read_text())
    if kind == "empty":
        doc["keys"] = []
    elif kind == "duplicate":
        doc["keys"] *= 2
    else:
        doc["keys"][0]["alg"] = "HS256"
    path.write_text(json.dumps(doc))
    monkeypatch.setattr(wiring, "_read_signing_key", lambda *a: pytest.fail("unexpected private key read"))
    with pytest.raises(wiring.MobileSessionConfigurationError):
        wiring.build_social_mobile_session_runtime(config, session_factory=no_database)


def test_exact_file_loader_never_serializes_the_key(tmp_path, monkeypatch, keys):
    path = tmp_path / "synthetic-file"
    path.write_bytes(b"synthetic-marker")
    path.chmod(0o600)

    def load(material, password):
        assert material == b"synthetic-marker"
        assert password is None
        return keys[1]

    monkeypatch.setattr(wiring.serialization, "load_pem_private_key", load)
    assert wiring._read_signing_key(str(path)) is keys[1]
    path.chmod(0o644)
    with pytest.raises(wiring.MobileSessionConfigurationError):
        wiring._read_signing_key(str(path))
    link = tmp_path / "symlink"
    link.symlink_to(path)
    with pytest.raises(OSError):
        wiring._read_signing_key(str(link))


@pytest.mark.parametrize("value,expected", [(None, False), ("false", False), ("true", True)])
def test_environment_maps_explicit_switches(monkeypatch, value, expected):
    from app.config import get_config

    for name in wiring.ENABLE_FLAGS:
        monkeypatch.delenv(name, raising=False)
        if value is not None:
            monkeypatch.setenv(name, value)
    cfg = get_config()
    assert all(cfg[name] is expected for name in wiring.ENABLE_FLAGS)


@pytest.mark.parametrize("value", ["1", "yes", "TRUE", " true", "no"])
def test_malformed_environment_switch_fails(monkeypatch, value):
    from app.config import get_config

    monkeypatch.setenv(wiring.ENABLE_FLAGS[0], value)
    with pytest.raises(ValueError, match="mobile session configuration invalid"):
        get_config()
