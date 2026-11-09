"""Explicit V2 application assembly with two directly authenticated SQL roles.

Import and disabled construction do no I/O. The ordinary app factory remains
unchanged. Manifest paths and key registrations are trusted operator inputs.
"""

import json
import os
import re
import stat
from dataclasses import dataclass, replace

EXTENSION = "social_enrollment_v2_runtime_v1"
SCHEMA = "ubid.social_enrollment_v2.runtime.v1"
CREDENTIAL_SCHEMA = "ubid.social_enrollment_v2.database_credentials.v1"
FRESHNESS = "native-v2-60s-v1"


class EnrollmentRuntimeConfigurationError(ValueError):
    def __init__(self):
        super().__init__("social enrollment v2 runtime configuration invalid")


def _deny():
    raise EnrollmentRuntimeConfigurationError() from None


def _exact(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        _deny()
    return value


def _unique_pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            _deny()
        result[name] = value
    return result


def read_operator_json(path):
    if type(path) is not str or not os.path.isabs(path) or os.path.normpath(path) != path:
        _deny()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o027 or not 0 < info.st_size <= 131072:
            _deny()
        raw = source.read(131073)
    if len(raw) > 131072:
        _deny()
    try:
        return json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=lambda _: _deny())
    except Exception:
        _deny()


@dataclass(frozen=True, repr=False)
class EnrollmentApplicationRuntime:
    enrollment: object
    issuance: object
    engines: tuple

    def close(self):
        for engine in self.engines:
            engine.dispose()


def _verify_direct_role_connection(connection, *, database, role, role_oid):
    cursor = None
    try:
        cursor = connection.cursor()
        cursor.execute(
            "SELECT current_database(),current_user,session_user,r.oid::bigint,"
            "current_setting('server_version_num')::integer FROM pg_catalog.pg_roles r WHERE r.rolname=current_user"
        )
        row = cursor.fetchone()
        if row is None or tuple(row[:4]) != (database, role, role, role_oid) or not 160000 <= row[4] < 170000:
            _deny()
    except Exception:
        _deny()
    finally:
        if cursor is not None:
            cursor.close()
        connection.rollback()


def build_enrollment_application_runtime(app_config, manifest=None):
    if manifest is None or type(manifest) is dict and manifest.get("enabled") is False:
        return None
    engines = []
    try:
        from sqlalchemy import URL, create_engine, event
        from sqlalchemy.orm import Session
        from sqlalchemy.pool import NullPool

        from app.services import social_enrollment_v2_ingress_schema as enrollment_schema
        from app.services import social_messaging_device_verification_deadline_evidence_v1 as evidence
        from app.services import social_preaccepted_enrollment_verification_statement_v2 as statement
        from app.services import social_session_issuance_v2_schema as session_schema
        from app.services.confidential_service_assertion_replay_storage import (
            PostgresConfidentialServiceAssertionReplayStore,
        )
        from app.services.oauth_session_lifecycle import SqlAlchemyOAuthSessionLifecycle
        from app.services.social_enrollment_v2_authenticated_composition import AuthenticatedEnrollmentV2Composition
        from app.services.social_enrollment_v2_catalog_roles import ChallengeWriterCatalogPin
        from app.services.social_enrollment_v2_challenge import (
            EnrollmentChallengeConfig,
            EnrollmentV2ChallengeComposition,
        )
        from app.services.social_enrollment_v2_finalization_contract import FinalizationConfig, StatementTrustPin
        from app.services.social_enrollment_v2_ingress import EnrollmentV2Ingress
        from app.services.social_enrollment_v2_reservation_contract import ReservationConfig
        from app.services.social_enrollment_v2_reservation_signer import DedicatedRS256EvidenceSigner
        from app.services.social_enrollment_v2_runtime_composition import SocialEnrollmentV2Composition
        from app.services.social_mobile_session_runtime import (
            _credentials,
            _identity,
            _path,
            _public_keys,
            _read_signing_key,
            _required,
        )
        from app.services.social_session_issuance_v2 import NativeV2SessionIssuer
        from app.services.social_session_issuance_v2_ingress import NativeV2SessionIngress

        m = _exact(
            manifest,
            (
                "schema",
                "version",
                "enabled",
                "databaseCredentialsPath",
                "challengeWriter",
                "finalizer",
                "socialOrigin",
                "service",
                "evidenceSigningKeyPath",
                "deadlineTrustRecords",
                "selectedEvidenceKid",
                "selectedEvidenceRevision",
                "statementTrustRecords",
            ),
        )
        if m["schema"] != SCHEMA or type(m["version"]) is not int or m["version"] != 1 or m["enabled"] is not True:
            _deny()
        for name in ("challengeWriter", "finalizer"):
            _exact(m[name], ("roleName", "roleOid"))
            ChallengeWriterCatalogPin(m[name]["roleName"], m[name]["roleOid"])
        if (
            m["challengeWriter"]["roleName"] == m["finalizer"]["roleName"]
            or m["challengeWriter"]["roleOid"] == m["finalizer"]["roleOid"]
        ):
            _deny()
        credentials = _exact(
            read_operator_json(m["databaseCredentialsPath"]), ("schema", "database", "host", "port", "roles")
        )
        if (
            credentials["schema"] != CREDENTIAL_SCHEMA
            or credentials["host"] != "127.0.0.1"
            or type(credentials["port"]) is not int
            or not 1 <= credentials["port"] <= 65535
            or type(credentials["database"]) is not str
            or re.fullmatch(r"[a-z][a-z0-9_]{0,62}", credentials["database"]) is None
        ):
            _deny()
        _exact(credentials["roles"], (m["challengeWriter"]["roleName"], m["finalizer"]["roleName"]))
        factories = {}
        for profile in ("challengeWriter", "finalizer"):
            name = m[profile]["roleName"]
            secret = _exact(credentials["roles"][name], ("username", "password"))
            if (
                secret["username"] != name
                or type(secret["password"]) is not str
                or not 32 <= len(secret["password"]) <= 256
            ):
                _deny()
            engine = create_engine(
                URL.create(
                    "postgresql+psycopg2",
                    username=name,
                    password=secret["password"],
                    host=credentials["host"],
                    port=credentials["port"],
                    database=credentials["database"],
                ),
                isolation_level="READ COMMITTED",
                poolclass=NullPool,
                hide_parameters=True,
                connect_args=dict(
                    connect_timeout=5,
                    sslmode="disable",
                    gssencmode="disable",
                    options="-c statement_timeout=30000 -c lock_timeout=2000",
                ),
            )
            engines.append(engine)

            def connected(connection, _record, database=credentials["database"], role=name, oid=m[profile]["roleOid"]):
                _verify_direct_role_connection(connection, database=database, role=role, role_oid=oid)

            event.listen(engine, "connect", connected)
            factories[profile] = lambda selected=engine: Session(selected)
        client_id = _identity(app_config, "SOCIAL_MOBILE_AUTHORIZATION_VIEWER_OAUTH_CLIENT_ID")
        backend = _identity(app_config, "SOCIAL_SESSION_ISSUANCE_BACKEND_ID")
        principal = _identity(app_config, "SOCIAL_SESSION_ISSUANCE_SERVICE_PRINCIPAL")
        issuer = _required(app_config, "JWT_ISSUER")
        token_config = {
            key: app_config[key] for key in ("JWT_ISSUER", "JWT_AUDIENCE", "TOKEN_TTL") if key in app_config
        }
        token_config["JWKS_DIR"] = _path(app_config, "JWKS_DIR", directory=True)
        lifecycles = {
            profile: SqlAlchemyOAuthSessionLifecycle(factory, client_id=client_id, token_config=token_config)
            for profile, factory in factories.items()
        }
        records = tuple(
            evidence.DeadlineEvidenceTrustRecordV1(
                **_exact(row, ("public_jwk", "trust_revision", "not_before", "not_after", "revoked_at"))
            )
            for row in m["deadlineTrustRecords"]
        )
        ec = evidence.MessagingDeviceVerificationDeadlineEvidenceV1Config(
            enabled=True,
            issuer=issuer,
            audience=m["socialOrigin"] + evidence.EVIDENCE_AUDIENCE_PATH,
            client_id=client_id,
            service_principal=principal,
            trust_records=records,
            freshness_profile=FRESHNESS,
        )
        rc = ReservationConfig(
            enabled=True,
            backend_id=backend,
            verification_audience=m["socialOrigin"],
            selected_kid=m["selectedEvidenceKid"],
            selected_revision=m["selectedEvidenceRevision"],
            evidence_config=ec,
            trust_pins=tuple(sorted((r.key_id, r.trust_revision, r.trust_record_id) for r in records)),
        )
        statement_rows = m["statementTrustRecords"]
        if type(statement_rows) is not list or not statement_rows:
            _deny()
        for row in statement_rows:
            _exact(row, ("public_jwk", "revision", "not_before", "not_after", "revoked_at"))
        sc = statement.SocialPreacceptedEnrollmentVerificationStatementV2Config(
            enabled=True,
            issuer=m["socialOrigin"],
            audience=issuer + statement.STATEMENT_CONSUME_PATH,
            client_id=client_id,
            service_principal=principal,
            trusted_jwks=tuple(r["public_jwk"] for r in statement_rows),
            freshness_profile=FRESHNESS,
        )
        keys = {k.kid: k for k in sc._keys}
        pins = tuple(
            StatementTrustPin(
                row["public_jwk"]["kid"],
                keys[row["public_jwk"]["kid"]].fingerprint,
                row["revision"],
                row["not_before"],
                row["not_after"],
                row["revoked_at"],
            )
            for row in statement_rows
        )
        writer_pin = ChallengeWriterCatalogPin(m["challengeWriter"]["roleName"], m["challengeWriter"]["roleOid"])
        fc = FinalizationConfig(True, rc, sc, pins, writer_pin)
        evidence_key = _read_signing_key(_path({"KEY": m["evidenceSigningKeyPath"]}, "KEY"))
        signer = DedicatedRS256EvidenceSigner(private_key=evidence_key, config=rc)
        composition = SocialEnrollmentV2Composition(session_factory=factories["finalizer"], signer=signer, config=fc)
        operations = AuthenticatedEnrollmentV2Composition(composition=composition, lifecycle=lifecycles["finalizer"])
        challenge = EnrollmentV2ChallengeComposition(
            lifecycle=lifecycles["challengeWriter"],
            config=EnrollmentChallengeConfig(
                enabled=True,
                client_id=client_id,
                backend_id=backend,
                service_principal=principal,
                issuer=issuer,
                audience=m["socialOrigin"],
                lifetime_ms=60000,
            ),
        )
        service = _exact(m["service"], ("clientJwksDir", "serviceJwksDir", "signingKeyId", "signingKeyPath"))
        service_config = {
            "V2_CLIENT_JWKS_DIR": service["clientJwksDir"],
            "V2_SERVICE_JWKS_DIR": service["serviceJwksDir"],
            "V2_SERVICE_SIGNING_KEY_ID": service["signingKeyId"],
            "V2_SERVICE_SIGNING_KEY_PATH": service["signingKeyPath"],
        }
        replay = PostgresConfidentialServiceAssertionReplayStore(factories["challengeWriter"])

        def channel(schema):
            configs, kid, key = _credentials(
                service_config,
                "V2",
                backend=backend,
                principal=principal,
                issuer=issuer,
                token_path=schema.TOKEN_PATH,
                resources=tuple(
                    (schema.PREFIX + "/" + name, schema.SCOPES[name], schema.PURPOSES[name]) for name in schema.COMMANDS
                ),
            )
            # V2 uses exact expiry; retain the shared V1 helper's clock policy.
            return tuple(replace(config, clock_skew_seconds=0) for config in configs), kid, key

        configs, kid, key = channel(enrollment_schema)
        enrollment = EnrollmentV2Ingress(configs, key, kid, challenge, operations, replay)
        configs, kid, key = channel(session_schema)
        issuance = NativeV2SessionIngress(
            configs,
            key,
            kid,
            NativeV2SessionIssuer(lifecycle=lifecycles["challengeWriter"], backend_id=backend, principal=principal),
            replay,
        )
        from jwt.algorithms import RSAAlgorithm

        dedicated = tuple(record._key.public_key.public_numbers() for record in records)
        public_other = [
            RSAAlgorithm.from_jwk(dict(jwk)).public_numbers()
            for jwk in (*_public_keys(token_config["JWKS_DIR"]), *configs[0].client_jwks, *configs[0].service_jwks)
        ]
        public_other.extend(item.public_key.public_numbers() for item in sc._keys)
        if any(numbers in dedicated for numbers in public_other):
            _deny()
        return EnrollmentApplicationRuntime(enrollment, issuance, tuple(engines))
    except Exception:
        for engine in engines:
            engine.dispose()
        _deny()


def install_enrollment_application_runtime(app, runtime):
    if type(runtime) is not EnrollmentApplicationRuntime:
        _deny()
    from app.blueprints.internal_social_enrollment_v2 import internal_social_enrollment_v2_bp
    from app.blueprints.internal_social_session_issuance_v2 import internal_social_session_issuance_v2_bp
    from app.services.social_enrollment_v2_ingress import EXTENSION as ENROLLMENT_EXTENSION
    from app.services.social_enrollment_v2_ingress import install_enrollment_v2_ingress
    from app.services.social_session_issuance_v2_ingress import EXTENSION as SESSION_EXTENSION
    from app.services.social_session_issuance_v2_ingress import install_native_v2_session_ingress

    if (
        app._got_first_request
        or any(name in app.extensions for name in (EXTENSION, ENROLLMENT_EXTENSION, SESSION_EXTENSION))
        or any(
            bp.name in app.blueprints
            for bp in (internal_social_enrollment_v2_bp, internal_social_session_issuance_v2_bp)
        )
    ):
        _deny()
    install_enrollment_v2_ingress(app, runtime.enrollment, enabled=True)
    install_native_v2_session_ingress(app, runtime.issuance, enabled=True)
    app.extensions[EXTENSION] = runtime
    return True


def create_social_enrollment_v2_app():
    """Separate Gunicorn entrypoint, selected explicitly by the staging operator."""
    from app.config import get_config
    from app.factory import create_social_mobile_app
    from app.services.social_messaging_private_routes import install_private_messaging

    path = os.environ.get("SOCIAL_ENROLLMENT_V2_CONFIG_PATH")
    manifest = read_operator_json(path)
    if manifest.get("enabled") is not True:
        _deny()
    cfg = get_config()
    runtime = build_enrollment_application_runtime(cfg, manifest)
    try:
        app = create_social_mobile_app(cfg)
        install_enrollment_application_runtime(app, runtime)
        install_private_messaging(app, cfg)
        return app
    except Exception:
        runtime.close()
        _deny()
