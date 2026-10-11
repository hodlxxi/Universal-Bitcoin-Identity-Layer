"""SQLite/doubles exercise source decisions, never native catalogs or triggers."""

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.pool import StaticPool

from app import tokens
from app.models import (
    Base,
    CurrentEntitlementEvidence,
    OAuthBrowserGeneration,
    OAuthClient,
    OAuthSessionGeneration,
    OAuthToken,
    Session,
    User,
)
from app.services import oauth_bearer_validation, social_session_issuance_v2_authority
from app.services.current_entitlement_evidence import CONTRACT_VERSION
from app.services.oauth_bearer_validation import TOKEN_CONTRACT
from app.services.oauth_scope_policy import SCOPE_POLICY_VERSION
from app.services.oauth_session_lifecycle import SqlAlchemyOAuthSessionLifecycle
from app.services.social_messaging_device_storage import SocialMessagingDeviceBindingRow
from app.services.social_session_issuance import SocialSessionIssuer
from app.services.social_session_issuance_v2 import NativeV2SessionIssuer
from app.services.social_session_issuance_v2_contract import V2IssuanceUnavailable
from app.services.social_session_issuance_v2_storage import (
    FUNCTION_CONFIGS,
    FUNCTIONS,
    INVALIDATE_BODY,
    LEGACY_FUNCTION_HASHES,
    TransactionGuard,
    V2Base,
    V2BindingBirth,
    V2Offer,
    V2TokenBirth,
)

ROOT = Path(__file__).resolve().parents[2]
VECTOR = json.loads((ROOT / "tests/fixtures/social_preacceptance_ed25519_handoff_v2.json").read_bytes())["vector"]
NOW = datetime(2026, 9, 8, 22, 30, tzinfo=timezone.utc)
SUBJECT = json.loads(VECTOR["preEnrollmentWire"])["subject"]
USER_ID = "00000000-0000-4000-8000-000000000002"
TOKEN_ID = "a1" * 16
BROWSER_ID = "b1" * 32
CLIENT = "social-client"
ISSUER = "https://ubid.example"


class Result:
    def __init__(self, value=None):
        self.value = value

    def scalar_one(self):
        return self.value


class ConnectionDouble:
    def __init__(self, graph, connection):
        self.graph = graph
        self.actual = connection
        self.connection = SimpleNamespace(dbapi_connection=SimpleNamespace(autocommit=False))
        self.dialect = SimpleNamespace(name="postgresql")
        self.xid = "42"
        self.closed = self.invalidated = False

    def get_transaction(self):
        return self.actual.get_transaction()

    def get_nested_transaction(self):
        return self.actual.get_nested_transaction()

    def in_transaction(self):
        return self.actual.in_transaction()

    def execute(self, statement, values=None):
        sql = str(statement)
        if sql == "SHOW transaction_isolation":
            return Result("read committed")
        if sql == "SHOW server_version_num":
            return Result("160010")
        if "pg_current_xact_id" in sql:
            return Result(self.xid)
        if "pg_advisory_xact_lock" in sql:
            return Result()
        raise AssertionError("unexpected unguarded SQL")


class SessionDouble:
    def __init__(self, graph):
        self.graph = graph
        self.actual = OrmSession(graph.engine, expire_on_commit=False)
        self.pinned = None

    def __getattr__(self, name):
        return getattr(self.actual, name)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.actual.close()

    def get_bind(self):
        return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

    def connection(self):
        actual = self.actual.connection()
        if self.pinned is None or self.pinned.actual is not actual:
            self.pinned = ConnectionDouble(self.graph, actual)
        return self.pinned

    def execute(self, statement, *, bind_arguments=None):
        assert bind_arguments == {"bind": self.connection()}
        assert statement.get_execution_options().get("populate_existing") is True
        self.graph.statements.append(str(statement))
        if str(statement).startswith("SHOW "):
            return self.connection().execute(statement)
        if "pg_advisory_xact_lock" in str(statement):
            return Result()
        if self.graph.after_wait is not None and "FOR UPDATE" in str(statement):
            callback, self.graph.after_wait = self.graph.after_wait, None
            callback()
        result = self.actual.execute(statement, bind_arguments={"bind": self.connection().actual})
        # Explicit synthetic counterparts to native AFTER INSERT birth triggers.
        # These effects are NOT proof that the SQL triggers execute.
        if getattr(statement, "is_insert", False):
            table = statement.table.name
            values = statement.compile().params
            if table == "oauth_tokens":
                self.actual.execute(V2TokenBirth.__table__.insert().values(token_id=values["id"], birth_xid="42"))
            if table == "social_messaging_device_bindings":
                op = self.actual.execute(
                    select(V2Offer.operation_id).where(V2Offer.request_id == values["request_id"])
                ).scalar_one()
                self.actual.execute(
                    V2BindingBirth.__table__.insert().values(
                        binding_id=values["binding_id"], operation_id=op, birth_xid="42"
                    )
                )
        return result


class Graph:
    def __init__(self, monkeypatch):
        self.now = NOW
        self.after_wait = None
        self.statements = []
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.engine = create_engine("sqlite:///:memory:", poolclass=StaticPool)
        with self.engine.begin() as c:
            c.execute(text("ATTACH DATABASE ':memory:' AS public"))
            for model in (
                User,
                OAuthClient,
                OAuthToken,
                Session,
                OAuthBrowserGeneration,
                OAuthSessionGeneration,
                CurrentEntitlementEvidence,
                SocialMessagingDeviceBindingRow,
                SocialSessionIssuer,
            ):
                model.__table__.create(c)
            V2Base.metadata.create_all(c)
        monkeypatch.setattr(social_session_issuance_v2_authority, "attest", lambda guard: "synthetic-only")
        monkeypatch.setattr(tokens, "get_signing_key", lambda _directory: ("offline-oauth", self.key))
        monkeypatch.setattr(
            oauth_bearer_validation,
            "get_key_by_kid",
            lambda _directory, kid: self.key if kid == "offline-oauth" else None,
        )
        graph = self

        class JwtClock(datetime):
            @classmethod
            def now(cls, tz=None):
                return graph.now

        monkeypatch.setattr(jwt.api_jwt, "datetime", JwtClock)
        self.lifecycle = SqlAlchemyOAuthSessionLifecycle(
            session_factory=lambda: SessionDouble(self),
            client_id=CLIENT,
            token_config={"JWT_ISSUER": ISSUER, "JWKS_DIR": "unused-injected-test-port"},
            clock=lambda: self.now,
        )
        self.issuer = NativeV2SessionIssuer(lifecycle=self.lifecycle, backend_id="backend", principal="principal")
        self.desktop = tokens.issue_rs256_jwt(
            SUBJECT,
            dict(
                aud=CLIENT,
                iat=int((NOW - timedelta(seconds=5)).timestamp()),
                exp=int((NOW + timedelta(minutes=10)).timestamp()),
                jti=TOKEN_ID,
                scope="openid profile",
                token_use="access",
                token_contract=TOKEN_CONTRACT,
            ),
            cfg=self.lifecycle._config,
        )
        with OrmSession(self.engine) as s, s.begin():
            s.add(User(id=USER_ID, pubkey=SUBJECT, is_active=True))
            s.add(
                OAuthClient(
                    client_id=CLIENT,
                    client_secret="synthetic",
                    client_name="synthetic",
                    redirect_uris=[],
                    grant_types=["authorization_code"],
                    response_types=["code"],
                    scope="openid profile",
                    is_active=True,
                    metadata_json={"trust_class": "operator_managed"},
                )
            )
            created = (NOW - timedelta(seconds=5)).replace(tzinfo=None)
            expiry = (NOW + timedelta(minutes=10)).replace(tzinfo=None)
            s.add(
                OAuthBrowserGeneration(
                    generation_id=BROWSER_ID,
                    user_id=USER_ID,
                    client_id=CLIENT,
                    subject=SUBJECT,
                    proof_id="b2" * 32,
                    created_at=created,
                    expires_at=expiry,
                    is_active=True,
                )
            )
            s.add(
                OAuthToken(
                    id=TOKEN_ID,
                    access_token=hashlib.sha256(self.desktop.encode()).hexdigest(),
                    token_type="Bearer",
                    client_id=CLIENT,
                    user_id=USER_ID,
                    scope="openid profile",
                    created_at=created,
                    access_token_expires_at=expiry,
                    is_revoked=False,
                    metadata_json=dict(
                        token_contract=TOKEN_CONTRACT,
                        token_use="access",
                        issuer=ISSUER,
                        audience=CLIENT,
                        kid="offline-oauth",
                        digest_algorithm="sha256",
                        scope_policy_version=SCOPE_POLICY_VERSION,
                    ),
                )
            )
            s.add(
                Session(
                    session_id="c1" * 32,
                    user_id=USER_ID,
                    session_type="web",
                    created_at=created,
                    expires_at=expiry,
                    is_active=True,
                    metadata_json=None,
                )
            )
            s.add(
                OAuthSessionGeneration(
                    token_id=TOKEN_ID,
                    browser_generation_id=BROWSER_ID,
                    session_id="c1" * 32,
                    user_id=USER_ID,
                    client_id=CLIENT,
                    subject=SUBJECT,
                )
            )
            s.add(
                SocialSessionIssuer(
                    client_id=CLIENT, backend_id="backend", service_principal="principal", is_active=True
                )
            )
            s.add(
                CurrentEntitlementEvidence(
                    evidence_id="00000000-0000-4000-8000-000000000001",
                    contract_version=CONTRACT_VERSION,
                    subject_pubkey=SUBJECT,
                    identity_class="full",
                    current_full_relation_satisfied=True,
                    evidence_source="synthetic",
                    evidence_version="v1",
                    source_evidence_sha256="ab" * 32,
                    observed_at=created,
                    created_at=created,
                    valid_until=expiry,
                    revoked_at=None,
                )
            )

    def create(self):
        return self.issuer.create_offer(VECTOR["authorizationWire"], desktop_bearer=self.desktop)

    def issue(self, **changes):
        values = dict(
            approval_wire=VECTOR["approvalEventWire"],
            secret="77" * 32,
            possession_proof=VECTOR["pairingPossessionProof"],
            verifier="88" * 32,
            delivery_key="55" * 32,
            approver_bearer=self.desktop,
        )
        values.update(changes)
        return self.issuer.issue("99" * 32, **values)

    def reader(self, session):
        return self.issuer._reader(session)


@pytest.fixture
def graph(monkeypatch):
    result = Graph(monkeypatch)
    yield result
    result.engine.dispose()


def test_separate_metadata_and_exact_migration_bodies():
    assert not {t.name for t in V2Base.metadata.tables.values()} & {t.name for t in Base.metadata.tables.values()}
    sql = (ROOT / "migrations/2026-10-10_social_session_issuance_v2_provenance_v1.sql").read_text()
    for name, body in FUNCTIONS.items():
        matches = re.findall(
            rf"CREATE FUNCTION public\.{name}\(\) RETURNS trigger LANGUAGE plpgsql "
            r"SECURITY DEFINER SET search_path = ([^\n]+?) AS \$v2\$(.*?)\$v2\$;",
            sql,
            re.DOTALL,
        )
        assert matches == [(FUNCTION_CONFIGS[name][0].removeprefix("search_path="), body)]
        assert f"REVOKE ALL ON FUNCTION public.{name}() FROM PUBLIC;" in sql
    assert "CREATE ROLE" not in sql and "ALTER TABLE" not in sql
    assert "SECURITY DEFINER SET search_path = pg_catalog" in sql
    assert "birth_xid = pg_catalog.pg_current_xact_id()::text" in sql


def test_invalidation_preserves_actual_child_update_and_unchanged_legacy_guards():
    assert FUNCTION_CONFIGS["social_session_v2_invalidate"] == ("search_path=pg_catalog, public, pg_temp",)
    assert all(
        config == ("search_path=pg_catalog",)
        for name, config in FUNCTION_CONFIGS.items()
        if name != "social_session_v2_invalidate"
    )
    assert "INSERT INTO public.social_session_v2_invalidations(operation_id)" in INVALIDATE_BODY
    assert "UPDATE public.oauth_tokens SET is_revoked = TRUE WHERE is_revoked IS FALSE AND id IN (" in INVALIDATE_BODY
    # Inspect relation references outside string literals; all of this new
    # body's business relations remain qualified despite its legacy-only path.
    without_literals = re.sub(r"'[^']*'", "''", INVALIDATE_BODY)
    relations = re.findall(r"\b(?:FROM|JOIN|UPDATE|INTO)\s+([a-z_.]+)", without_literals)
    assert relations and all(name.startswith("public.") for name in relations)
    sources = "\n".join(path.read_text() for path in sorted((ROOT / "migrations").glob("*.sql")))
    for name, expected in LEGACY_FUNCTION_HASHES.items():
        matches = re.findall(
            rf"CREATE(?: OR REPLACE)? FUNCTION {name}\(\)\s+RETURNS (?:TRIGGER|trigger)\s+"
            r"LANGUAGE plpgsql\s+AS \$\$(.*?)\$\$;",
            sources,
            re.DOTALL,
        )
        assert len(matches) == 1
        assert hashlib.sha256(matches[0].encode()).hexdigest() == expected


def test_attestation_pins_exact_function_configuration_and_public_schema_owner(monkeypatch):
    from app.services import social_session_issuance_v2_storage as storage

    class CatalogResult:
        def __init__(self, rows):
            self.rows = rows

        def one(self):
            assert len(self.rows) == 1
            return self.rows[0]

        def all(self):
            return self.rows

    class Catalog:
        schema_owner = 100
        secure_schema = True
        configs = {name: list(config) for name, config in FUNCTION_CONFIGS.items()}

        def sql(self, sql, values=None):
            if "FROM pg_catalog.pg_roles" in sql:
                return CatalogResult([(False, False, False, False, False, 0)])
            if "FROM pg_catalog.pg_namespace WHERE nspname='public'" in sql:
                assert "NOT pg_catalog.has_schema_privilege(current_user,'public','CREATE')" in sql
                assert "pg_catalog.has_schema_privilege(current_user,'public','USAGE')" in sql
                assert "pg_catalog.current_setting('session_replication_role')" in sql
                assert "NOT pg_catalog.pg_has_role(current_user,nspowner,'MEMBER')" in sql
                assert "current_user = session_user" in sql
                return CatalogResult([(2200, self.schema_owner, self.secure_schema)])
            name = values["name"]
            return CatalogResult(
                [(200, 100, FUNCTIONS[name], True, self.configs[name], "v", True, 0, "f", "plpgsql", False, False)]
            )

        def check(self):
            pass

    # Constrain this offline double to the actual role/schema/function phase;
    # relation/legacy catalogs have their own checks, and no PG execution occurs.
    monkeypatch.setattr(storage, "_attest_legacy", lambda _guard: [])
    monkeypatch.setattr(storage, "V2Base", SimpleNamespace(metadata=SimpleNamespace(sorted_tables=[])))
    catalog = Catalog()
    original = storage.attest(catalog)
    catalog.schema_owner = 101
    assert storage.attest(catalog) != original
    catalog.secure_schema = False
    with pytest.raises(V2IssuanceUnavailable):
        storage.attest(catalog)
    catalog.secure_schema = True
    for name, expected in FUNCTION_CONFIGS.items():
        for wrong in (
            None,
            ["search_path=public, pg_catalog, pg_temp"],
            ["search_path=pg_catalog, pg_temp, public"],
            ["search_path=pg_catalog, public"],
            ["search_path=pg_catalog, public, pg_temp", "work_mem=4MB"],
            (
                ["search_path=pg_catalog"]
                if name == "social_session_v2_invalidate"
                else ["search_path=pg_catalog, public, pg_temp"]
            ),
        ):
            catalog.configs[name] = wrong
            with pytest.raises(V2IssuanceUnavailable):
                storage.attest(catalog)
        catalog.configs[name] = list(expected)
    assert storage.attest(catalog)


def test_guard_pins_real_objects_and_denies_backend_restart(graph):
    with SessionDouble(graph) as s, s.begin():
        guard = TransactionGuard(s)
        guard.check()
        s.connection().xid = "43"
        with pytest.raises(V2IssuanceUnavailable):
            guard.check()
        assert guard.poisoned


def test_guard_denies_physical_swap_and_savepoint_replacement(graph):
    with SessionDouble(graph) as s, s.begin():
        guard = TransactionGuard(s)
        s.connection().connection.dbapi_connection = SimpleNamespace(autocommit=False)
        with pytest.raises(V2IssuanceUnavailable):
            guard.check()
    with SessionDouble(graph) as s, s.begin():
        guard = TransactionGuard(s)
        savepoint = s.begin_nested()
        with pytest.raises(V2IssuanceUnavailable):
            guard.check()
        savepoint.rollback()


def test_guard_denies_connection_swap_even_with_same_backend(graph):
    with SessionDouble(graph) as s, s.begin():
        guard = TransactionGuard(s)
        s.pinned = ConnectionDouble(graph, s.pinned.actual)
        with pytest.raises(V2IssuanceUnavailable):
            guard.check()


def test_real_old_initial_mutation_routes_reads_locks_and_core_write_to_guard(graph, monkeypatch):
    from app.services.social_messaging_device_binding_authorization_storage import (
        SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage,
    )
    from app.services.social_messaging_device_contract import MessagingDeviceAuthorityUnavailable
    from app.services.social_messaging_device_storage import SqlAlchemyTransactionBoundSocialMessagingDeviceStorage
    from app.services.social_session_issuance_v2_contract import binding_from_wire

    graph.create()
    with SessionDouble(graph) as s, s.begin():
        reader = graph.reader(s)
        connection = reader.guard.connection
        original_execute = connection.execute
        locks = []

        def connection_execute(statement, values=None):
            if "pg_advisory_xact_lock" in str(statement):
                locks.append(str(statement))
            return original_execute(statement, values)

        monkeypatch.setattr(connection, "execute", connection_execute)
        graph.statements.clear()
        owner = SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage(reader.port)
        binding = binding_from_wire(VECTOR["authorizationWire"])
        owner._lock_request(binding.request_id)
        owner._lock_mutation(subject=binding.subject, device_id=binding.device_id, public_keys=(binding.public_key,))
        primitive = SqlAlchemyTransactionBoundSocialMessagingDeviceStorage(reader.port)
        assert primitive.apply_authorized(binding, now=NOW) == binding
        reader.port.flush()
        assert primitive.binding_for_id(binding.binding_id) == binding
        # SessionDouble independently asserts exact bind and identity refresh on
        # every SQL read/Core write; advisory locks must use the pinned Connection.
        assert len(locks) == 5  # request, Full subject, device, global key, exact key
        assert not any("pg_advisory_xact_lock" in sql for sql in graph.statements)
        inserts = [sql for sql in graph.statements if sql.startswith("INSERT INTO social_messaging_device_bindings")]
        assert len(inserts) == 1
        assert not s.new and not s.dirty
        with pytest.raises(MessagingDeviceAuthorityUnavailable):
            primitive.apply_authorized(binding, now=NOW)
        assert (
            len([sql for sql in graph.statements if sql.startswith("INSERT INTO social_messaging_device_bindings")])
            == 1
        )


def test_closed_trigger_validator_rejects_changed_binding_condition_or_extra_hook():
    from app.services.social_session_issuance_v2_storage import _attest_triggers

    class Rows:
        def __init__(self, values):
            self.values = values

        def all(self):
            return self.values

    expected = {"v2_insert": ("social_session_v2_guard", 7, False, False)}
    valid = (
        101,
        201,
        "v2_insert",
        "social_session_v2_guard",
        7,
        False,
        False,
        "O",
        0,
        "",
        None,
        b"",
        None,
        None,
        0,
        "public",
    )
    guarded = SimpleNamespace(sql=lambda *_args: Rows([valid]))
    assert _attest_triggers(guarded, 1, expected) == [(101, 201)]
    for index, value in ((4, 5), (7, "D"), (8, 1), (10, "forged WHEN"), (15, "shadow")):
        changed = list(valid)
        changed[index] = value
        guarded.sql = lambda *_args, changed=changed: Rows([tuple(changed)])
        with pytest.raises(V2IssuanceUnavailable):
            _attest_triggers(guarded, 1, expected)
    guarded.sql = lambda *_args: Rows([valid, valid])
    with pytest.raises(V2IssuanceUnavailable):
        _attest_triggers(guarded, 1, expected)
