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

    def one(self):
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
        if "current_setting('transaction_isolation')" in sql:
            assert "current_setting('server_version_num')" in sql and "pg_current_xact_id" in sql
            return Result(("read committed", "160010", self.xid))
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
                return CatalogResult([(False, False, False, False, False, 0, [], [], 44, True, True, False)])
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
    original = storage._attest_catalog(catalog)
    catalog.schema_owner = 101
    assert storage._attest_catalog(catalog) != original
    catalog.secure_schema = False
    with pytest.raises(V2IssuanceUnavailable):
        storage._attest_catalog(catalog)
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
                storage._attest_catalog(catalog)
        catalog.configs[name] = list(expected)
    assert storage._attest_catalog(catalog)


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


@pytest.fixture
def runtime_profile_catalog(monkeypatch):
    from app.services import social_session_issuance_v2_storage as storage

    class Result:
        def __init__(self, rows):
            self.rows = rows

        def one(self):
            assert len(self.rows) == 1
            return self.rows[0]

        def all(self):
            return self.rows

    class Catalog:
        role = (False, False, False, False, False, 0, [], [], 44, True, True, False)

        def sql(self, sql, values=None):
            if "FROM pg_catalog.pg_roles" in sql:
                # Exercise the unchanged rejection before the correction too.
                return Result([self.role if " AS member_roles" in sql else self.role[:6]])
            if "FROM pg_catalog.pg_namespace WHERE nspname='public'" in sql:
                return Result([(2200, 100, True)])
            name = values["name"]
            return Result(
                [
                    (
                        200,
                        100,
                        FUNCTIONS[name],
                        True,
                        list(FUNCTION_CONFIGS[name]),
                        "v",
                        True,
                        0,
                        "f",
                        "plpgsql",
                        False,
                        False,
                    )
                ]
            )

        def check(self):
            pass

    # This double isolates role/function checks. The opt-in native tests use
    # the complete real catalog and unpatched authority on PostgreSQL 16.
    monkeypatch.setattr(storage, "_attest_legacy", lambda _guard: [])
    monkeypatch.setattr(storage, "V2Base", SimpleNamespace(metadata=SimpleNamespace(sorted_tables=[])))
    return storage, Catalog()


@pytest.mark.parametrize(
    "members,names,oids,inherit",
    [(0, [], [], False), (0, [], [], True), (1, ["pg_read_all_settings"], [3500], True)],
    ids=["original-noinherit", "original-inherit", "composed"],
)
def test_runtime_role_profiles_accept_exact_memberships(runtime_profile_catalog, members, names, oids, inherit):
    storage, catalog = runtime_profile_catalog
    catalog.role = (False, False, False, False, False, members, names, oids, 44, inherit, True, False)
    assert storage._attest_catalog(catalog)


@pytest.mark.parametrize(
    "members,names,oids,inherit,login,admin",
    [
        (0, ["pg_read_all_settings"], [3500], True, True, False),
        (1, [], [], True, True, False),
        (2, ["pg_read_all_settings"], [3500], True, True, False),
        (1, ["pg_read_all_data"], [3500], True, True, False),
        (2, ["pg_read_all_settings", "unexpected_owner"], [3500, 9000], True, True, False),
        (1, ["pg_read_all_settings", "inherited_owner"], [3500, 9000], True, True, False),
        (1, ["pg_read_all_settings"], [3500], False, True, False),
        (1, ["pg_read_all_settings"], [3500], True, False, False),
        (1, ["pg_read_all_settings"], [3500], True, True, True),
        (1, ["pg_read_all_settings"], [], True, True, False),
        (1, ["pg_read_all_settings"], [0], True, True, False),
        (1, ["pg_read_all_settings"], [3500, 9000], True, True, False),
        (0, [], [], True, False, False),
    ],
)
def test_runtime_role_profiles_reject_extra_or_ineffective_memberships(
    runtime_profile_catalog, members, names, oids, inherit, login, admin
):
    storage, catalog = runtime_profile_catalog
    catalog.role = (False, False, False, False, False, members, names, oids, 44, inherit, login, admin)
    with pytest.raises(V2IssuanceUnavailable):
        storage._attest_catalog(catalog)


@pytest.mark.parametrize("composed", [False, True])
@pytest.mark.parametrize("power", range(5))
def test_runtime_role_profiles_reject_administrative_power(runtime_profile_catalog, composed, power):
    storage, catalog = runtime_profile_catalog
    role = list(catalog.role)
    if composed:
        role[5:8] = [1, ["pg_read_all_settings"], [3500]]
    role[power] = True
    catalog.role = tuple(role)
    with pytest.raises(V2IssuanceUnavailable):
        storage._attest_catalog(catalog)


def test_runtime_role_identity_pins_profile_login_and_membership_oids(runtime_profile_catalog):
    storage, catalog = runtime_profile_catalog
    original = storage._attest_catalog(catalog)
    catalog.role = (False, False, False, False, False, 1, ["pg_read_all_settings"], [3500], 44, True, True, False)
    composed = storage._attest_catalog(catalog)
    assert original != composed
    changed_role = list(catalog.role)
    changed_role[8] = 45
    catalog.role = tuple(changed_role)
    assert storage._attest_catalog(catalog) != composed
    changed_role[8], changed_role[7] = 44, [3501]
    catalog.role = tuple(changed_role)
    assert storage._attest_catalog(catalog) != composed


def test_transaction_guard_uses_one_backend_observation_per_check(graph, monkeypatch):
    with SessionDouble(graph) as s, s.begin():
        c = s.connection()
        observed = []
        execute = c.execute

        def capture(statement, values=None):
            observed.append(str(statement))
            return execute(statement, values)

        monkeypatch.setattr(c, "execute", capture)
        guard = TransactionGuard(s)
        assert len(observed) == 1
        assert all(
            name in observed[0] for name in ("transaction_isolation", "server_version_num", "pg_current_xact_id")
        )
        observed.clear()
        guard.check()
        assert len(observed) == 1
        assert guard.xid == "42" and guard.poisoned is False


@pytest.mark.parametrize(
    "observation",
    [
        ("repeatable read", "160010", "42"),
        (None, "160010", "42"),
        ("read committed", 160010, "42"),
        ("read committed", "150015", "42"),
        ("read committed", "170000", "42"),
        ("read committed", "160x", "42"),
        ("read committed", "-160001", "42"),
        ("read committed", "160010", None),
        ("read committed", "160010", 42),
        ("read committed", "160010", "0"),
        ("read committed", "160010", "-1"),
        ("read committed", "160010", "+42"),
        ("read committed", "160010", " 42"),
        ("read committed", "160010", "42 "),
        ("read committed", "160010", "00"),
        ("read committed", "160010", "18446744073709551616"),
        ("read committed", "160010", "43"),
        ("read committed", "160010"),
        ("read committed", "160010", "42", "extra"),
    ],
)
def test_transaction_guard_batched_observation_rejects_invalid_state_and_stays_poisoned(
    graph, monkeypatch, observation
):
    with SessionDouble(graph) as s, s.begin():
        c = s.connection()
        guard = TransactionGuard(s)
        calls = []

        def invalid(statement, values=None):
            calls.append(str(statement))
            return Result(observation)

        monkeypatch.setattr(c, "execute", invalid)
        with pytest.raises(V2IssuanceUnavailable):
            guard.check()
        assert guard.poisoned and len(calls) == 1
        monkeypatch.setattr(c, "execute", lambda *_args: Result(("read committed", "160010", "42")))
        with pytest.raises(V2IssuanceUnavailable):
            guard.check()


@pytest.mark.parametrize("change", ["physical", "connection", "root", "savepoint"])
def test_transaction_guard_batched_observation_checks_continuity_after_query(graph, monkeypatch, change):
    with SessionDouble(graph) as s, s.begin():
        c = s.connection()
        guard = TransactionGuard(s)
        execute = c.execute

        def changed(statement, values=None):
            result = execute(statement, values)
            if change == "physical":
                c.connection.dbapi_connection = SimpleNamespace(autocommit=False)
            elif change == "connection":
                s.pinned = ConnectionDouble(graph, c.actual)
            elif change == "root":
                monkeypatch.setattr(s, "get_transaction", lambda: SimpleNamespace(is_active=True))
            else:
                c.actual.begin_nested()
            return result

        monkeypatch.setattr(c, "execute", changed)
        with pytest.raises(V2IssuanceUnavailable):
            guard.check()
        assert guard.poisoned
        if change == "savepoint":
            c.actual.get_nested_transaction().rollback()


def test_transaction_guard_batched_observation_error_poisons_without_query_fallback(graph, monkeypatch):
    with SessionDouble(graph) as s, s.begin():
        c = s.connection()
        guard = TransactionGuard(s)
        calls = []

        def broken(statement, values=None):
            calls.append(str(statement))
            raise RuntimeError("synthetic backend observation unavailable")

        monkeypatch.setattr(c, "execute", broken)
        with pytest.raises(V2IssuanceUnavailable):
            guard.check()
        assert guard.poisoned and len(calls) == 1


@pytest.mark.parametrize("depth", [1, 2, 3])
def test_transaction_guard_internal_layers_share_one_fresh_backend_observation(graph, monkeypatch, depth):
    from app.services.social_session_issuance_v2_authority import BoundSession

    with SessionDouble(graph) as s, s.begin():
        guards = [TransactionGuard(s)]
        for _ in range(depth):
            guards.append(TransactionGuard(BoundSession(guards[-1])))
        c = s.connection()
        execute = c.execute
        calls = []

        def capture(statement, values=None):
            calls.append(str(statement))
            return execute(statement, values)

        monkeypatch.setattr(c, "execute", capture)
        guards[-1].check()
        assert len(calls) == 1
        assert all(g.xid == "42" and not g.poisoned for g in guards)
        guards[-1].check()
        assert len(calls) == 2  # A new invocation must observe the backend again.
        c.xid = "43"
        with pytest.raises(V2IssuanceUnavailable):
            guards[-1].check()
        assert len(calls) == 3 and all(g.poisoned for g in guards)


@pytest.mark.parametrize("phase", ["before", "after"])
@pytest.mark.parametrize(
    "change", ["parent_xid", "parent_poison", "parent_physical", "parent_root", "port_guard", "port_connection"]
)
def test_transaction_guard_internal_layer_continuity_is_not_skipped(graph, monkeypatch, phase, change):
    from app.services.social_session_issuance_v2_authority import BoundSession

    with SessionDouble(graph) as s, s.begin():
        parent = TransactionGuard(s)
        port = BoundSession(parent)
        child = TransactionGuard(port)
        replacement_parent = TransactionGuard(s)
        c = s.connection()
        execute = c.execute

        def alter():
            if change == "parent_xid":
                parent.xid = "43"
            elif change == "parent_poison":
                parent.poisoned = True
            elif change == "parent_physical":
                parent.physical = SimpleNamespace(autocommit=False)
            elif change == "parent_root":
                parent.root = SimpleNamespace(is_active=True)
            elif change == "port_guard":
                port.guard = replacement_parent
            else:
                monkeypatch.setattr(port, "connection", lambda: c)

        if phase == "before":
            alter()
        else:

            def changed(statement, values=None):
                row = execute(statement, values)
                alter()
                return row

            monkeypatch.setattr(c, "execute", changed)
        with pytest.raises(V2IssuanceUnavailable):
            child.check()
        assert child.poisoned


@pytest.fixture
def catalog_batch_graph(monkeypatch):
    from app.services import social_session_issuance_v2_storage as storage

    # OID is a PostgreSQL nonnumeric JSON category. Native JSONB uses a string
    # unless this fixed field is explicitly cast to bigint; direct SQL uses int.
    oid_fields = {
        "schema": {0: "oid", 1: "nspowner"},
        "triggers": {0: "t.oid", 1: "t.tgfoid", 14: "t.tgparentid"},
        "constraints": {0: "k.oid", 10: "k.conparentid", 11: "k.confrelid", 12: "k.conindid"},
        "function": {0: "p.oid", 1: "p.proowner"},
        "table": {0: "c.oid", 1: "c.relowner", 2: "c.reltype", 3: "c.reltoastrelid"},
        "legacy_function": {0: "p.oid", 1: "p.proowner"},
        "legacy_table": {0: "c.oid", 1: "c.relowner"},
        "target": {0: "to_regclass(:target)::oid"},
    }

    # Real native table/constraint/function inventories; legacy validator tests
    # remain separate and disposable PostgreSQL verifies the full composition.
    monkeypatch.setattr(storage, "LEGACY_FUNCTION_HASHES", {})
    monkeypatch.setattr(storage, "OWNER_TRIGGERS", {})
    names = sorted(
        {t.name for t in V2Base.metadata.sorted_tables}
        | {c[4][0] for rows in storage.CONSTRAINTS.values() for c in rows if c[4]}
    )
    oids = {name: 1000 + i for i, name in enumerate(names)}
    by_oid = {oid: name for name, oid in oids.items()}
    tables = {t.name: t for t in V2Base.metadata.sorted_tables}

    class Rows:
        def __init__(self, rows):
            self.rows = rows

        def all(self):
            return self.rows

        def one(self):
            assert len(self.rows) == 1
            return self.rows[0]

        def scalar_one(self):
            row = self.one()
            assert len(row) == 1
            return row[0]

    class Catalog:
        poisoned = False
        changed = False
        mutate = None
        fail_objects = False

        def __init__(self):
            self.statements = []
            self.checks = 0

        def _check_objects(self):
            if self.poisoned or self.fail_objects:
                raise V2IssuanceUnavailable()
            return (self,)

        def check(self):
            self.checks += 1
            self._check_objects()

        def answer(self, tag, values):
            if tag == "role":
                return [(False, False, False, False, False, 0, [], [], 44, True, True, False)]
            if tag == "schema":
                return [(2200, 100 + self.changed, True)]
            if tag == "function":
                name = values["name"]
                return [
                    (
                        200 + list(FUNCTIONS).index(name),
                        100,
                        FUNCTIONS[name],
                        True,
                        list(FUNCTION_CONFIGS[name]),
                        "v",
                        True,
                        0,
                        "f",
                        "plpgsql",
                        False,
                        False,
                    )
                ]
            if tag == "target":
                return [(oids[values["target"].removeprefix("public.")],)]
            if tag == "table":
                name = values["name"]
                allowed = name not in (
                    storage.V2Invalidation.__tablename__,
                    V2BindingBirth.__tablename__,
                    V2TokenBirth.__tablename__,
                )
                return [
                    (
                        oids[name],
                        100,
                        oids[name] + 100,
                        0,
                        "r",
                        False,
                        False,
                        False,
                        True,
                        allowed,
                        False,
                        False,
                        False,
                        False,
                    )
                ]
            if tag == "toast":
                return []
            if tag == "column_privileges":
                return [(False,)]
            if tag == "index":
                return [(True, True, True, True, None, None, "btree")]
            name = by_oid[values["oid"]]
            if tag == "columns":
                return [
                    (
                        c.name,
                        (
                            "bigint"
                            if isinstance(c.type, storage.BigInteger)
                            else "text" if isinstance(c.type, storage.Text) else f"character varying({c.type.length})"
                        ),
                        not c.nullable,
                    )
                    for c in tables[name].columns
                ]
            if tag == "constraints":
                rows = []
                for i, c in enumerate(storage.CONSTRAINTS[name]):
                    target = oids[c[4][0]] if c[4] else 0
                    index = 10000 + values["oid"] * 100 + i if c[1] in ("p", "u", "f") else 0
                    rows.append(
                        (
                            20000 + values["oid"] * 100 + i,
                            c[0],
                            c[1],
                            c[2],
                            c[3],
                            True,
                            False,
                            False,
                            True,
                            0,
                            0,
                            target,
                            index,
                            "synthetic-expression",
                        )
                    )
                if name == V2Offer.__tablename__:
                    rows.append(
                        (30000, "v2_complete", "t", "synthetic-trigger", None, True, True, True, True, 0, 0, 0, 0, None)
                    )
                return sorted(rows, key=lambda row: row[1])
            if tag == "triggers":
                expected = {
                    "v2_immutable": ("social_session_v2_immutable", 27, False, False),
                    "v2_no_truncate": ("social_session_v2_immutable", 34, False, False),
                }
                if name not in (
                    storage.V2Invalidation.__tablename__,
                    V2BindingBirth.__tablename__,
                    V2TokenBirth.__tablename__,
                ):
                    expected["v2_insert"] = ("social_session_v2_guard", 7, False, False)
                if name == V2Offer.__tablename__:
                    expected["v2_complete"] = ("social_session_v2_complete", 5, True, True)
                return [
                    (
                        40000 + i,
                        200 + list(FUNCTIONS).index(v[0]),
                        k,
                        *v,
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
                    for i, (k, v) in enumerate(sorted(expected.items()))
                ]
            raise AssertionError("unexpected catalog selector")

        def sql(self, sql, values=None):
            values = values or {}
            self.statements.append(sql)
            self.check()
            marker = re.search(r"/\* UBID_CATALOG_FAMILIES ([a-z0-9_=,;]+) \*/", sql)
            if not sql.startswith("SELECT pg_catalog.jsonb_build_array(") and marker is None:
                # Old unbatched attestation, for a real regression-before run.
                tag = classify_catalog_select(sql)
                result = Rows(self.answer(tag, values))
            else:
                matches, selections = [], []
                if marker is not None:
                    # The fixed transport groups a scan once for each family.
                    # All original row/type/cardinality assertions below remain.
                    for family in marker[1].split(";"):
                        tag, indexes = family.split("=")
                        query = storage._CATALOG_SELECTS[tag][1]
                        names = set(re.findall(r"(?<!:):([a-z_]+)", query))
                        for index in indexes.split(","):
                            bound = {name: values["catalog_" + index + "_" + name] for name in names}
                            selections.append((int(index), tag, query, bound))
                else:
                    # Retain the previous transport for regression comparison.
                    for tag, (_, query, width) in storage._CATALOG_SELECTS.items():
                        pattern = re.escape(query)
                        for name in set(re.findall(r"(?<!:):([a-z_]+)", query)):
                            pattern = pattern.replace(re.escape(":" + name), ":catalog_[0-9]+_" + name)
                        for hit in re.finditer(pattern, sql):
                            parameters = re.findall(r":catalog_([0-9]+)_([a-z_]+)", hit[0])
                            assert len({i for i, _ in parameters}) <= 1
                            bound = {name: values["catalog_" + i + "_" + name] for i, name in parameters}
                            selections.append((hit.start(), tag, query, bound))
                for position, tag, query, bound in selections:
                    width = storage._CATALOG_SELECTS[tag][2]
                    raw = []
                    for row in self.answer(tag, bound):
                        assert len(row) == width
                        row = list(row)
                        for index, expression in oid_fields.get(tag, {}).items():
                            value = row[index]
                            if value is not None and expression + "::bigint" not in query:
                                row[index] = str(value)
                        raw.append(
                            {"f" + str(i + 1): "\\x" + v.hex() if type(v) is bytes else v for i, v in enumerate(row)}
                        )
                    matches.append((position, tag, raw))
                matches.sort(key=lambda item: item[0])
                # PostgreSQL JSONB decoding returns native JSON scalar types;
                # ORM metadata's quoted_name subtype must not leak from this double.
                observed = json.loads(json.dumps([row for _, _, row in matches]))
                if self.mutate:
                    observed = self.mutate(observed)
                result = Rows([(observed,)])
            self.check()
            return result

    return storage, Catalog()


def classify_catalog_select(sql):
    # Exact phase labels for the OLD source's real SQL expressions. The new
    # batch budget test does not hide missing batch support behind a fake port.
    if " AS member_roles" in sql:
        return "role"
    if "FROM pg_catalog.pg_namespace WHERE" in sql:
        return "schema"
    if "FROM pg_catalog.pg_proc p" in sql:
        return "function"
    if "SELECT c.oid,c.relowner,c.reltype" in sql:
        return "table"
    if "FROM pg_catalog.pg_attribute" in sql:
        return "columns"
    if "SELECT pg_has_role" in sql:
        return "toast"
    if "SELECT has_any_column_privilege" in sql:
        return "column_privileges"
    if "FROM pg_catalog.pg_trigger" in sql:
        return "triggers"
    if "FROM pg_catalog.pg_constraint" in sql:
        return "constraints"
    if "SELECT to_regclass" in sql:
        return "target"
    if "SELECT indisvalid" in sql:
        return "index"
    raise AssertionError("unknown catalog SQL")


def test_attestation_uses_three_fresh_catalog_batches(catalog_batch_graph):
    storage, catalog = catalog_batch_graph
    assert storage.attest(catalog)
    assert len(catalog.statements) == 3


def test_batched_catalog_preserves_exact_unbatched_fingerprint(catalog_batch_graph):
    storage, catalog = catalog_batch_graph
    original = storage._attest_catalog(catalog)
    catalog.statements.clear()
    assert storage.attest(catalog) == original
    assert len(catalog.statements) == 3
    assert catalog.checks > 0


def test_catalog_observations_are_fresh_each_attestation(catalog_batch_graph):
    storage, catalog = catalog_batch_graph
    first = storage.attest(catalog)
    catalog.changed = True
    assert storage.attest(catalog) != first
    assert len(catalog.statements) == 6


@pytest.mark.parametrize("wrong", [None, {}, [], [[]], [None] * 100])
def test_catalog_batch_malformed_envelope_denies_and_poisons(catalog_batch_graph, wrong):
    storage, catalog = catalog_batch_graph
    catalog.mutate = lambda _rows: wrong
    with pytest.raises(V2IssuanceUnavailable):
        storage.attest(catalog)
    assert catalog.poisoned


@pytest.mark.parametrize("wrong", [[], {"f1": 1}, {"f1": 1, "f2": 2}, {"f" + str(i): None for i in range(1, 14)}])
def test_catalog_batch_malformed_row_denies(catalog_batch_graph, wrong):
    storage, catalog = catalog_batch_graph

    def mutate(rows):
        rows[0] = [wrong]
        return rows

    catalog.mutate = mutate
    with pytest.raises(V2IssuanceUnavailable):
        storage.attest(catalog)
    assert catalog.poisoned


@pytest.mark.parametrize("wrong", [True, 1, "yes", None])
def test_catalog_batch_rejects_changed_privileged_role(catalog_batch_graph, wrong):
    storage, catalog = catalog_batch_graph

    def mutate(rows):
        rows[0][0]["f1"] = wrong
        return rows

    catalog.mutate = mutate
    with pytest.raises(V2IssuanceUnavailable):
        storage.attest(catalog)
    assert catalog.poisoned


def test_catalog_batch_preserves_cardinality(catalog_batch_graph):
    storage, catalog = catalog_batch_graph

    def mutate(rows):
        rows[1].append(dict(rows[1][0]))
        return rows

    catalog.mutate = mutate
    with pytest.raises(V2IssuanceUnavailable):
        storage.attest(catalog)
    assert catalog.poisoned


def test_catalog_snapshot_rejects_unknown_selector_and_object_change(catalog_batch_graph):
    storage, catalog = catalog_batch_graph
    observation = storage._CatalogObservation(catalog)
    with pytest.raises(V2IssuanceUnavailable):
        observation.sql("SELECT 1")
    catalog.fail_objects = True
    with pytest.raises(V2IssuanceUnavailable):
        observation.sql(storage._CATALOG_SELECTS["role"][0])


def test_catalog_rows_preserve_null_arrays_bytes_and_isolate_mutation():
    from app.services.social_session_issuance_v2_storage import _CatalogRows

    rows = _CatalogRows([(None, True, 1, "1", [1, None, [True]], b"\x00")])
    first = rows.one()
    first[4].append("changed")
    assert rows.one() == (None, True, 1, "1", [1, None, [True]], b"\x00")
    with pytest.raises(V2IssuanceUnavailable):
        rows.scalar_one()


@pytest.mark.parametrize("quote", [None, False, True])
def test_catalog_keys_normalize_real_sqlalchemy_metadata_names(quote):
    from sqlalchemy.sql.elements import quoted_name

    from app.services import social_session_issuance_v2_storage as storage

    name = quoted_name("social_session_v2_offers", quote)
    assert type(name) is quoted_name
    sql = storage._CATALOG_SELECTS["table"][0]
    assert storage._catalog_key(sql, {"name": name}) == storage._catalog_key(sql, {"name": str(name)})
    # Verify the actual mappings, independently of a handcrafted plain-string port.
    for table in V2Base.metadata.sorted_tables:
        assert type(table.name) is quoted_name
        assert storage._catalog_key(sql, {"name": table.name}) == storage._catalog_key(sql, {"name": str(table.name)})


def test_catalog_keys_reject_unrecognized_string_subclasses():
    from app.services import social_session_issuance_v2_storage as storage

    class UnrecognizedName(str):
        pass

    with pytest.raises(V2IssuanceUnavailable):
        storage._catalog_key(
            storage._CATALOG_SELECTS["table"][0], {"name": UnrecognizedName("social_session_v2_offers")}
        )


def test_catalog_metadata_normalization_does_not_authorize_unknown_selector(catalog_batch_graph):
    from sqlalchemy.sql.elements import quoted_name

    storage, catalog = catalog_batch_graph
    observation = storage._CatalogObservation(catalog)
    with pytest.raises(V2IssuanceUnavailable):
        observation.sql(storage._CATALOG_SELECTS["table"][0], {"name": quoted_name("unregistered_table", True)})


@pytest.mark.parametrize(
    "tag", ["schema", "triggers", "constraints", "function", "table", "legacy_function", "legacy_table", "target"]
)
def test_catalog_json_identity_fields_use_explicit_numeric_transport(tag):
    from app.services import social_session_issuance_v2_storage as storage

    # Closed positions from the original SELECT types, including absent OID 0.
    expected = {
        "schema": {0: "oid", 1: "nspowner"},
        "triggers": {0: "t.oid", 1: "t.tgfoid", 14: "t.tgparentid"},
        "constraints": {0: "k.oid", 10: "k.conparentid", 11: "k.confrelid", 12: "k.conindid"},
        "function": {0: "p.oid", 1: "p.proowner"},
        "table": {0: "c.oid", 1: "c.relowner", 2: "c.reltype", 3: "c.reltoastrelid"},
        "legacy_function": {0: "p.oid", 1: "p.proowner"},
        "legacy_table": {0: "c.oid", 1: "c.relowner"},
        "target": {0: "to_regclass(:target)::oid"},
    }
    source, json_query, width = storage._CATALOG_SELECTS[tag]
    for position, expression in expected[tag].items():
        assert position < width
        assert expression + "::bigint" not in source
        assert json_query.count(expression + "::bigint") == 1


def test_catalog_batch_rejects_numeric_string_oid_instead_of_coercing(catalog_batch_graph):
    storage, catalog = catalog_batch_graph

    def mutate(rows):
        # First table-shaped result in the first batch. Keep its exact shape,
        # but return the wrong native scalar type, as the previous JSON did.
        table = next(group[0] for group in rows if group and len(group[0]) == 14)
        table["f1"] = str(table["f1"])
        return rows

    catalog.mutate = mutate
    with pytest.raises(V2IssuanceUnavailable):
        storage.attest(catalog)
    assert catalog.poisoned


@pytest.mark.parametrize("depth", [1, 2, 3])
def test_catalog_plan_nested_execute_has_two_fresh_guard_checks(graph, monkeypatch, depth):
    from app.services.social_session_issuance_v2_authority import BoundSession

    with SessionDouble(graph) as session, session.begin():
        guards = [TransactionGuard(session)]
        for _ in range(depth):
            guards.append(TransactionGuard(BoundSession(guards[-1])))
        connection = session.connection()
        execute = connection.execute
        calls = []

        def capture(statement, values=None):
            calls.append(str(statement))
            return execute(statement, values)

        monkeypatch.setattr(connection, "execute", capture)
        rows = guards[-1].execute(select(User).where(User.id == USER_ID)).scalars().all()
        assert len(rows) == 1 and rows[0].id == USER_ID
        assert len(calls) == 2
        assert all("pg_current_xact_id" in sql for sql in calls)
        assert all(guard.xid == "42" and not guard.poisoned for guard in guards)


@pytest.mark.parametrize("change", ["xid", "physical", "root", "savepoint", "parent_poison"])
def test_catalog_plan_leaf_execute_still_rejects_changes_during_data_read(graph, monkeypatch, change):
    from app.services.social_session_issuance_v2_authority import BoundSession

    with SessionDouble(graph) as session, session.begin():
        parent = TransactionGuard(session)
        child = TransactionGuard(BoundSession(parent))
        connection = session.connection()
        execute = session.execute

        def changed(statement, *, bind_arguments=None):
            result = execute(statement, bind_arguments=bind_arguments)
            if change == "xid":
                connection.xid = "43"
            elif change == "physical":
                connection.connection.dbapi_connection = SimpleNamespace(autocommit=False)
            elif change == "root":
                monkeypatch.setattr(session, "get_transaction", lambda: SimpleNamespace(is_active=True))
            elif change == "savepoint":
                connection.actual.begin_nested()
            else:
                parent.poisoned = True
            return result

        monkeypatch.setattr(session, "execute", changed)
        with pytest.raises(V2IssuanceUnavailable):
            child.execute(select(User).where(User.id == USER_ID))
        assert child.poisoned
        if change == "savepoint":
            connection.actual.get_nested_transaction().rollback()


def test_catalog_plan_scans_each_catalog_family_once_and_keeps_every_selector(catalog_batch_graph):
    storage, catalog = catalog_batch_graph
    original = storage._attest_catalog(catalog)
    catalog.statements.clear()
    assert storage.attest(catalog) == original
    assert len(catalog.statements) == 3
    for sql in catalog.statements:
        marker = re.search(r"/\* UBID_CATALOG_FAMILIES ([a-z0-9_=,;]+) \*/", sql)
        assert marker is not None
        groups = [part.split("=") for part in marker[1].split(";")]
        indexes = [int(index) for _, items in groups for index in items.split(",")]
        assert sorted(indexes) == list(range(len(indexes)))
        for family, (tag, _) in enumerate(groups):
            assert sql.count("catalog_family_" + str(family) + " AS MATERIALIZED (") == 1
            if tag in (
                "function",
                "legacy_function",
                "table",
                "legacy_table",
                "columns",
                "constraints",
                "triggers",
                "toast",
                "index",
            ):
                assert sql.count("catalog_scan_" + str(family) + " AS MATERIALIZED (") == 1


@pytest.mark.parametrize(
    "specifications", [[], [("table", {"name": "x"}), ("table", {"name": "x"})], [("table", {"unexpected": "x"})]]
)
def test_catalog_plan_rejects_missing_duplicate_or_unknown_selectors(specifications):
    from app.services import social_session_issuance_v2_storage as storage

    with pytest.raises(V2IssuanceUnavailable):
        storage._catalog_fetch_plan(specifications)


def test_catalog_plan_keeps_legacy_name_resolution_and_numeric_oid_projection():
    from app.services import social_session_issuance_v2_storage as storage

    sql, parameters, expected = storage._catalog_fetch_plan(
        [("legacy_table", {"name": "oauth_tokens"}), ("legacy_table", {"name": "users"}), ("triggers", {"oid": 17})]
    )
    assert "to_regclass(c.relname)::oid = c.oid" in sql
    assert "t.oid::bigint" in sql and "t.tgfoid::bigint" in sql and "t.tgparentid::bigint" in sql
    assert parameters["catalog_family_0_selectors"] == ["oauth_tokens", "users"]
    assert parameters["catalog_family_1_selectors"] == [17]
    assert len(expected) == 3


def test_completion_original_json_carrier_keeps_typed_fingerprint(catalog_batch_graph):
    storage, catalog = catalog_batch_graph
    expected = storage._attest_catalog(catalog)
    catalog.statements.clear()
    assert storage.attest(catalog) == expected
    assert len(catalog.statements) == 3
    for sql in catalog.statements:
        assert "pg_catalog.json_build_array(" in sql
        assert "pg_catalog.json_agg(" in sql
        assert "pg_catalog.row_to_json(ROW(" in sql
        assert "pg_catalog.to_jsonb(ROW(" not in sql


def test_completion_plan_cache_contains_no_selectors_or_observations():
    from app.services import social_session_issuance_v2_storage as storage

    storage._completion_catalog_plans.clear()
    sql, first, expected = storage._catalog_fetch_plan([("table", {"name": "first"}), ("columns", {"oid": 17})])
    assert len(storage._completion_catalog_plans) == 1
    again, second, next_expected = storage._catalog_fetch_plan(
        [("table", {"name": "second"}), ("columns", {"oid": 29})]
    )
    assert again is sql
    assert first["catalog_family_0_selectors"] == ["first"]
    assert second["catalog_family_0_selectors"] == ["second"]
    assert second["catalog_family_1_selectors"] == [29]
    assert expected != next_expected
    second["catalog_family_0_selectors"].append("mutation")
    assert first["catalog_family_0_selectors"] == ["first"]
    stored = next(iter(storage._completion_catalog_plans.values()))
    assert stored == (sql, (("catalog_family_0_selectors", 0, "name"), ("catalog_family_1_selectors", 1, "oid")))
