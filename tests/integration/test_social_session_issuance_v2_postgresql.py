"""Opt-in PostgreSQL 16 verification, synthetic graph only.

An external operator must authorize/provision an isolated cluster and exact empty
prerequisite schema under distinct DDL/runtime roles. No cluster/role/key setup,
DATABASE_URL fallback, Unix socket, live/default target or automatic teardown.
The external runner owns verified cluster teardown. Skips prove no native effect.
"""

import hashlib
import json
import os
import secrets
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from queue import Queue
from threading import Event

import pytest
from coincurve import PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import create_engine, null, select, text, update
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.pool import NullPool

from app import tokens
from app.models import (
    CurrentEntitlementEvidence,
    OAuthBrowserGeneration,
    OAuthClient,
    OAuthSessionGeneration,
    OAuthToken,
    Session,
    User,
)
from app.services import oauth_bearer_validation
from app.services import social_messaging_mobile_pre_enrollment_v2 as v2
from app.services.current_entitlement_evidence import CONTRACT_VERSION
from app.services.oauth_bearer_validation import TOKEN_CONTRACT
from app.services.oauth_scope_policy import SCOPE_POLICY_VERSION
from app.services.oauth_session_lifecycle import SqlAlchemyOAuthSessionLifecycle
from app.services.social_messaging_device_contract import messaging_device_binding_id
from app.services.social_messaging_device_proof_profile import x25519_public_key_commitment_v1
from app.services.social_session_issuance import SocialSessionIssuer
from app.services.social_session_issuance_v2 import NativeV2SessionIssuer
from app.services.social_session_issuance_v2_contract import V2IssuanceUnavailable, canonical
from app.services.social_session_issuance_v2_storage import V2Base, V2Invalidation, V2Issuance, V2Parent

ROOT = Path(__file__).resolve().parents[2]
PREFIX = "UBID_V2_ISSUANCE_REHEARSAL_"
ACK = "DISPOSABLE-SYNTHETIC-V2-ISSUANCE-APPLY"
DATABASE = "ubid_v2_issuance_rehearsal"
DDL_ROLE = "ubid_v2_issuance_ddl"
RUNTIME_ROLE = "ubid_v2_issuance_runtime"
PREREQUISITES = {
    "users",
    "oauth_clients",
    "oauth_tokens",
    "sessions",
    "oauth_codes",
    "current_entitlement_evidence",
    "oauth_browser_generations",
    "oauth_session_generations",
    "oauth_session_code_bindings",
    "social_messaging_device_bindings",
    "social_messaging_device_binding_authorization_evidence",
    "social_messaging_device_binding_authorization_replay",
    "social_messaging_device_authorization_requests",
    "social_messaging_device_authorization_binding_owners",
    "social_messaging_mobile_operations",
    "social_messaging_mobile_acceptances",
    "social_messaging_mobile_exchanges",
    "social_messaging_mobile_session_handoffs",
    "social_session_issuers",
    "social_session_pairing_parents",
    "social_session_issuances",
}


def guarded_target_configuration():
    if os.environ.get(PREFIX + "ACK") is None:
        pytest.skip("explicit isolated V2 PostgreSQL rehearsal not authorized")
    assert os.environ[PREFIX + "ACK"] == ACK
    port = int(os.environ[PREFIX + "PORT"])
    assert 49152 <= port <= 65535
    data = Path(os.environ[PREFIX + "DATA"]).resolve()
    assert data.name == "data" and data.parent.parent == Path("/tmp")
    assert data.parent.name.startswith("ubid-v2-issuance-rehearsal-")
    assert len(data.parent.name.removeprefix("ubid-v2-issuance-rehearsal-")) >= 16
    assert (data / "PG_VERSION").read_text().strip() == "16"
    urls = []
    for suffix, role in (("DDL_DSN", DDL_ROLE), ("RUNTIME_DSN", RUNTIME_ROLE)):
        url = make_url(os.environ[PREFIX + suffix])
        assert url.drivername == "postgresql+psycopg2" and url.host == "127.0.0.1"
        assert url.port == port and url.database == DATABASE and url.username == role
        assert url.password is None and not url.query
        urls.append(url)
    return urls, data, port


@pytest.fixture(scope="module")
def native_target():
    urls, data, port = guarded_target_configuration()
    ddl, runtime = [
        create_engine(
            url,
            poolclass=NullPool,
            hide_parameters=True,
            connect_args={"connect_timeout": 3, "options": "-c lock_timeout=2000 -c statement_timeout=8000"},
        )
        for url in urls
    ]
    try:
        for engine, role in ((ddl, DDL_ROLE), (runtime, RUNTIME_ROLE)):
            with engine.connect() as c:
                assert tuple(
                    c.execute(
                        text(
                            "SELECT current_database(),current_user,session_user,pg_catalog.host(inet_server_addr()),"
                            "inet_server_port()"
                        )
                    ).one()
                ) == (DATABASE, role, role, "127.0.0.1", port)
                if role == DDL_ROLE:
                    assert Path(c.execute(text("SHOW data_directory")).scalar_one()).resolve() == data
                    assert c.execute(text("SHOW listen_addresses")).scalar_one() == "127.0.0.1"
                    assert c.execute(text("SHOW unix_socket_directories")).scalar_one() == ""
        with ddl.begin() as c:
            names = set(
                c.execute(
                    text(
                        "SELECT relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n "
                        "ON n.oid=c.relnamespace WHERE n.nspname='public' AND relkind IN ('r','p','v','m','f')"
                    )
                ).scalars()
            )
            assert names == PREREQUISITES
            for name in sorted(PREREQUISITES):
                assert c.execute(text(f"SELECT count(*) FROM public.{name}")).scalar_one() == 0
            c.exec_driver_sql((ROOT / "migrations/2026-10-10_social_session_issuance_v2_provenance_v1.sql").read_text())
            for table in V2Base.metadata.sorted_tables:
                c.exec_driver_sql(f"GRANT SELECT ON public.{table.name} TO {RUNTIME_ROLE}")
            for name in ("offers", "parents", "acceptances", "issuances"):
                c.exec_driver_sql(f"GRANT INSERT ON public.social_session_v2_{name} TO {RUNTIME_ROLE}")
        yield ddl, runtime
    finally:
        ddl.dispose()
        runtime.dispose()
        # External runner must stop/remove the exact disposable cluster and
        # record teardown. Retaining synthetic ledgers here is deliberate.


@pytest.fixture
def native_graph(native_target, monkeypatch, request):
    ddl, runtime = native_target
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(tokens, "get_signing_key", lambda _directory: ("synthetic-oauth", key))
    monkeypatch.setattr(
        oauth_bearer_validation, "get_key_by_kid", lambda _directory, kid: key if kid == "synthetic-oauth" else None
    )
    issuer = "https://synthetic-ubid.example"
    client = "synthetic-" + secrets.token_hex(8)
    user_id = str(uuid.uuid4())
    signer = PrivateKey()
    subject = signer.public_key_xonly.format().hex()
    token_id = secrets.token_hex(16)
    browser_id = secrets.token_hex(32)
    session_id = secrets.token_hex(32)
    start = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(seconds=1)
    expiry = start + timedelta(seconds=15 if getattr(request, "param", None) == "short" else 600)
    bearer = tokens.issue_rs256_jwt(
        subject,
        dict(
            aud=client,
            iat=int(start.timestamp()),
            exp=int(expiry.timestamp()),
            jti=token_id,
            scope="openid profile",
            token_use="access",
            token_contract=TOKEN_CONTRACT,
        ),
        cfg={"JWT_ISSUER": issuer, "JWKS_DIR": "synthetic-injected-port"},
    )
    with OrmSession(ddl) as s, s.begin():
        s.add(User(id=user_id, pubkey=subject, is_active=True))
        s.add(
            OAuthClient(
                client_id=client,
                client_secret="synthetic",
                client_name="synthetic",
                redirect_uris=[],
                grant_types=["authorization_code"],
                response_types=["code"],
                scope="openid profile",
                metadata_json={"trust_class": "operator_managed"},
                is_active=True,
            )
        )
        s.flush()
        s.add(
            SocialSessionIssuer(
                client_id=client,
                backend_id="synthetic-backend",
                service_principal="synthetic-principal",
                is_active=True,
            )
        )
        s.add(
            OAuthBrowserGeneration(
                generation_id=browser_id,
                user_id=user_id,
                client_id=client,
                subject=subject,
                proof_id=secrets.token_hex(32),
                created_at=start.replace(tzinfo=None),
                expires_at=expiry.replace(tzinfo=None),
                is_active=True,
            )
        )
        s.add(
            OAuthToken(
                id=token_id,
                access_token=hashlib.sha256(bearer.encode()).hexdigest(),
                client_id=client,
                user_id=user_id,
                token_type="Bearer",
                scope="openid profile",
                created_at=start.replace(tzinfo=None),
                access_token_expires_at=expiry.replace(tzinfo=None),
                is_revoked=False,
                metadata_json=dict(
                    token_contract=TOKEN_CONTRACT,
                    token_use="access",
                    issuer=issuer,
                    audience=client,
                    kid="synthetic-oauth",
                    digest_algorithm="sha256",
                    scope_policy_version=SCOPE_POLICY_VERSION,
                ),
            )
        )
        s.add(
            Session(
                session_id=session_id,
                user_id=user_id,
                session_type="web",
                created_at=start.replace(tzinfo=None),
                expires_at=expiry.replace(tzinfo=None),
                is_active=True,
                metadata_json=null(),
            )
        )
        s.flush()
        metadata_is_sql_null = s.execute(
            select(Session.metadata_json.is_(None)).where(Session.session_id == session_id)
        ).scalar_one()
        assert metadata_is_sql_null is True
        s.add(
            OAuthSessionGeneration(
                token_id=token_id,
                browser_generation_id=browser_id,
                session_id=session_id,
                user_id=user_id,
                client_id=client,
                subject=subject,
            )
        )
        s.add(
            CurrentEntitlementEvidence(
                evidence_id=str(uuid.uuid4()),
                contract_version=CONTRACT_VERSION,
                subject_pubkey=subject,
                identity_class="full",
                current_full_relation_satisfied=True,
                evidence_source="synthetic",
                evidence_version="v1",
                source_evidence_sha256=secrets.token_hex(32),
                observed_at=start,
                created_at=start,
                valid_until=expiry,
                revoked_at=None,
            )
        )
    # Rebuild fresh canonical bytes without editing any fixed fixture.
    vector = json.loads((ROOT / "tests/fixtures/social_preacceptance_ed25519_handoff_v2.json").read_bytes())["vector"]
    content = json.loads(json.loads(vector["authorizationWire"])["content"])
    claim = content["authorization"]
    request, device, operation = [secrets.token_hex(32) for _ in range(3)]
    public = x25519.X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    end = start + timedelta(seconds=300)

    def stamp(date):
        return date.isoformat(timespec="seconds").replace("+00:00", "Z")

    claim.update(
        subject=subject,
        requestId=request,
        deviceId=device,
        publicKey=public,
        issuedAt=stamp(start),
        expiresAt=stamp(end),
        bindingValidFrom=stamp(start),
        bindingExpiresAt=stamp(start + timedelta(days=1)),
    )
    binding_id = messaging_device_binding_id(
        subject=subject,
        device_id=device,
        public_key=public,
        binding_version=1,
        valid_from=start,
        expires_at=start + timedelta(days=1),
        operation="register",
        prior_binding_id=None,
        request_id=request,
    )
    semantic = canonical(content)
    secret, verifier, delivery = [secrets.token_hex(32) for _ in range(3)]
    pre = json.loads(vector["preEnrollmentWire"])
    pre.update(
        subject=subject,
        requestId=request,
        deviceId=device,
        pairingId=operation,
        x25519BindingId=binding_id,
        issuedAt=int(start.timestamp()) * 1000,
        expiresAt=int(end.timestamp()) * 1000,
        x25519PublicKeyCommitment=x25519_public_key_commitment_v1(public),
        bindingAuthorizationDigest=hashlib.sha256(semantic.encode()).hexdigest(),
    )
    context = canonical(
        dict(
            createdAt=stamp(start),
            expiresAt=stamp(end),
            desktopContext=secrets.token_hex(32),
            pairingId=operation,
            secretCommitment=v2.pairing_secret_commitment_v2(secret),
            exchangeCommitment=v2.phone_exchange_commitment_v2(verifier),
        )
    )
    wire = v2.canonical_authorization_envelope_v2_bytes(
        content=semantic, context_wire=context, pre_enrollment_wire=canonical(pre)
    ).decode()
    approval = v2.canonical_approval_event_v2_bytes(
        wire, signature=signer.sign_schnorr(bytes.fromhex(v2.approval_event_id_v2(wire))).hex()
    ).decode()
    lifecycle = SqlAlchemyOAuthSessionLifecycle(
        lambda: OrmSession(runtime),
        client_id=client,
        token_config={"JWT_ISSUER": issuer, "JWKS_DIR": "synthetic-injected-port"},
        clock=lambda: datetime.now(timezone.utc),
    )
    owner = NativeV2SessionIssuer(lifecycle=lifecycle, backend_id="synthetic-backend", principal="synthetic-principal")
    owner.create_offer(wire, desktop_bearer=bearer)
    proofs = dict(
        approval_wire=approval,
        secret=secret,
        verifier=verifier,
        delivery_key=delivery,
        possession_proof=v2.pairing_possession_proof_v2(secret, v2.authorization_v2_digest(wire)),
        approver_bearer=bearer,
    )
    return ddl, runtime, owner, operation, proofs, token_id


def test_native_committed_producer_reader_and_retry(native_graph):
    ddl, runtime, owner, operation, proofs, parent = native_graph
    first = owner.issue(operation, **proofs)
    assert owner.recover(operation, **proofs) == first
    with OrmSession(runtime) as s, s.begin():
        r = owner._reader(s)
        assert r.read(first["receipt"]["issuanceId"]).facts.parent_token_id == parent
    with pytest.raises(V2IssuanceUnavailable):
        owner.recover(operation, **(proofs | dict(delivery_key=secrets.token_hex(32))))


def test_native_causal_no_late_adoption_or_mutation(native_graph):
    ddl, runtime, owner, operation, proofs, parent = native_graph
    with OrmSession(runtime) as s:
        p = s.execute(select(V2Parent).where(V2Parent.operation_id == operation)).scalar_one()
        values = {c.name: getattr(p, c.key) for c in p.__table__.columns}
    with ddl.begin() as c:
        c.exec_driver_sql("ALTER TABLE public.social_session_v2_parents DISABLE TRIGGER v2_immutable")
        c.execute(text("DELETE FROM public.social_session_v2_parents WHERE operation_id=:op"), {"op": operation})
        c.exec_driver_sql("ALTER TABLE public.social_session_v2_parents ENABLE TRIGGER v2_immutable")
        with pytest.raises(Exception):
            with c.begin_nested():
                c.execute(V2Parent.__table__.insert().values(**values))
        # Rollback all DDL/history tampering, preserving the complete original row.
        c.rollback()
    owner.issue(operation, **proofs)
    with pytest.raises(Exception):
        with runtime.begin() as c:
            c.execute(V2Issuance.__table__.update().values(revision="00" * 32))
    with pytest.raises(Exception):
        with runtime.begin() as c:
            c.exec_driver_sql("SELECT public.social_session_v2_guard()")


def test_native_parent_invalidation_permanent_history(native_graph):
    ddl, runtime, owner, operation, proofs, parent = native_graph
    first = owner.issue(operation, **proofs)
    with OrmSession(ddl) as s, s.begin():
        s.execute(update(OAuthToken).where(OAuthToken.id == parent).values(is_revoked=True))
    with OrmSession(runtime) as s, s.begin():
        issuance = s.execute(select(V2Issuance).where(V2Issuance.operation_id == operation)).scalar_one()
        assert s.get(OAuthToken, issuance.token_id).is_revoked is True
        assert s.get(OAuthToken, parent).is_revoked is True
        assert s.get(V2Invalidation, operation).operation_id == operation
        mapping = s.get(V2Parent, operation)
        assert s.get(Session, mapping.session_id).is_active is False
    result = owner.recover(operation, **proofs)
    assert result["receipt"] == first["receipt"] and result["currentActive"] is False
    assert result["viewerAccessToken"] is result["subject"] is None
    with pytest.raises(Exception):
        with OrmSession(ddl) as s, s.begin():
            s.execute(update(OAuthToken).where(OAuthToken.id == parent).values(is_revoked=False))


def test_native_concurrent_first_writers_converge(native_graph):
    ddl, runtime, owner, operation, proofs, parent = native_graph
    from sqlalchemy import event

    # A completed real lock wait is part of this test's specification.
    # The ordinary two-second timeout tests denial, not convergence after wait.
    bounded_runtime = create_engine(
        runtime.url,
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={"connect_timeout": 3, "options": "-c lock_timeout=30000 -c statement_timeout=30000"},
    )
    backend = Queue()

    def connected(connection, _record):
        backend.put(connection.get_backend_pid())

    event.listen(bounded_runtime, "connect", connected)
    lifecycle = SqlAlchemyOAuthSessionLifecycle(
        lambda: OrmSession(bounded_runtime),
        client_id=owner.lifecycle.client_id,
        token_config=owner.lifecycle._config,
        clock=owner.lifecycle._now,
    )
    concurrent_owner = NativeV2SessionIssuer(
        lifecycle=lifecycle, backend_id=owner.backend_id, principal=owner.principal
    )
    try:
        with OrmSession(ddl) as blocker:
            transaction = blocker.begin()
            user = blocker.execute(select(V2Parent.user_id).where(V2Parent.operation_id == operation)).scalar_one()
            blocker.execute(select(User).where(User.id == user).with_for_update()).scalar_one()
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(concurrent_owner.issue, operation, **proofs) for _ in range(2)]
                try:
                    pids = [backend.get(timeout=10) for _ in range(2)]
                    assert len(set(pids)) == 2
                    limit = time.monotonic() + 10
                    observed = False
                    while time.monotonic() < limit:
                        with runtime.connect() as monitor:
                            states = monitor.execute(
                                text(
                                    "SELECT pid,wait_event_type='Lock' FROM pg_catalog.pg_stat_activity "
                                    "WHERE pid IN (:first,:second)"
                                ),
                                {"first": pids[0], "second": pids[1]},
                            ).all()
                        if len(states) == 2 and all(row[1] is True for row in states):
                            observed = True
                            break
                        if any(future.done() for future in futures):
                            break
                        time.sleep(0.01)
                    assert observed, "both native first writers must be observed waiting for locks"
                    assert all(not future.done() for future in futures)
                finally:
                    transaction.rollback()
                results = [future.result(timeout=40) for future in futures]
        assert results[0] == results[1]
        assert results[0]["currentActive"] is True
        with OrmSession(runtime) as session, session.begin():
            from app.services.social_session_issuance_v2_storage import V2Acceptance

            assert (
                len(session.execute(select(V2Acceptance).where(V2Acceptance.operation_id == operation)).scalars().all())
                == 1
            )
            rows = session.execute(select(V2Issuance).where(V2Issuance.operation_id == operation)).scalars().all()
            assert len(rows) == 1
            assert session.get(OAuthToken, rows[0].token_id).is_revoked is False
        assert owner.recover(operation, **proofs) == results[0]
    finally:
        event.remove(bounded_runtime, "connect", connected)
        bounded_runtime.dispose()


def _native_reader_wait(native_graph, *, cross_expiry):
    ddl, runtime, owner, operation, proofs, parent = native_graph
    first = owner.issue(operation, **proofs)
    with OrmSession(runtime) as s, s.begin():
        assert owner._reader(s).read(first["receipt"]["issuanceId"]).facts.token_id
    backend = Queue()
    released = Event()
    observed_clocks = []
    deadline = first["receipt"]["expiresAt"] / 1000
    with OrmSession(ddl) as blocker:
        transaction = blocker.begin()
        parent_row = blocker.execute(select(V2Parent).where(V2Parent.operation_id == operation)).scalar_one()
        blocker.execute(select(User).where(User.id == parent_row.user_id).with_for_update()).scalar_one()

        def read_after_wait():
            with OrmSession(runtime) as s, s.begin():
                # Outlast the deliberately short original authority deadline.
                # An earlier lock/statement timeout must never masquerade as
                # rejection of expired authority after a completed lock wait.
                s.connection().exec_driver_sql("SET LOCAL lock_timeout='30000ms'")
                s.connection().exec_driver_sql("SET LOCAL statement_timeout='30000ms'")
                r = owner._reader(s)

                def observed_clock():
                    now = datetime.now(timezone.utc)
                    if released.is_set():
                        observed_clocks.append(now.timestamp())
                    return now

                r.clock = observed_clock
                backend.put(r.guard.sql("SELECT pg_catalog.pg_backend_pid()").scalar_one())
                if cross_expiry:
                    with pytest.raises(V2IssuanceUnavailable):
                        r.read(first["receipt"]["issuanceId"])
                    assert observed_clocks and min(observed_clocks) >= deadline
                    return None
                return r.read(first["receipt"]["issuanceId"]).facts.token_id

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(read_after_wait)
            try:
                pid = backend.get(timeout=8)
                bound = time.monotonic() + 5
                observed = False
                while time.monotonic() < bound:
                    with runtime.connect() as monitor:
                        observed = (
                            monitor.execute(
                                text("SELECT wait_event_type='Lock' FROM pg_catalog.pg_stat_activity WHERE pid=:pid"),
                                {"pid": pid},
                            ).scalar_one()
                            is True
                        )
                    if observed:
                        break
                    time.sleep(0.01)
                assert observed, "real native reader lock wait was not observed"
                assert not future.done(), "reader stopped before the blocker was released"
                if cross_expiry:
                    remaining = deadline - datetime.now(timezone.utc).timestamp()
                    assert 0 < remaining < 16, "authority was already expired before the observed wait"
                    time.sleep(remaining + 0.05)
                    assert not future.done(), "timeout occurred before completion of the native lock wait"
                else:
                    time.sleep(0.05)
                    assert datetime.now(timezone.utc).timestamp() < deadline
                    assert not future.done()
            finally:
                # Release even if a queue/monitor/assertion fails; otherwise
                # executor shutdown could wait for the synthetic blocker.
                released.set()
                transaction.rollback()
            result = future.result(timeout=10)
            assert observed_clocks, "trusted time was not sampled after the observed wait"
            if cross_expiry:
                assert result is None
            else:
                assert result is not None
                assert max(observed_clocks) < deadline


def test_native_live_reader_resamples_after_successful_real_lock_wait(native_graph):
    _native_reader_wait(native_graph, cross_expiry=False)


@pytest.mark.parametrize("native_graph", ["short"], indirect=True)
def test_native_expiry_resampled_after_real_lock_wait(native_graph):
    _native_reader_wait(native_graph, cross_expiry=True)


def test_native_wrong_original_phone_proofs_cannot_insert_acceptance(native_graph):
    ddl, runtime, owner, operation, proofs, parent = native_graph
    from app.services.social_session_issuance_v2_storage import V2Acceptance

    for changed in (
        dict(verifier=secrets.token_hex(32)),
        dict(secret=secrets.token_hex(32)),
        dict(possession_proof=secrets.token_hex(32)),
    ):
        with pytest.raises(V2IssuanceUnavailable):
            owner.issue(operation, **(proofs | changed))
        with OrmSession(runtime) as s:
            assert s.execute(select(V2Acceptance).where(V2Acceptance.operation_id == operation)).scalars().all() == []
    owner.issue(operation, **proofs)


def test_native_producer_root_rollback_has_no_child_or_binding(native_graph):
    ddl, runtime, owner, operation, proofs, parent = native_graph
    from sqlalchemy import event

    from app.services.social_session_issuance_v2_storage import V2Acceptance

    def fail_commit(session):
        raise ValueError("synthetic owner commit failure")

    event.listen(OrmSession, "before_commit", fail_commit)
    try:
        with pytest.raises(V2IssuanceUnavailable):
            owner.issue(operation, **proofs)
    finally:
        event.remove(OrmSession, "before_commit", fail_commit)
    with OrmSession(runtime) as s:
        assert s.execute(select(V2Acceptance).where(V2Acceptance.operation_id == operation)).scalars().all() == []
        assert s.execute(select(V2Issuance).where(V2Issuance.operation_id == operation)).scalars().all() == []
    assert owner.issue(operation, **proofs)["currentActive"] is True


def test_native_runtime_privilege_and_ddl_immutable_trigger_are_distinct(native_graph):
    ddl, runtime, owner, operation, proofs, parent = native_graph
    owner.issue(operation, **proofs)
    with runtime.connect() as c:
        assert (
            c.execute(
                text("SELECT has_function_privilege(current_user," "'public.social_session_v2_guard()','EXECUTE')")
            ).scalar_one()
            is False
        )
        assert (
            c.execute(
                text("SELECT has_table_privilege(current_user," "'public.social_session_v2_issuances','UPDATE')")
            ).scalar_one()
            is False
        )
    with pytest.raises(Exception) as denied:
        with ddl.begin() as c:
            c.execute(
                V2Issuance.__table__.update().where(V2Issuance.operation_id == operation).values(revision="aa" * 32)
            )
    assert getattr(denied.value.orig, "pgcode", None) == "P0001"
