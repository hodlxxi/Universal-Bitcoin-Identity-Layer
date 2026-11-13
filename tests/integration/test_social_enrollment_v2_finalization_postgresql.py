"""Opt-in PG16 draft, NOT_RUN unless a separately provisioned target is supplied.

No schema/cluster/role creation or migration application. Every test collects
individually. The inherited synthetic native graph patches only ephemeral OAuth
key ports; guards/readers and V2 RSA consumers run unpatched. External provisioning
and verified teardown are mandatory. No DATABASE_URL or default port fallback.
"""

import base64
import hashlib
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from queue import Queue
from threading import Event

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.services import social_device_challenge_store as challenges
from app.services import social_device_ed25519_association_storage as associations
from app.services import social_device_verification_statement as legacy_verifier
from app.services import social_enrollment_receipt_storage as legacy_receipts
from app.services import social_enrollment_transition_authority as legacy_transition
from app.services import social_messaging_device_admission_contract as admission
from app.services import social_messaging_device_ed25519_association_lifecycle as lifecycle
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_storage as durable
from app.services.social_enrollment_v2_finalization import V2FinalizationOwner
from app.services.social_enrollment_v2_finalization_contract import FinalizationDenied
from app.services.social_enrollment_v2_finalization_storage import NATIVE_COLUMNS, NativeV2Effects, attest_native_schema
from tests.integration.test_social_enrollment_v2_reservation_postgresql import REQUIRED_TABLES
from tests.integration.test_social_enrollment_v2_reservation_postgresql import owner as reservation_owner
from tests.integration.test_social_enrollment_v2_reservation_postgresql import reservation_native
from tests.integration.test_social_session_issuance_v2_postgresql import native_graph
from tests.unit.test_social_enrollment_v2_finalization import signed_statement

PREFIX = "UBID_V2_FINALIZATION_REHEARSAL_"
ACK = "DISPOSABLE-SYNTHETIC-V2-FINALIZATION-PREINSTALLED"
ROOT = Path(__file__).parents[2]


def epoch_ms():
    now = datetime.now(timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    elapsed = now - epoch
    return elapsed.days * 86400000 + elapsed.seconds * 1000 + elapsed.microseconds // 1000


def selected_target(*, original=False):
    if os.environ.get(PREFIX + "ACK") is None:
        pytest.skip("explicit disposable finalization target absent; POSTGRESQL_REHEARSAL=NOT_RUN")
    assert os.environ[PREFIX + "ACK"] == ACK
    nonce = os.environ[PREFIX + "NONCE"]
    assert len(nonce) == 32 and all(c in "0123456789abcdef" for c in nonce)
    port = int(os.environ[PREFIX + "PORT"])
    assert 49152 <= port <= 65535
    data = Path(os.environ[PREFIX + "DATA"]).resolve()
    assert data == Path("/tmp") / ("ubid-v2-finalization-rehearsal-" + nonce) / "data"
    assert (data / "PG_VERSION").read_text().strip() == "16"
    database = ("ubid_v2_finalization_original_" if original else "ubid_v2_finalization_rehearsal_") + nonce
    suffix = "ORIGINAL_" if original else ""
    engines = []
    for selector, role in (("DDL_DSN", "ubid_v2_finalization_ddl"), ("RUNTIME_DSN", "ubid_v2_finalization_runtime")):
        url = make_url(os.environ[PREFIX + suffix + selector])
        assert url.drivername == "postgresql+psycopg2" and url.host == "127.0.0.1" and url.port == port
        assert url.database == database and url.username == role and url.password is None and not url.query
        engines.append(
            create_engine(
                url,
                poolclass=NullPool,
                hide_parameters=True,
                connect_args={"connect_timeout": 5, "options": "-c lock_timeout=180000 -c statement_timeout=240000"},
            )
        )
    ddl, runtime = engines
    try:
        for engine in engines:
            with engine.connect() as c:
                identity = c.execute(
                    text(
                        "SELECT current_database(),current_user,session_user,"
                        "pg_catalog.host(inet_server_addr()),inet_server_port(),current_setting('server_version_num')"
                    )
                ).one()
                assert tuple(identity[:5]) == (database, engine.url.username, engine.url.username, "127.0.0.1", port)
                assert identity[5].startswith("16")
                if engine is ddl:
                    assert Path(c.execute(text("SHOW data_directory")).scalar_one()).resolve() == data
                    assert c.execute(text("SHOW listen_addresses")).scalar_one() == "127.0.0.1"
                    assert c.execute(text("SHOW unix_socket_directories")).scalar_one() == ""
                    names = set(
                        c.execute(
                            text(
                                "SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n "
                                "ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f')"
                            )
                        ).scalars()
                    )
                    assert names == REQUIRED_TABLES | (set() if original else set(NATIVE_COLUMNS))
        return engines
    except BaseException:
        for engine in engines:
            engine.dispose()
        raise


@pytest.fixture(scope="module")
def native_target():
    engines = selected_target()
    try:
        # External provisioning must use the full core model schema before
        # lifecycle additions and the exact pinned migrations. Earlier minimal
        # V1 helper tables (including users.is_active NOT NULL) are insufficient.
        with engines[1].connect() as connection:
            attest_native_schema(connection)
        yield tuple(engines)
    finally:
        for engine in engines:
            engine.dispose()
        # External runner owns exact-cluster teardown; ledgers are retained.


@pytest.fixture
def finalized_native(reservation_native):
    ddl, runtime, wire, issuance, rc, signer, expires = reservation_native
    with Session(runtime) as s, s.begin():
        reservation = reservation_owner(s, reservation_native).reserve(wire, issuance_id=issuance)
    config, compact = signed_statement(wire, rc, reservation.observed_at, expires_at=reservation.expires_at)
    arguments = dict(
        reservation_id=reservation.reservation_id,
        reservation_revision=1,
        verification_input_wire=wire,
        evidence_compact_jws=reservation.evidence_compact_jws,
        statement_compact_jws=compact,
        issuance_id=issuance,
    )
    return ddl, runtime, config, arguments, reservation


def finalizer(session, g, clock=epoch_ms):
    return V2FinalizationOwner(session, config=g[2], clock=clock)


def count_effects(connection, reservation):
    return tuple(
        connection.execute(
            text(f"SELECT count(*) FROM public.{table} WHERE reservation_id=:id"), {"id": reservation}
        ).scalar_one()
        for table in NATIVE_COLUMNS
    )


def test_native_full_commit_and_exact_accepted_retry(finalized_native):
    g = finalized_native
    with Session(g[1]) as s, s.begin():
        result = finalizer(s, g).finalize(**g[3])
        assert count_effects(s.connection(), g[4].reservation_id) == (1, 1, 1, 1)
        assert result.final_admission == "denied"
    # Later expiry is historical recovery, not live revalidation/signing.
    with Session(g[1]) as s, s.begin():
        retry = finalizer(s, g, lambda: g[4].expires_at + 600000).finalize(**g[3])
        assert retry.historical_recovery and retry.receipt_wire == result.receipt_wire
        assert count_effects(s.connection(), g[4].reservation_id) == (1, 1, 1, 1)
    receipt = json.loads(result.receipt_wire)
    with Session(g[1]) as s, s.begin():
        from app.services import social_messaging_mobile_pre_enrollment_v2 as v2

        p = v2.parse_preaccepted_enrollment_verification_input_v2(g[3]["verification_input_wire"])
        associations.SqlAlchemyEd25519AssociationStore(s).revoke(
            p.context.subject, p.context.device_id, expected_association_id=receipt["associationId"], expected_epoch=1
        )
    with Session(g[1]) as s, s.begin():
        assert finalizer(s, g, lambda: g[4].expires_at + 600000).finalize(**g[3]).receipt_wire == result.receipt_wire


@pytest.mark.parametrize("boundary", ["association", "receipt", "consumption", "cas"])
def test_native_rollback_at_effect_receipt_consumption_cas_boundary(finalized_native, boundary):
    g = finalized_native

    def fail(connection, cursor, statement, parameters, context, executemany):
        if "execute_social_enrollment_v2_native_effects" in statement and isinstance(parameters, dict):
            hit = parameters.get("stage") == boundary
        else:
            hit = boundary == "cas" and statement.lstrip().startswith("UPDATE") and durable.TABLE in statement
        if hit:
            raise RuntimeError("synthetic boundary failure")

    with Session(g[1]) as s:
        root = s.begin()
        event.listen(s.connection(), "after_cursor_execute", fail)
        with pytest.raises(FinalizationDenied):
            finalizer(s, g).finalize(**g[3])
        root.rollback()
    with g[1].connect() as c:
        assert count_effects(c, g[4].reservation_id) == (0, 0, 0, 0)
        assert (
            c.execute(
                text(
                    "SELECT state FROM public.social_preaccepted_enrollment_v2_atomic_acceptances WHERE reservation_id=:id"
                ),
                {"id": g[4].reservation_id},
            ).scalar_one()
            == "pending"
        )


@pytest.mark.parametrize(
    "stages", [[], ["association"], ["association", "receipt"], ["association", "receipt", "consumption"]]
)
def test_native_deferred_completeness_rejects_partial_or_mismatched_effects(finalized_native, stages):
    g = finalized_native
    with Session(g[1]) as s:
        root = s.begin()
        owner = finalizer(s, g)
        a = owner.authority
        stored = a.discover_finalization(
            g[4].reservation_id,
            1,
            g[3]["verification_input_wire"],
            g[3]["evidence_compact_jws"],
            g[3]["statement_compact_jws"],
        )
        plan = a.prepare_finalization(stored, g[3]["statement_compact_jws"], g[3]["issuance_id"])
        record = a.resolve(plan)
        from app.services import social_messaging_mobile_pre_enrollment_v2 as v2

        p = v2.parse_preaccepted_enrollment_verification_input_v2(record.input_wire)
        ev = lifecycle.initial_association_v1(lifecycle.AssociationLifecycleV1(), p.enrollment_wire).events[0]
        for stage in stages:
            s.connection().execute(
                text(
                    "SELECT public.execute_social_enrollment_v2_native_effects(:id,:event,:effect,:receipt,:ep,:sp,:stage)"
                ),
                dict(
                    id=g[4].reservation_id,
                    event=lifecycle.canonical_association_event_v1_bytes(ev).decode(),
                    effect=record.canonical_plan.effect_wire,
                    receipt=record.canonical_plan.receipt.wire,
                    ep=json.dumps(record.evidence_pin, separators=(",", ":")),
                    sp=json.dumps(record.statement_pin, separators=(",", ":")),
                    stage=stage,
                ),
            )
        if not stages:
            with pytest.raises(durable.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable):
                a.storage.finalize_accepted(
                    g[4].reservation_id,
                    finalization_observation_wire=record.canonical_plan.observation.wire,
                    expected_input_wire=p.wire,
                    expected_context_wire=p.context.wire,
                    evidence_compact_jws=g[3]["evidence_compact_jws"],
                    evidence_config=g[2].reservation_config.evidence_config,
                    statement_compact_jws=g[3]["statement_compact_jws"],
                    statement_config=g[2].statement_config,
                    decided_at=record.canonical_plan.observation.observed_at,
                )
        else:
            with pytest.raises(Exception):
                root.commit()
        s.rollback()
    with g[1].connect() as c:
        assert count_effects(c, g[4].reservation_id) == (0, 0, 0, 0)


@pytest.mark.parametrize("expire", [False, True])
def test_native_completed_wait_resamples_clock_and_rejects_expiry(finalized_native, expire):
    g = finalized_native
    pid_queue = Queue()
    release = Event()

    def clock():
        return g[4].expires_at if expire and release.is_set() else epoch_ms()

    def worker():
        with Session(g[1]) as s, s.begin():
            pid_queue.put(s.connection().execute(text("SELECT pg_backend_pid()")).scalar_one())
            return finalizer(s, g, clock).finalize(**g[3])

    with Session(g[0]) as blocker:
        root = blocker.begin()
        blocker.connection().execute(
            text("LOCK TABLE public.social_preaccepted_enrollment_v2_atomic_acceptances IN SHARE ROW EXCLUSIVE MODE")
        )
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(worker)
            try:
                pid = pid_queue.get(timeout=30)
                deadline = time.monotonic() + 60
                observed = False
                while time.monotonic() < deadline and not future.done():
                    with g[0].connect() as c:
                        observed = bool(
                            c.execute(
                                text(
                                    "SELECT wait_event_type='Lock' AND state='active' FROM pg_stat_activity WHERE pid=:pid"
                                ),
                                {"pid": pid},
                            ).scalar_one()
                        )
                    if observed:
                        break
                assert observed and not future.done()
            finally:
                release.set()
                root.rollback()  # Release before executor shutdown, even on failure.
            if expire:
                with pytest.raises(FinalizationDenied):
                    future.result(timeout=120)
            else:
                assert future.result(timeout=120).receipt_wire


def test_native_competing_finalizers_return_one_immutable_receipt(finalized_native):
    g = finalized_native
    ready = Queue()
    start = Event()

    def worker():
        with Session(g[1]) as s, s.begin():
            ready.put(s.connection().execute(text("SELECT pg_backend_pid()")).scalar_one())
            assert start.wait(30)
            return finalizer(s, g).finalize(**g[3])

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(worker) for _ in range(2)]
        assert ready.get(timeout=30) != ready.get(timeout=30)
        start.set()
        results = [future.result(timeout=120) for future in futures]
    assert results[0].receipt_wire == results[1].receipt_wire
    assert sorted(result.historical_recovery for result in results) == [False, True]
    with g[1].connect() as c:
        assert count_effects(c, g[4].reservation_id) == (1, 1, 1, 1)


@pytest.mark.parametrize("change", ["root_xid", "savepoint_aba", "function_body", "role"])
def test_native_root_xid_and_catalog_role_changes_deny(finalized_native, change):
    g = finalized_native
    with Session(g[1]) as s:
        root = s.begin()
        owner = finalizer(s, g)
        if change == "root_xid":
            s.connection().exec_driver_sql("COMMIT")
        elif change == "savepoint_aba":
            nested = s.begin_nested()
            nested.rollback()
        elif change == "function_body":
            with g[0].begin() as c:
                c.exec_driver_sql(
                    "ALTER FUNCTION public.execute_social_enrollment_v2_native_effects(TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT) COST 101"
                )
        else:
            with g[0].begin() as c:
                c.exec_driver_sql("GRANT pg_monitor TO ubid_v2_finalization_runtime")
        try:
            with pytest.raises(FinalizationDenied):
                owner.finalize(**g[3])
            root.rollback()
        finally:
            if change == "function_body":
                with g[0].begin() as c:
                    c.exec_driver_sql(
                        "ALTER FUNCTION public.execute_social_enrollment_v2_native_effects(TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT) COST 100"
                    )
            if change == "role":
                with g[0].begin() as c:
                    c.exec_driver_sql("REVOKE pg_monitor FROM ubid_v2_finalization_runtime")


def verified_legacy_initial_native_fixture():
    """Genuine V1 RSA attestation of the actual initial lifecycle identity.

    The frozen admission vector proves statement shape and RSA authentication;
    its proposed association does not describe an absent -> initial transition.
    Preserve its challenge, phone proof and approval event byte-for-byte. Derive
    only the initial association fields, then sign/verify those exact new wires
    using an ephemeral in-memory test key and the unchanged V1 consumer.
    """
    raw = (ROOT / "tests/fixtures/social_device_admission_v1.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == "09722ca9ab230a7bbc73b2228dfed5e80cdd2c2bb44a32e8571bdcf246ca4324"
    fixed = json.loads(raw)
    v = fixed["vectors"]["enrollmentV2"]
    original = admission.parse_verification_input_v1(v["inputWire"])
    configured = fixed["configuration"]
    original_config = legacy_verifier.SocialDeviceVerificationStatementConfig(
        enabled=True,
        issuer=configured["issuer"],
        audience=configured["audience"],
        client_id=configured["clientId"],
        service_principal=configured["servicePrincipal"],
        trusted_jwks=(fixed["publicVerificationMaterial"]["jwk"],),
    )
    deadlines = dict(
        now=v["now"],
        challenge_expires_at=json.loads(original.challenge_wire)["expiresAt"],
        session_expires_at=v["sessionExpiresAt"],
        approver_session_expires_at=v["approverSessionExpiresAt"],
    )
    authenticated_original = legacy_verifier.verify_social_device_verification_statement_v1(
        v["compactJws"],
        config=original_config,
        expected_context_wire=original.context.wire,
        expected_input_wire=original.wire,
        **deadlines,
    )
    context = json.loads(original.context.wire)
    context.update(
        associationId=lifecycle.association_id_v1(original.challenge_wire, 1, None),
        associationVersion=1,
        authorityEpoch=1,
        predecessorAssociationId=None,
    )
    context_wire = json.dumps(context, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    fields = json.loads(original.wire)
    input_wire = admission.canonical_verification_input_v1_bytes(
        context=context_wire,
        challenge=fields["challenge"],
        proof=fields["proof"],
        approval_event=fields["approvalEvent"],
        actual_request=fields["actualRequest"],
        routing_request=fields["routingRequest"],
    ).decode("ascii")
    value = admission.parse_verification_input_v1(input_wire)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()

    def encoded_integer(number):
        raw_integer = number.to_bytes((number.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw_integer).decode("ascii").rstrip("=")

    kid = "synthetic-legacy-native-initial"
    config = legacy_verifier.SocialDeviceVerificationStatementConfig(
        enabled=True,
        issuer=original_config.issuer,
        audience=original_config.audience,
        client_id=original_config.client_id,
        service_principal=original_config.service_principal,
        trusted_jwks=(
            {
                "kty": "RSA",
                "use": "sig",
                "alg": admission.STATEMENT_ALGORITHM,
                "kid": kid,
                "n": encoded_integer(numbers.n),
                "e": encoded_integer(numbers.e),
            },
        ),
    )
    header = admission.canonical_verification_statement_protected_header_v1_bytes(kid=kid).decode("ascii")
    payload = admission.canonical_verification_statement_payload_v1_bytes(
        issuer=config.issuer,
        audience=config.audience,
        client_id=config.client_id,
        service_principal=config.service_principal,
        result=authenticated_original.result,
        challenge_kind=authenticated_original.challenge_kind,
        challenge_id=value.context.challenge_id,
        attempt_id=value.context.attempt_id,
        context_digest=admission.verification_context_digest_v1(value.context.wire),
        input_digest=admission.verification_input_digest_v1(value.wire),
        issued_at=authenticated_original.issued_at,
        expires_at=authenticated_original.expires_at,
        token_id=authenticated_original.token_id,
    ).decode("ascii")
    signing_input = ".".join(
        base64.urlsafe_b64encode(part.encode("ascii")).decode("ascii").rstrip("=") for part in (header, payload)
    ).encode("ascii")
    compact = admission.compact_verification_statement_v1(
        protected_header_wire=header,
        payload_wire=payload,
        signature=key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256()),
    )
    authenticated = legacy_verifier.verify_social_device_verification_statement_v1(
        compact,
        config=config,
        expected_context_wire=value.context.wire,
        expected_input_wire=value.wire,
        **deadlines,
    )
    return (
        value,
        authenticated,
        v["now"],
        min(
            deadlines["session_expires_at"], deadlines["approver_session_expires_at"], deadlines["challenge_expires_at"]
        ),
    )


@pytest.mark.parametrize("original", [True, False])
def test_native_original_v1_and_extended_target_behavior(native_target, original):
    # Genuine V1 RSA statement and correct initial identity -> unchanged V1 stores.
    # No V2 signature is converted, relabeled or passed to a V1 consumer.
    engines = selected_target(original=True) if original else list(native_target)
    ddl, runtime = engines
    try:
        value, authenticated, now, deadline = verified_legacy_initial_native_fixture()
        with Session(ddl) as s, s.begin():
            challenges.SqlAlchemyDeviceChallengeStore(s).create_issued(
                context_wire=value.context.wire, challenge_wire=value.challenge_wire
            )
        with Session(runtime) as s, s.begin():
            durable.SqlAlchemyTransactionBoundAtomicAcceptanceStorage(s)
            store = associations.SqlAlchemyEd25519AssociationStore(s)
            prior = store.lock_lifecycle(value.context.subject, value.context.device_id)
            authority = legacy_transition.authorize_enrollment_transition_v1(
                value,
                authenticated,
                prior,
                observed_at=now,
                locked_deadline_ms=deadline,
                full_proof_id=value.context.full_proof_id,
                approver_full_proof_id=value.context.approver_full_proof_id,
            )
            association = store.establish_initial(value.wire, authenticated, now=now)
            legacy_receipts.SqlAlchemyEnrollmentAdmissionReceiptStore(s).store_committed(
                authority, proposed_association_id=association.association_id, decided_at=now
            )
            challenges.SqlAlchemyDeviceChallengeStore(s).record_enrollment_consumed(authority, observed_at=now)
    finally:
        if original:
            for engine in engines:
                engine.dispose()


@pytest.mark.parametrize("table", NATIVE_COLUMNS)
@pytest.mark.parametrize("operation", ["UPDATE", "DELETE", "TRUNCATE"])
def test_native_immutable_evidence_rejects_owner_update_delete_truncate(finalized_native, table, operation):
    g = finalized_native
    with Session(g[1]) as s, s.begin():
        original = finalizer(s, g).finalize(**g[3]).receipt_wire
    statement = (
        f"UPDATE public.{table} SET birth_xid='1'"
        if operation == "UPDATE"
        else f"DELETE FROM public.{table}" if operation == "DELETE" else f"TRUNCATE public.{table}"
    )
    with g[0].connect() as c:
        root = c.begin()
        with pytest.raises(Exception):
            c.execute(text(statement))
        root.rollback()
    with Session(g[1]) as s, s.begin():
        assert finalizer(s, g).finalize(**g[3]).receipt_wire == original


@pytest.mark.parametrize(
    "change,alter,restore,same_object",
    [
        (
            "nullable",
            "ALTER TABLE public.social_device_ed25519_association_events ALTER COLUMN event_wire DROP NOT NULL",
            "ALTER TABLE public.social_device_ed25519_association_events ALTER COLUMN event_wire SET NOT NULL",
            None,
        ),
        (
            "default",
            "ALTER TABLE public.social_device_ed25519_association_events ALTER COLUMN event_wire SET DEFAULT 'replacement'",
            "ALTER TABLE public.social_device_ed25519_association_events ALTER COLUMN event_wire DROP DEFAULT",
            None,
        ),
        (
            "fk_deferral",
            "ALTER TABLE public.social_device_ed25519_association_events ALTER CONSTRAINT fk_social_ed25519_event_chain DEFERRABLE INITIALLY DEFERRED",
            "ALTER TABLE public.social_device_ed25519_association_events ALTER CONSTRAINT fk_social_ed25519_event_chain NOT DEFERRABLE",
            "fk_social_ed25519_event_chain",
        ),
        (
            "check_definition",
            "ALTER TABLE public.social_device_ed25519_association_events DROP CONSTRAINT ck_social_ed25519_event_id, ADD CONSTRAINT ck_social_ed25519_event_id CHECK (association_id IS NOT NULL)",
            "ALTER TABLE public.social_device_ed25519_association_events DROP CONSTRAINT ck_social_ed25519_event_id, ADD CONSTRAINT ck_social_ed25519_event_id CHECK (association_id ~ '^[0-9a-f]{64}$')",
            None,
        ),
        (
            "index_options",
            "ALTER INDEX public.uq_social_ed25519_creation_key SET (fillfactor=90)",
            "ALTER INDEX public.uq_social_ed25519_creation_key RESET (fillfactor)",
            "uq_social_ed25519_creation_key",
        ),
        (
            "partial_predicate",
            "DROP INDEX public.uq_social_ed25519_creation_key; CREATE UNIQUE INDEX uq_social_ed25519_creation_key ON public.social_device_ed25519_association_events (subject,device_id,ed25519_public_key) WHERE kind IN ('initial','rotate')",
            "DROP INDEX public.uq_social_ed25519_creation_key; CREATE UNIQUE INDEX uq_social_ed25519_creation_key ON public.social_device_ed25519_association_events (subject,device_id,ed25519_public_key) WHERE kind IN ('initial','rotate','reenroll')",
            None,
        ),
    ],
)
def test_native_shared_columns_constraints_indexes_replacements_deny(
    finalized_native, change, alter, restore, same_object
):
    """Explicit disposable fixture only; catalog denial precedes any V2 effect.

    ALTER preserves table OID and, where marked, the constraint/index OID. A
    predicate/CHECK replacement preserves the table OID while replacing the
    definition object. No direct system-catalog writes or disabled guards.
    """
    g = finalized_native
    table = "public.social_device_ed25519_association_events"
    with g[0].connect() as c:
        table_oid = c.execute(text("SELECT CAST(:name AS regclass)::oid::bigint"), {"name": table}).scalar_one()
        before = count_effects(c, g[4].reservation_id)
        object_oid = None
        if same_object:
            object_oid = c.execute(
                (
                    text("SELECT oid::bigint FROM pg_catalog.pg_constraint WHERE conrelid=:oid AND conname=:name")
                    if change == "fk_deferral"
                    else text("SELECT CAST(:name AS regclass)::oid::bigint")
                ),
                {"oid": table_oid, "name": same_object if change == "fk_deferral" else "public." + same_object},
            ).scalar_one()
    mutations = []

    def observe_mutations(_connection, _cursor, statement, _parameters, _context, _executemany):
        if "execute_social_enrollment_v2_native_effects(" in statement or (
            statement.lstrip().upper().startswith("UPDATE ")
            and "social_preaccepted_enrollment_v2_atomic_acceptances" in statement
        ):
            mutations.append(statement)

    event.listen(g[1], "before_cursor_execute", observe_mutations)
    altered = False
    try:
        with g[0].begin() as c:
            # Execute statements individually; all are closed test constants.
            for statement in alter.split("; "):
                c.exec_driver_sql(statement)
        altered = True
        with Session(g[1]) as s, s.begin():
            with pytest.raises(FinalizationDenied):
                finalizer(s, g).finalize(**g[3])
            s.rollback()
        assert not mutations
        with g[0].connect() as c:
            assert (
                c.execute(text("SELECT CAST(:name AS regclass)::oid::bigint"), {"name": table}).scalar_one()
                == table_oid
            )
            if object_oid is not None:
                observed = c.execute(
                    (
                        text("SELECT oid::bigint FROM pg_catalog.pg_constraint WHERE conrelid=:oid AND conname=:name")
                        if change == "fk_deferral"
                        else text("SELECT CAST(:name AS regclass)::oid::bigint")
                    ),
                    {"oid": table_oid, "name": same_object if change == "fk_deferral" else "public." + same_object},
                ).scalar_one()
                assert observed == object_oid
            assert count_effects(c, g[4].reservation_id) == before
            assert (
                c.execute(
                    text(
                        "SELECT state FROM public.social_preaccepted_enrollment_v2_atomic_acceptances WHERE reservation_id=:id"
                    ),
                    {"id": g[4].reservation_id},
                ).scalar_one()
                == "pending"
            )
    finally:
        event.remove(g[1], "before_cursor_execute", observe_mutations)
        if altered:
            with g[0].begin() as c:
                for statement in restore.split("; "):
                    c.exec_driver_sql(statement)


DEPENDENCY_DEFAULT_CASES = (
    ("users", "id"),
    ("current_entitlement_evidence", "evidence_id"),
    ("oauth_tokens", "id"),
    ("sessions", "session_id"),
    ("oauth_clients", "client_id"),
    ("oauth_session_generations", "token_id"),
    ("oauth_browser_generations", "generation_id"),
    ("social_messaging_device_bindings", "binding_id"),
    ("social_session_issuers", "client_id"),
    ("social_messaging_mobile_operations", "operation_id"),
    ("social_messaging_device_authorization_binding_owners", "binding_id"),
    ("social_device_admission_challenges", "challenge_id"),
    ("social_device_admission_challenge_revisions", "challenge_id"),
    ("social_device_ed25519_association_chains", "subject"),
    ("social_device_ed25519_association_events", "subject"),
    ("social_device_enrollment_admission_receipts", "receipt_id"),
    ("social_preaccepted_enrollment_v2_atomic_acceptances", "reservation_id"),
    ("social_session_v2_offers", "operation_id"),
    ("social_session_v2_parents", "operation_id"),
    ("social_session_v2_acceptances", "operation_id"),
    ("social_session_v2_issuances", "operation_id"),
    ("social_session_v2_invalidations", "operation_id"),
    ("social_session_v2_binding_births", "binding_id"),
    ("social_session_v2_token_births", "token_id"),
    ("social_enrollment_v2_native_associations", "reservation_id"),
    ("social_enrollment_v2_native_effects", "reservation_id"),
    ("social_enrollment_v2_native_consumptions", "reservation_id"),
    ("social_enrollment_v2_native_decisions", "reservation_id"),
)


def assert_native_catalog_replacement_denied(g, table, alter, restore):
    """Bounded restoring DDL on the explicitly selected synthetic target only."""
    with g[0].connect() as c:
        oid = c.execute(text("SELECT CAST(:name AS regclass)::oid::bigint"), {"name": "public." + table}).scalar_one()
        before = count_effects(c, g[4].reservation_id)
    mutations = []

    def observe(_connection, _cursor, statement, _parameters, _context, _executemany):
        if (
            statement.lstrip().upper().startswith(("INSERT ", "UPDATE ", "DELETE ", "TRUNCATE "))
            or "execute_social_enrollment_v2_native_effects(" in statement
        ):
            mutations.append(statement)

    event.listen(g[1], "before_cursor_execute", observe)
    altered = False
    try:
        with g[0].begin() as c:
            c.exec_driver_sql(alter)
        altered = True
        with Session(g[1]) as s, s.begin():
            with pytest.raises(FinalizationDenied):
                finalizer(s, g).finalize(**g[3])
            s.rollback()
        assert not mutations
        with g[0].connect() as c:
            assert (
                c.execute(text("SELECT CAST(:name AS regclass)::oid::bigint"), {"name": "public." + table}).scalar_one()
                == oid
            )
            assert count_effects(c, g[4].reservation_id) == before
            assert (
                c.execute(
                    text(
                        "SELECT state FROM public.social_preaccepted_enrollment_v2_atomic_acceptances WHERE reservation_id=:id"
                    ),
                    {"id": g[4].reservation_id},
                ).scalar_one()
                == "pending"
            )
    finally:
        event.remove(g[1], "before_cursor_execute", observe)
        if altered:
            with g[0].begin() as c:
                c.exec_driver_sql(restore)


@pytest.mark.parametrize("table,column", DEPENDENCY_DEFAULT_CASES)
def test_native_dependency_catalog_replacements_deny(finalized_native, table, column):
    # All original source profiles have absent server defaults for these keys.
    # Neither the Python defaults nor a caller-supplied model become expectations.
    assert_native_catalog_replacement_denied(
        finalized_native,
        table,
        f"ALTER TABLE public.{table} ALTER COLUMN {column} SET DEFAULT 'replacement'",
        f"ALTER TABLE public.{table} ALTER COLUMN {column} DROP DEFAULT",
    )


@pytest.mark.parametrize(
    "table",
    (
        "social_enrollment_v2_native_associations",
        "social_enrollment_v2_native_effects",
        "social_enrollment_v2_native_consumptions",
        "social_enrollment_v2_native_decisions",
    ),
)
@pytest.mark.parametrize(
    "surface", ("index_options", "toast_options", "compression", "public_table", "public_column", "standalone_index")
)
def test_native_native_table_ancillary_replacements_deny(finalized_native, table, surface):
    # Ordinary supported DDL only: no writes to system catalogs or TOAST internals,
    # disabled guards, automatic schema provisioning, new roles, or live fallback.
    if surface == "index_options":
        alter, restore = (
            f"ALTER INDEX public.{table}_pkey SET (fillfactor=90)",
            f"ALTER INDEX public.{table}_pkey RESET (fillfactor)",
        )
    elif surface == "toast_options":
        alter, restore = (
            f"ALTER TABLE public.{table} SET (toast.autovacuum_enabled=false)",
            f"ALTER TABLE public.{table} RESET (toast.autovacuum_enabled)",
        )
    elif surface == "compression":
        alter, restore = (
            f"ALTER TABLE public.{table} ALTER COLUMN birth_xid SET COMPRESSION pglz",
            f"ALTER TABLE public.{table} ALTER COLUMN birth_xid SET COMPRESSION default",
        )
    elif surface == "public_table":
        alter, restore = f"GRANT SELECT ON public.{table} TO PUBLIC", f"REVOKE SELECT ON public.{table} FROM PUBLIC"
    elif surface == "public_column":
        alter, restore = (
            f"GRANT SELECT (birth_xid) ON public.{table} TO PUBLIC",
            f"REVOKE SELECT (birth_xid) ON public.{table} FROM PUBLIC",
        )
    else:
        alter, restore = (
            f"CREATE INDEX v2_ancillary_probe_idx ON public.{table} (reservation_id)",
            "DROP INDEX public.v2_ancillary_probe_idx",
        )
    assert_native_catalog_replacement_denied(finalized_native, table, alter, restore)


AUTHORITY_NATIVE_REPLACEMENTS = (
    (
        "oauth_browser_generations",
        "ALTER TABLE public.oauth_browser_generations ALTER CONSTRAINT oauth_browser_generations_user_id_fkey DEFERRABLE INITIALLY DEFERRED",
        "ALTER TABLE public.oauth_browser_generations ALTER CONSTRAINT oauth_browser_generations_user_id_fkey NOT DEFERRABLE",
    ),
    (
        "social_messaging_device_authorization_binding_owners",
        "ALTER TABLE public.social_messaging_device_authorization_binding_owners ALTER CONSTRAINT social_messaging_device_authorization_binding_o_binding_id_fkey NOT DEFERRABLE",
        "ALTER TABLE public.social_messaging_device_authorization_binding_owners ALTER CONSTRAINT social_messaging_device_authorization_binding_o_binding_id_fkey DEFERRABLE INITIALLY DEFERRED",
    ),
    (
        "current_entitlement_evidence",
        "ALTER TABLE public.current_entitlement_evidence DROP CONSTRAINT ck_current_entitlement_contract_version, ADD CONSTRAINT ck_current_entitlement_contract_version CHECK (contract_version IN ('hodlxxi.current_entitlement_evidence.v1','replacement'))",
        "ALTER TABLE public.current_entitlement_evidence DROP CONSTRAINT ck_current_entitlement_contract_version, ADD CONSTRAINT ck_current_entitlement_contract_version CHECK (contract_version = 'hodlxxi.current_entitlement_evidence.v1')",
    ),
    (
        "users",
        "ALTER INDEX public.idx_user_created SET (fillfactor=90)",
        "ALTER INDEX public.idx_user_created RESET (fillfactor)",
    ),
    (
        "oauth_tokens",
        "ALTER INDEX public.ix_oauth_tokens_access_token SET (fillfactor=90)",
        "ALTER INDEX public.ix_oauth_tokens_access_token RESET (fillfactor)",
    ),
    (
        "oauth_browser_generations",
        "ALTER INDEX public.uq_browser_generation_current SET (fillfactor=90)",
        "ALTER INDEX public.uq_browser_generation_current RESET (fillfactor)",
    ),
    ("users", "GRANT SELECT ON public.users TO PUBLIC", "REVOKE SELECT ON public.users FROM PUBLIC"),
    ("users", "GRANT SELECT (id) ON public.users TO PUBLIC", "REVOKE SELECT (id) ON public.users FROM PUBLIC"),
    (
        "oauth_codes",
        "ALTER TABLE public.oauth_codes ALTER CONSTRAINT oauth_codes_user_id_fkey DEFERRABLE INITIALLY DEFERRED",
        "ALTER TABLE public.oauth_codes ALTER CONSTRAINT oauth_codes_user_id_fkey NOT DEFERRABLE",
    ),
    (
        "social_messaging_device_authorization_requests",
        "ALTER INDEX public.social_messaging_device_authorization_requests_pkey SET (fillfactor=90)",
        "ALTER INDEX public.social_messaging_device_authorization_requests_pkey RESET (fillfactor)",
    ),
)


@pytest.mark.parametrize("table,alter,restore", AUTHORITY_NATIVE_REPLACEMENTS)
def test_native_authority_constraints_indexes_acls_ri_replacements_deny(finalized_native, table, alter, restore):
    # Only the externally ACKed complete core-model + pinned-migration schema.
    # ALTER CONSTRAINT preserves FK OIDs and replaces their real RI bindings;
    # CHECK replacement preserves the table, but PostgreSQL allocates a new
    # constraint OID. No system catalog mutation or disabled trigger is used.
    assert_native_catalog_replacement_denied(finalized_native, table, alter, restore)


NATIVE_FRESHNESS_PROFILE = "native-v2-60s-v1"
