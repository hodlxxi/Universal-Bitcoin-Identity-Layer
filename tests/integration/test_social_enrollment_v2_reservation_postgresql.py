"""Opt-in native reservation rehearsal; skipped without a disposable target.

An external runner must provision the exact pinned prerequisite migrations and
restricted roles in a unique disposable PostgreSQL 16 cluster, and verify its
teardown. These tests neither install schema nor provision keys/roles/clusters.
No patched authority, catalog, role or transaction checks. The reused synthetic
issuance fixture injects only its ephemeral OAuth signer; evidence uses the real
dedicated signer. Shape-only phone proofs never claim Social Ed25519 validity.
"""

import base64
import json
import os
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from queue import Queue
from threading import Event

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.services import social_admission_session_binding as bindings
from app.services import social_device_challenge_store as challenges
from app.services import social_messaging_device_ed25519_association_lifecycle as association
from app.services import social_messaging_device_proof_profile as profile
from app.services import social_messaging_device_verification_deadline_evidence_v1 as evidence
from app.services import social_messaging_mobile_pre_enrollment_v2 as v2
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_storage as durable
from app.services.social_enrollment_v2_reservation import V2ReservationOwner
from app.services.social_enrollment_v2_reservation_authority import _binding_preimages
from app.services.social_enrollment_v2_reservation_contract import (
    ReservationConfig,
    ReservationDenied,
    dedicated_reservation_key_id,
)
from app.services.social_enrollment_v2_reservation_signer import DedicatedRS256EvidenceSigner
from app.services.social_session_issuance_v2_authority import NativeV2AuthorityReader
from app.services.social_session_issuance_v2_contract import V2IssuanceUnavailable
from tests.integration.test_social_session_issuance_v2_postgresql import PREREQUISITES, native_graph
from tests.unit.test_social_enrollment_v2_reservation_signer import DelayedRSA

PREFIX = "UBID_V2_RESERVATION_REHEARSAL_"
ACK = "DISPOSABLE-SYNTHETIC-V2-RESERVATION-PREINSTALLED"
ROOT = Path(__file__).resolve().parents[2]
REQUIRED_TABLES = (
    PREREQUISITES
    | {
        durable.TABLE,
        "social_device_admission_challenges",
        "social_device_admission_challenge_revisions",
        "social_device_ed25519_association_chains",
        "social_device_ed25519_association_events",
        "social_device_enrollment_admission_receipts",
    }
    | {
        "social_session_v2_" + name
        for name in (
            "offers",
            "parents",
            "binding_births",
            "token_births",
            "acceptances",
            "issuances",
            "invalidations",
        )
    }
)


def guarded_target_configuration():
    if os.environ.get(PREFIX + "ACK") is None:
        pytest.skip("native environment NOT provided; PostgreSQL reservation rehearsal NOT_RUN")
    assert os.environ[PREFIX + "ACK"] == ACK
    nonce = os.environ[PREFIX + "NONCE"]
    assert len(nonce) == 32 and all(c in "0123456789abcdef" for c in nonce)
    port = int(os.environ[PREFIX + "PORT"])
    assert 49152 <= port <= 65535
    data = Path(os.environ[PREFIX + "DATA"]).resolve()
    assert data == Path("/tmp") / ("ubid-v2-reservation-rehearsal-" + nonce) / "data"
    assert (data / "PG_VERSION").read_text().strip() == "16"
    urls = []
    for suffix, role in (("DDL_DSN", "ubid_v2_reservation_ddl"), ("RUNTIME_DSN", "ubid_v2_reservation_runtime")):
        url = make_url(os.environ[PREFIX + suffix])
        assert url.drivername == "postgresql+psycopg2" and url.host == "127.0.0.1"
        assert url.port == port and url.database == "ubid_v2_reservation_rehearsal_" + nonce
        assert url.username == role and url.password is None and not url.query
        urls.append(url)
    return urls, data, port


@pytest.fixture(scope="module")
def native_target():
    urls, data, port = guarded_target_configuration()
    engines = [
        create_engine(
            url,
            poolclass=NullPool,
            hide_parameters=True,
            connect_args={"connect_timeout": 5, "options": "-c lock_timeout=180000 -c statement_timeout=240000"},
        )
        for url in urls
    ]
    ddl, runtime = engines
    try:
        for engine in engines:
            with engine.connect() as c:
                assert tuple(
                    c.execute(
                        text(
                            "SELECT current_database(),current_user,session_user,pg_catalog.host(inet_server_addr()),inet_server_port()"
                        )
                    ).one()
                ) == (engine.url.database, engine.url.username, engine.url.username, "127.0.0.1", port)
                assert c.execute(text("SHOW server_version_num")).scalar_one().startswith("16")
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
                    assert names == REQUIRED_TABLES
                    for name in sorted(REQUIRED_TABLES):
                        assert (
                            c.execute(
                                text("SELECT pg_catalog.to_regclass(:name)"), {"name": "public." + name}
                            ).scalar_one()
                            is not None
                        )
                        assert c.execute(text(f"SELECT count(*) FROM public.{name}")).scalar_one() == 0
        yield ddl, runtime
    finally:
        for engine in engines:
            engine.dispose()
        # The external runner must stop/remove exactly this unique cluster and
        # capture teardown. Immutable synthetic ledgers remain until then.


@pytest.fixture
def reservation_native(native_graph):
    ddl, runtime, issuer, operation, proofs, parent = native_graph
    delivered = issuer.issue(operation, **proofs)
    issuance_id = delivered["receipt"]["issuanceId"]
    with Session(runtime) as s, s.begin():
        f = issuer._reader(s).read(issuance_id).facts
    approval = v2.parse_approval_event_v2(proofs["approval_wire"])
    pre = approval.envelope.pre_enrollment
    now = datetime.now(timezone.utc)
    observed = int(now.timestamp()) * 1000
    expires = min(
        observed + 60_000, f.phone_expires_at_ms, f.approver_expires_at_ms, f.full_expires_at_ms, pre.expires_at
    )
    enrollment = profile.canonical_enrollment_v2_bytes(
        audience="https://synthetic-social.example",
        device_id=f.device_id,
        ed25519_public_key=pre.ed25519_public_key,
        enrollment_challenge_id=secrets.token_hex(32),
        issued_at=observed,
        expires_at=expires,
        subject=f.subject,
        x25519_binding_id=f.binding_id,
        x25519_binding_version=f.binding_version,
        x25519_public_key_commitment=f.public_key_commitment,
    ).decode("ascii")
    parsed = profile.parse_enrollment_v2(enrollment)
    template = json.loads((ROOT / "tests/fixtures/social_preacceptance_ed25519_handoff_v2.json").read_bytes())["vector"]
    fields = json.loads(template["verificationContextWire"])
    device, approver = _binding_preimages(f)
    fields.update(
        subject=f.subject,
        deviceId=f.device_id,
        challengeId=parsed.enrollment_challenge_id,
        attemptId=secrets.token_hex(32),
        audience=parsed.audience,
        bindingId=f.binding_id,
        bindingVersion=f.binding_version,
        x25519PublicKeyCommitment=f.public_key_commitment,
        ed25519PublicKey=pre.ed25519_public_key,
        associationId=association.association_id_v1(enrollment, 1, None),
        sessionBinding=bindings.derive_session_binding_v1(device),
        approverSessionBinding=bindings.derive_approver_session_binding_v1(approver),
        fullProofId=f.full_proof_id,
        approverFullProofId=f.full_proof_id,
    )
    context = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    phone = profile.canonical_enrollment_proof_v2_bytes(
        enrollment_challenge_id=parsed.enrollment_challenge_id,
        enrollment_digest=profile.enrollment_v2_digest(enrollment),
        public_key=pre.ed25519_public_key,
        signature="11" * 64,
    ).decode("ascii")
    wire = v2.canonical_preaccepted_enrollment_verification_input_v2_bytes(
        approval_event_wire=approval.wire, context_wire=context, enrollment_wire=enrollment, phone_proof_wire=phone
    ).decode("ascii")
    # Existing genuine issuance primitive, only for disposable synthetic fixture.
    # The actual installed native AFTER INSERT revision producer must run.
    with Session(ddl) as s, s.begin():
        challenges.SqlAlchemyDeviceChallengeStore(s).create_issued(context_wire=context, challenge_wire=enrollment)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_numbers()

    def encoded(n):
        return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode().rstrip("=")

    jwk = dict(kty="RSA", use="sig", alg="RS256", kid="synthetic", n=encoded(public.n), e=encoded(public.e))
    jwk["kid"] = dedicated_reservation_key_id(
        key_fingerprint=evidence._public_key(jwk).fingerprint,
        trust_revision=1,
        not_before=observed - 1000,
        not_after=observed + 600_000,
    )
    trust = evidence.DeadlineEvidenceTrustRecordV1(jwk, 1, observed - 1000, observed + 600_000)
    ec = evidence.MessagingDeviceVerificationDeadlineEvidenceV1Config(
        enabled=True,
        issuer=f.issuer,
        audience=parsed.audience + evidence.EVIDENCE_AUDIENCE_PATH,
        client_id=f.client_id,
        service_principal=f.service_principal,
        trust_records=(trust,),
    )
    config = ReservationConfig(
        enabled=True,
        backend_id=f.backend_id,
        verification_audience=parsed.audience,
        selected_kid=trust.key_id,
        selected_revision=1,
        evidence_config=ec,
        trust_pins=((trust.key_id, 1, trust.trust_record_id),),
    )
    signing_calls = []
    observed_key = DelayedRSA(key, lambda: signing_calls.append(True))
    signer = DedicatedRS256EvidenceSigner(private_key=observed_key, config=config)
    signer._rehearsal_signing_calls = signing_calls
    return ddl, runtime, wire, issuance_id, config, signer, parsed.expires_at


def owner(session, g, clock=None):
    return V2ReservationOwner(session, config=g[4], signer=g[5], clock=clock or (lambda: datetime.now(timezone.utc)))


def test_native_rollback_atomicity_and_exact_committed_pending(reservation_native):
    g = reservation_native
    with Session(g[1]) as s:
        tx = s.begin()
        first = owner(s, g).reserve(g[2], issuance_id=g[3])
        tx.rollback()
    with g[1].connect() as c:
        assert not c.execute(
            select(durable.SocialPreacceptedEnrollmentV2AtomicAcceptanceRow).where(
                durable.SocialPreacceptedEnrollmentV2AtomicAcceptanceRow.reservation_id == first.reservation_id
            )
        ).all()
    with Session(g[1]) as s, s.begin():
        stored = owner(s, g).reserve(g[2], issuance_id=g[3])
    before = len(g[5]._rehearsal_signing_calls)
    with Session(g[1]) as s, s.begin():
        retry_owner = owner(s, g)
        # Prove retry does not enter the dedicated signer without replacing it.
        candidate = retry_owner.authority.prepare(g[2], g[3])
        assert type(candidate) is durable.StoredAtomicAcceptanceV1
        assert candidate.evidence_compact_jws == stored.evidence_compact_jws
    assert len(g[5]._rehearsal_signing_calls) == before


def _observe_wait(ddl, pid, future):
    end = time.monotonic() + 90
    pulse = Event()
    while time.monotonic() < end:
        with ddl.connect() as c:
            row = c.execute(
                text("SELECT wait_event_type FROM pg_catalog.pg_stat_activity WHERE pid=:pid"), {"pid": pid}
            ).one_or_none()
        if row and row[0] == "Lock":
            assert not future.done()
            return
        assert not future.done(), "worker completed before a native lock wait was observed"
        pulse.wait(0.05)
    pytest.fail("native lock wait not observed within diagnostic budget")


@pytest.mark.parametrize("cross_expiry", [False, True])
def test_native_completed_table_wait_resamples_clock_and_preserves_lock_order(reservation_native, cross_expiry):
    g = reservation_native
    backend = Queue()
    released = Event()
    observed = []

    def run():
        with Session(g[1]) as s, s.begin():

            def clock():
                now = datetime.now(timezone.utc)
                if released.is_set():
                    observed.append(now)
                # Injected trusted test server clock crosses actual input
                # deadline AFTER a completed native wait, without long sleeps.
                return datetime.fromtimestamp(g[6] / 1000, timezone.utc) if cross_expiry and released.is_set() else now

            backend.put(s.connection().execute(text("SELECT pg_catalog.pg_backend_pid()")).scalar_one())
            o = owner(s, g, clock)
            if cross_expiry:
                with pytest.raises(ReservationDenied):
                    o.reserve(g[2], issuance_id=g[3])
                assert o.failed and observed
                return None
            result = o.reserve(g[2], issuance_id=g[3])
            assert observed and result.observed_at >= int(observed[0].timestamp()) * 1000
            return result

    with Session(g[0]) as blocker:
        tx = blocker.begin()
        blocker.connection().execute(
            text("LOCK TABLE public.social_preaccepted_enrollment_v2_atomic_acceptances IN SHARE ROW EXCLUSIVE MODE")
        )
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(run)
            try:
                _observe_wait(g[0], backend.get(timeout=90), future)
            finally:
                released.set()
                tx.rollback()
            future.result(timeout=240)


def test_native_competing_first_reservations_complete_collision_set_and_no_resign(reservation_native):
    g = reservation_native
    start = Event()

    def run():
        start.wait(90)
        with Session(g[1]) as s, s.begin():
            o = owner(s, g)
            return o.reserve(g[2], issuance_id=g[3])

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(run) for _ in range(2)]
        start.set()
        results = [future.result(timeout=240) for future in futures]
    assert results[0] == results[1]
    assert len(g[5]._rehearsal_signing_calls) == 1
    with Session(g[1]) as s, s.begin():
        retry_owner = owner(s, g)
        stored = retry_owner.authority.discover(g[2])
        assert stored.evidence_compact_jws == results[0].evidence_compact_jws
        parsed = v2.parse_preaccepted_enrollment_verification_input_v2(g[2])
        complete = retry_owner.authority._collisions(parsed, stored)
        assert len(complete) == 1
        # Exercise the real native adapter with evidence digest/JTI included,
        # then independently inspect every canonical collision identity on
        # its same guarded connection. No catalog/authority check is patched.
        table = durable.SocialPreacceptedEnrollmentV2AtomicAcceptanceRow.__table__
        for column in (
            "reservation_id",
            "request_id",
            "operation_id",
            "device_id",
            "acceptance_id",
            "challenge_id",
            "association_id",
            "input_digest",
            "evidence_token_id",
            "evidence_digest",
        ):
            rows = (
                retry_owner.authority.guard.connection.execute(
                    select(table).where(table.c[column] == complete[0][column]).with_for_update()
                )
                .mappings()
                .all()
            )
            assert len(rows) == 1
            assert durable.parse_stored_atomic_acceptance_v1(rows[0], evidence_config=g[4].evidence_config) == stored
            retry_owner.authority._check()
        assert retry_owner.reserve(g[2], issuance_id=g[3]) == results[0]
    assert len(g[5]._rehearsal_signing_calls) == 1
    altered = json.loads(g[2])
    proof = json.loads(altered["phoneProof"])
    proof["signature"] = "22" * 64
    altered["phoneProof"] = json.dumps(proof, sort_keys=True, separators=(",", ":"))
    with Session(g[1]) as s, s.begin():
        with pytest.raises(ReservationDenied):
            owner(s, g).reserve(json.dumps(altered, sort_keys=True, separators=(",", ":")), issuance_id=g[3])


def test_native_root_xid_replacement_and_catalog_attestation(reservation_native):
    g = reservation_native
    with Session(g[1]) as s:
        tx = s.begin()
        o = owner(s, g)
        candidate = o.authority.prepare(g[2], g[3])
        # Native root ABA: original Python objects remain, backend root changes.
        s.connection().exec_driver_sql("ROLLBACK")
        s.connection().exec_driver_sql("BEGIN ISOLATION LEVEL READ COMMITTED")
        with pytest.raises(ReservationDenied):
            o.signer.sign(candidate, owner=o.authority)
        assert o.authority.guard.poisoned
        tx.rollback()
    with Session(g[1]) as s, s.begin():
        o = owner(s, g)
        o.authority.prepare(g[2], g[3])
        # Actual restricted owner construction exercised all native catalogs.
        assert o.authority.native.catalog_identity
        assert o.authority.challenge_reader._catalog_identity
        assert o.authority.storage._guard_definition_sha256


def test_native_observed_combined_lock_order_and_same_physical_backend(reservation_native):
    g = reservation_native
    observations = []

    def record(connection, cursor, statement, parameters, context, executemany):
        observations.append((id(connection.connection.dbapi_connection), statement))

    event.listen(g[1], "before_cursor_execute", record)
    try:
        with Session(g[1]) as s:
            tx = s.begin()
            owner(s, g).reserve(g[2], issuance_id=g[3])
            tx.rollback()
    finally:
        event.remove(g[1], "before_cursor_execute", record)
    assert len({physical for physical, _ in observations}) == 1
    sql = [statement for _, statement in observations]
    reservation_lock = next(i for i, statement in enumerate(sql) if statement.startswith("LOCK TABLE"))
    full = next(i for i, statement in enumerate(sql) if "FROM current_entitlement_evidence" in statement)
    binding = next(
        i
        for i, statement in enumerate(sql)
        if "FROM social_messaging_device_bindings" in statement and "FOR UPDATE" in statement
    )
    challenge = next(
        i
        for i, statement in enumerate(sql)
        if "FROM social_device_admission_challenges" in statement and "FOR UPDATE" in statement
    )
    history = next(
        i
        for i, statement in enumerate(sql)
        if "FROM social_device_ed25519_association_chains" in statement and "FOR UPDATE" in statement
    )
    # Native reader takes subject/User authority locks earlier, then evaluates
    # its evidence after binding under those held locks. This is the ACTUAL
    # combined order; no patched orchestration or fabricated order assertion.
    assert reservation_lock < binding < full < challenge < history


def test_native_same_oid_catalog_definition_change_poison_requires_rollback(reservation_native):
    g = reservation_native
    with Session(g[1]) as s:
        tx = s.begin()
        o = owner(s, g)
        candidate = o.authority.prepare(g[2], g[3])
        try:
            with g[0].begin() as c:
                c.exec_driver_sql("ALTER FUNCTION public.guard_social_preaccepted_v2_acceptance_v1() COST 101")
            with pytest.raises(ReservationDenied):
                o.signer.sign(candidate, owner=o.authority)
            assert o.authority.failed and o.authority.guard.poisoned
            assert not g[5]._rehearsal_signing_calls
        finally:
            tx.rollback()
            with g[0].begin() as c:
                c.exec_driver_sql("ALTER FUNCTION public.guard_social_preaccepted_v2_acceptance_v1() COST 100")


@pytest.mark.parametrize(
    "table",
    [
        "social_device_ed25519_association_chains",
        "social_device_ed25519_association_events",
        "social_device_enrollment_admission_receipts",
    ],
)
def test_native_history_row_filtering_denies_before_signing(reservation_native, table):
    g = reservation_native
    # Exact synthetic allowlist above; DDL belongs to the disposable owner.
    with g[0].begin() as c:
        c.exec_driver_sql(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
        c.exec_driver_sql(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")
    try:
        with Session(g[1]) as s, s.begin():
            o = owner(s, g)
            with pytest.raises(ReservationDenied):
                o.reserve(g[2], issuance_id=g[3])
            assert o.failed and o.authority.guard.poisoned
            assert not g[5]._rehearsal_signing_calls
    finally:
        with g[0].begin() as c:
            c.exec_driver_sql(f"ALTER TABLE public.{table} NO FORCE ROW LEVEL SECURITY")
            c.exec_driver_sql(f"ALTER TABLE public.{table} DISABLE ROW LEVEL SECURITY")


def _catalog_reader(session):
    return NativeV2AuthorityReader(
        session,
        client_id="synthetic",
        backend_id="synthetic-backend",
        principal="synthetic-principal",
        issuer="https://synthetic-ubid.example",
        clock=lambda: datetime.now(timezone.utc),
    )


def test_native_original_and_composed_roles_pass_but_midtransaction_profile_change_denies(native_target):
    ddl, runtime = native_target
    try:
        with Session(runtime) as s, s.begin():
            reader = _catalog_reader(s)
            reader._check()
            with ddl.begin() as c:
                c.execute(text("REVOKE pg_read_all_settings FROM ubid_v2_reservation_runtime"))
            with pytest.raises(V2IssuanceUnavailable):
                reader._check()
        with Session(runtime) as s, s.begin():
            _catalog_reader(s)._check()
        with ddl.begin() as c:
            c.execute(text("GRANT pg_read_all_settings TO ubid_v2_reservation_runtime"))
        with Session(runtime) as s, s.begin():
            _catalog_reader(s)._check()
    finally:
        with ddl.begin() as c:
            c.execute(text("GRANT pg_read_all_settings TO ubid_v2_reservation_runtime"))


@pytest.mark.parametrize("extra_role", ["pg_read_all_data", "pg_read_all_stats"])
def test_native_extra_role_membership_denies_before_authority_read(native_target, extra_role):
    ddl, runtime = native_target
    assert extra_role in ("pg_read_all_data", "pg_read_all_stats")
    try:
        with ddl.begin() as c:
            c.execute(text(f"GRANT {extra_role} TO ubid_v2_reservation_runtime"))
        with Session(runtime) as s, s.begin():
            with pytest.raises(V2IssuanceUnavailable):
                _catalog_reader(s)
    finally:
        with ddl.begin() as c:
            c.execute(text(f"REVOKE {extra_role} FROM ubid_v2_reservation_runtime"))
