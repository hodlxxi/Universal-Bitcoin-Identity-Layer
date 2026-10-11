"""Offline producer -> native reader -> RSA -> strict consumer -> pending store.

SQLite and catalog doubles prove source decisions, NOT PostgreSQL serialization.
"""

import base64
import json
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select, text
from sqlalchemy.orm import Session as OrmSession

from app.models import CurrentEntitlementEvidence, OAuthToken
from app.services import social_admission_session_binding as bindings
from app.services import social_device_challenge_revision_storage as revision
from app.services import social_device_challenge_store as challenge_store
from app.services import social_device_ed25519_association_storage as association
from app.services import social_messaging_device_admission_contract as admission
from app.services import social_messaging_device_verification_deadline_evidence_v1 as evidence
from app.services import social_messaging_mobile_pre_enrollment_v2 as v2
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_contract as pending
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_storage as durable
from app.services.social_enrollment_receipt_storage import SocialEnrollmentAdmissionReceiptRow
from app.services.social_enrollment_v2_reservation import V2ReservationOwner
from app.services.social_enrollment_v2_reservation_authority import _binding_preimages
from app.services.social_enrollment_v2_reservation_contract import (
    ReservationConfig,
    ReservationDenied,
    dedicated_reservation_key_id,
)
from app.services.social_enrollment_v2_reservation_signer import DedicatedRS256EvidenceSigner
from tests.unit.test_social_device_challenge_revision_storage import GuardedSession, Rows
from tests.unit.test_social_session_issuance_v2_storage import NOW, VECTOR, ConnectionDouble, Graph, SessionDouble


def configuration(key, kid="dedicated-evidence", *, retained=()):
    numbers = key.public_key().public_numbers()

    def encoded(n):
        return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode().rstrip("=")

    start = int(NOW.timestamp()) * 1000
    jwk = dict(kty="RSA", use="sig", alg="RS256", kid=kid, n=encoded(numbers.n), e=encoded(numbers.e))
    kid = dedicated_reservation_key_id(
        key_fingerprint=evidence._public_key(jwk).fingerprint,
        trust_revision=1,
        not_before=start - 1000,
        not_after=start + 600_000,
    )
    jwk["kid"] = kid
    record = evidence.DeadlineEvidenceTrustRecordV1(
        jwk,
        1,
        start - 1000,
        start + 600_000,
    )
    ec = evidence.MessagingDeviceVerificationDeadlineEvidenceV1Config(
        enabled=True,
        issuer="https://ubid.example",
        audience="https://social.example" + evidence.EVIDENCE_AUDIENCE_PATH,
        client_id="social-client",
        service_principal="principal",
        trust_records=retained + (record,),
    )
    return ReservationConfig(
        enabled=True,
        backend_id="backend",
        verification_audience="https://social.example",
        selected_kid=kid,
        selected_revision=1,
        evidence_config=ec,
        trust_pins=tuple(sorted((r.key_id, r.trust_revision, r.trust_record_id) for r in ec.trust_records)),
    )


class ReservationConnection(ConnectionDouble):
    def execute(self, statement, values=None):
        sql = str(statement)
        self.graph.events.append(sql)
        if sql.startswith("LOCK TABLE"):
            if self.graph.wait:
                self.graph.wait()
            return Rows([])
        if " AS resolves, " in sql or " AS resolves " in sql:
            # Model only metadata actually selected: older code that omits a
            # visibility/ownership column cannot see its unsafe state.
            security = getattr(self.graph, "history_security", {})
            selected = [
                ("row_security", "c.relrowsecurity"),
                ("force_row_security", "c.relforcerowsecurity"),
                ("runtime_owns_or_inherits", "AS runtime_owns_or_inherits"),
            ]
            return Rows(
                [
                    (10 + i, 20 + i, 30, "r", True)
                    + tuple(security.get(i, {}).get(name, False) for name, selector in selected if selector in sql)
                    for i in range(3)
                ]
            )
        if "public.social_device_enrollment_admission_receipts" in sql:
            query = sql.replace(" FOR UPDATE", "").replace(
                "public.social_device_enrollment_admission_receipts", "social_device_enrollment_admission_receipts"
            )
            query = query.replace("authority_wire::jsonb ->> 'deviceId'", "json_extract(authority_wire, '$.deviceId')")
            query = query.replace("authority_wire::jsonb ->> 'subject'", "json_extract(authority_wire, '$.subject')")
            return self.actual.execute(text(query), values)
        if (
            sql in (revision.CATALOG_SQL, revision.SECURITY_SQL)
            or "public.social_device_admission_challenge_revisions" in sql
        ):
            return self.graph.revision_catalog.execute(statement, values)
        if "current_setting('transaction_isolation')" in sql:
            return super().execute(statement, values)
        if "current_setting('server_version_num')" in sql:
            return Rows("160010")
        if "SELECT count(*) FROM pg_trigger" in sql:
            return Rows(6 if values and "chain" in values else 2)
        if sql.startswith("SHOW") or "pg_current_xact_id" in sql or "pg_advisory_xact_lock" in sql:
            return super().execute(statement, values)
        # Real canonical Core selects/inserts (including PostgreSQL ON CONFLICT)
        # operate on synthetic in-memory SQLite, on the same pinned connection.
        result = self.actual.execute(statement, values or {})
        if getattr(statement, "is_insert", False) and statement.table.name == durable.TABLE and self.graph.after_insert:
            self.graph.after_insert()
        return result


class ReservationSession(SessionDouble):
    def connection(self):
        actual = self.actual.connection()
        if self.pinned is None or self.pinned.actual is not actual:
            self.pinned = ReservationConnection(self.graph, actual)
        return self.pinned


class ReservationGraph(Graph):
    def __init__(self, monkeypatch):
        super().__init__(monkeypatch)
        self.events = []
        self.wait = self.after_insert = None
        self.create()
        delivery = self.issue()
        self.issuance_id = delivery["receipt"]["issuanceId"]
        with SessionDouble(self) as s, s.begin():
            f = self.reader(s).read(self.issuance_id).facts
        fields = json.loads(VECTOR["verificationContextWire"])
        device, approver = _binding_preimages(f)
        fields.update(
            sessionBinding=bindings.derive_session_binding_v1(device),
            approverSessionBinding=bindings.derive_approver_session_binding_v1(approver),
            fullProofId=f.full_proof_id,
            approverFullProofId=f.full_proof_id,
        )
        context = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        original = json.loads(VECTOR["preacceptedEnrollmentVerificationInputWire"])
        self.input_wire = v2.canonical_preaccepted_enrollment_verification_input_v2_bytes(
            approval_event_wire=VECTOR["approvalEventWire"],
            context_wire=context,
            enrollment_wire=original["enrollment"],
            phone_proof_wire=original["phoneProof"],
        ).decode("ascii")
        p = v2.parse_preaccepted_enrollment_verification_input_v2(self.input_wire)
        row = dict(
            challenge_id=p.context.challenge_id,
            context_wire=p.context.wire,
            challenge_wire=p.enrollment_wire,
            routing_request_wire=None,
            state="issued",
        )
        self.revision_catalog = GuardedSession(row)
        with self.engine.begin() as c:
            challenge_store.SocialDeviceAdmissionChallengeRow.__table__.create(c)
            association.SocialDeviceEd25519AssociationChain.__table__.create(c)
            association.SocialDeviceEd25519AssociationEvent.__table__.create(c)
            SocialEnrollmentAdmissionReceiptRow.__table__.create(c)
            durable._AtomicAcceptanceBase.metadata.create_all(c)
            c.execute(challenge_store.SocialDeviceAdmissionChallengeRow.__table__.insert().values(**row))

        # Storage catalog injection is explicit offline-only. The native XID,
        # Session/Connection/root/savepoint/physical checks are the REAL guard.
        def checked_storage(store):
            if store._failed:
                raise ValueError("synthetic poisoned storage")
            store._session.guard.check()
            store._connection = store._session.guard.connection
            return store._connection

        monkeypatch.setattr(
            durable.SqlAlchemyTransactionBoundAtomicAcceptanceStorage, "_check_transaction", checked_storage
        )
        self.evidence_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.config = configuration(self.evidence_key)
        self.sign_calls = 0
        original_sign = DedicatedRS256EvidenceSigner.sign

        def counted(signer, candidate, *, owner):
            self.sign_calls += 1
            return original_sign(signer, candidate, owner=owner)

        monkeypatch.setattr(DedicatedRS256EvidenceSigner, "sign", counted)

    def owner(self, session, config=None, key=None):
        config = config or self.config
        return V2ReservationOwner(
            session,
            config=config,
            clock=lambda: self.now,
            signer=DedicatedRS256EvidenceSigner(private_key=key or self.evidence_key, config=config),
        )

    def rows(self):
        with self.engine.connect() as c:
            return c.execute(select(durable.SocialPreacceptedEnrollmentV2AtomicAcceptanceRow)).all()


@pytest.fixture
def reservation_graph(monkeypatch):
    g = ReservationGraph(monkeypatch)
    yield g
    g.engine.dispose()


def reserve(g, owner):
    return owner.reserve(g.input_wire, issuance_id=g.issuance_id)


def test_real_native_graph_rsa_strict_consumer_pending_storage_and_exact_retry(reservation_graph):
    g = reservation_graph
    with ReservationSession(g) as s, s.begin():
        result = reserve(g, g.owner(s))
        authenticated = evidence.verify_messaging_device_verification_deadline_evidence_v1(
            result.evidence_compact_jws,
            config=g.config.evidence_config,
            expected_input_wire=g.input_wire,
            now=result.observed_at,
        )
        claims = authenticated.claims
        assert claims.operation_id == "99" * 32
        assert claims.social_session_issuance_id == g.issuance_id
        assert claims.observed_at == int(NOW.timestamp()) * 1000
        assert claims.expires_at == claims.observed_at + 10000
        wire = pending.canonical_pending_atomic_acceptance_reservation_v1_bytes(
            evidence_compact_jws=result.evidence_compact_jws,
            evidence_config=g.config.evidence_config,
            expected_input_wire=g.input_wire,
            observed_at=result.observed_at,
            challenge_revision=1,
        )
        assert pending.parse_atomic_acceptance_reservation_v1(wire.decode()).reservation_id == result.reservation_id
        assert result.provisional_until_caller_commit and result.final_admission == "denied"
    g.now += timedelta(milliseconds=333)
    g.sign_calls = 0
    with ReservationSession(g) as s, s.begin():
        retry = reserve(g, g.owner(s))
        assert retry == result
    assert g.sign_calls == 0 and len(g.rows()) == 1


def test_retry_retains_original_trust_when_new_key_is_selected(reservation_graph):
    g = reservation_graph
    with ReservationSession(g) as s, s.begin():
        first = reserve(g, g.owner(s))
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    new_config = configuration(new_key, "new-dedicated", retained=g.config.evidence_config.trust_records)
    g.now += timedelta(milliseconds=1)
    g.sign_calls = 0
    with ReservationSession(g) as s, s.begin():
        assert reserve(g, g.owner(s, new_config, new_key)) == first
    assert g.sign_calls == 0


@pytest.mark.parametrize("delay", ["locks", "sign", "persistence"])
def test_expiry_after_completed_wait_or_slow_sign_or_persistence_poison_requires_rollback(
    reservation_graph, monkeypatch, delay
):
    g = reservation_graph
    if delay == "locks":
        g.wait = lambda: setattr(g, "now", NOW + timedelta(seconds=60))
    elif delay == "persistence":
        g.after_insert = lambda: setattr(g, "now", NOW + timedelta(seconds=10))
    else:
        original = DedicatedRS256EvidenceSigner.sign

        def slow(signer, candidate, *, owner):
            compact = original(signer, candidate, owner=owner)
            g.now = NOW + timedelta(seconds=10)
            return compact

        monkeypatch.setattr(DedicatedRS256EvidenceSigner, "sign", slow)
    with ReservationSession(g) as s:
        transaction = s.begin()
        owner = g.owner(s)
        with pytest.raises(ReservationDenied) as error:
            reserve(g, owner)
        assert error.value.__context__ is None and error.value.__cause__ is None
        assert owner.failed and owner.authority.guard.poisoned
        assert transaction.is_active  # no internal rollback/commit/savepoint
        with pytest.raises(ReservationDenied):
            reserve(g, owner)
        transaction.rollback()
    assert g.rows() == []


def test_fractional_clock_and_observation_after_wait(reservation_graph):
    g = reservation_graph
    g.wait = lambda: setattr(g, "now", NOW + timedelta(microseconds=2_123_999))
    with ReservationSession(g) as s, s.begin():
        result = reserve(g, g.owner(s))
    assert result.observed_at == int(NOW.timestamp()) * 1000 + 2123


def test_sql_failure_poison_no_provisional_success_and_caller_rollback(reservation_graph):
    g = reservation_graph

    def fail():
        raise RuntimeError("confidential driver detail")

    g.after_insert = fail
    with ReservationSession(g) as s:
        transaction = s.begin()
        owner = g.owner(s)
        with pytest.raises(ReservationDenied) as error:
            reserve(g, owner)
        assert error.value.__context__ is None and transaction.is_active
        transaction.rollback()
    assert not g.rows()


def test_no_effects_receipt_association_consumption_or_cas(reservation_graph):
    g = reservation_graph
    with ReservationSession(g) as s:
        tx = s.begin()
        reserve(g, g.owner(s))
        connection = s.connection().actual
        assert (
            connection.execute(select(challenge_store.SocialDeviceAdmissionChallengeRow.state)).scalar_one() == "issued"
        )
        for model in (
            association.SocialDeviceEd25519AssociationChain,
            association.SocialDeviceEd25519AssociationEvent,
            SocialEnrollmentAdmissionReceiptRow,
        ):
            assert not connection.execute(select(model.__table__)).all()
        tx.rollback()
    assert not g.rows()


@pytest.mark.parametrize(
    "missing",
    ["original_missing", "original_revoked", "original_replaced", "expired", "changed_input", "wrong_issuance"],
)
def test_pending_retry_denies_changed_original_authority_and_bytes_without_signing(reservation_graph, missing):
    g = reservation_graph
    with ReservationSession(g) as s, s.begin():
        first = reserve(g, g.owner(s))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    old = g.config.selected_trust()
    retained = (old,)
    if missing == "original_missing":
        retained = ()
    elif missing == "original_revoked":
        retained = (replace(old, revoked_at=old.not_before),)
    elif missing == "original_replaced":
        retained = (replace(old, trust_revision=2),)
        with pytest.raises(ReservationDenied):
            configuration(key, "rotated-dedicated", retained=retained)
        # Even replacing both public registration and independent pin cannot
        # relabel the revision encoded in the original signed kid.
        return
    config = configuration(key, "rotated-dedicated", retained=retained)
    wire, issuance = g.input_wire, g.issuance_id
    if missing == "expired":
        g.now = NOW + timedelta(seconds=10)
    elif missing == "changed_input":
        parsed = json.loads(wire)
        proof = json.loads(parsed["phoneProof"])
        proof["signature"] = "22" * 64
        parsed["phoneProof"] = json.dumps(proof, sort_keys=True, separators=(",", ":"))
        wire = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    elif missing == "wrong_issuance":
        issuance = "ee" * 32
    g.sign_calls = 0
    with ReservationSession(g) as s, s.begin():
        with pytest.raises(ReservationDenied):
            g.owner(s, config, key).reserve(wire, issuance_id=issuance)
    assert g.sign_calls == 0
    with g.engine.connect() as c:
        row = c.execute(select(durable.SocialPreacceptedEnrollmentV2AtomicAcceptanceRow.__table__)).mappings().one()
    assert row["evidence_compact_jws"] == first.evidence_compact_jws


@pytest.mark.parametrize("state", ["rejected", "expired", "cancelled"])
def test_terminal_uniqueness_is_retained_and_never_reopened(reservation_graph, state):
    g = reservation_graph
    with ReservationSession(g) as s, s.begin():
        first = reserve(g, g.owner(s))
    with g.engine.begin() as c:
        row = c.execute(select(durable.SocialPreacceptedEnrollmentV2AtomicAcceptanceRow.__table__)).mappings().one()
        decided = first.expires_at if state == "expired" else first.observed_at
        terminal = pending.transition_pending_reservation_terminal_v1_bytes(
            row["reservation_wire"], state=state, decided_at=decided
        ).decode("ascii")
        c.execute(
            durable.SocialPreacceptedEnrollmentV2AtomicAcceptanceRow.__table__.update().values(
                reservation_wire=terminal, state=state, decided_at=decided
            )
        )
    g.sign_calls = 0
    with ReservationSession(g) as s, s.begin():
        with pytest.raises(ReservationDenied):
            reserve(g, g.owner(s))
    assert g.sign_calls == 0 and len(g.rows()) == 1


def test_caller_dict_and_evidence_substitution_are_not_api_authority(reservation_graph):
    g = reservation_graph
    with ReservationSession(g) as s, s.begin():
        with pytest.raises(ReservationDenied):
            g.owner(s).reserve({"current": True, "input": g.input_wire}, issuance_id=g.issuance_id)
    with ReservationSession(g) as s, s.begin():
        with pytest.raises(ReservationDenied):
            g.owner(s).reserve(g.input_wire, issuance_id=g.issuance_id, evidence_compact_jws="a.b.c")
    assert g.sign_calls == 0


@pytest.mark.parametrize(
    "column",
    [
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
    ],
)
def test_complete_collision_set_reparses_every_indexed_identity_before_signing(reservation_graph, column):
    g = reservation_graph
    with ReservationSession(g) as s, s.begin():
        reserve(g, g.owner(s))
    with g.engine.begin() as c:
        row = c.execute(select(durable.SocialPreacceptedEnrollmentV2AtomicAcceptanceRow.__table__)).mappings().one()
        original = row[column]
        # Keep the typed digest prefix and change just one canonical hex byte.
        replacement = original[:-1] + ("0" if original[-1] != "0" else "1")
        c.execute(
            durable.SocialPreacceptedEnrollmentV2AtomicAcceptanceRow.__table__.update().values(**{column: replacement})
        )
    g.sign_calls = 0
    with ReservationSession(g) as s, s.begin():
        with pytest.raises(ReservationDenied):
            reserve(g, g.owner(s))
    assert g.sign_calls == 0


def test_ambiguous_locked_collision_observation_denies_before_native_authority(reservation_graph, monkeypatch):
    from tests.unit.test_social_device_challenge_revision_storage import Rows

    g = reservation_graph
    with ReservationSession(g) as s, s.begin():
        reserve(g, g.owner(s))
    g.sign_calls = 0
    with ReservationSession(g) as s, s.begin():
        owner = g.owner(s)
        connection = s.connection()
        original = connection.execute

        def ambiguous(statement, values=None):
            result = original(statement, values)
            if getattr(statement, "is_select", False) and durable.TABLE in str(statement):
                rows = result.mappings().all()
                return Rows(rows + rows)
            return result

        monkeypatch.setattr(connection, "execute", ambiguous)
        with pytest.raises(ReservationDenied):
            reserve(g, owner)
        assert owner.authority.native is None
    assert g.sign_calls == 0


def test_failed_transaction_cannot_be_reopened_with_new_owner_before_caller_rollback(reservation_graph):
    g = reservation_graph

    def fail():
        raise RuntimeError("synthetic provisional persistence failure")

    g.after_insert = fail
    with ReservationSession(g) as s:
        tx = s.begin()
        with pytest.raises(ReservationDenied):
            reserve(g, g.owner(s))
        g.after_insert = None
        with pytest.raises(ReservationDenied):
            g.owner(s)
        assert tx.is_active
        tx.rollback()
        with s.begin():
            result = reserve(g, g.owner(s))
            assert result.provisional_until_caller_commit
    assert len(g.rows()) == 1
