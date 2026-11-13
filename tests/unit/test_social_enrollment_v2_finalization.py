"""Real signatures/native provenance with SQLite DML doubles, not native proof."""

import base64
import json
import weakref
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy import MetaData, select, text
from sqlalchemy.schema import BLANK_SCHEMA

from app.services import social_device_ed25519_association_storage as associations
from app.services import social_enrollment_v2_finalization_authority as authority
from app.services import social_enrollment_v2_finalization_storage as native
from app.services import social_messaging_mobile_pre_enrollment_v2 as v2
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_contract as canonical
from app.services import social_preaccepted_enrollment_verification_statement_v2 as statement
from app.services.social_enrollment_v2_finalization import V2FinalizationOwner
from app.services.social_enrollment_v2_finalization_contract import (
    FinalizationConfig,
    FinalizationDenied,
    StatementTrustPin,
)
from app.services.social_session_issuance_v2_authority import NativeV2AuthorityReader
from tests.unit.test_social_device_challenge_revision_storage import Rows
from tests.unit.test_social_enrollment_v2_reservation import (
    ReservationConnection,
    ReservationGraph,
    ReservationSession,
    reserve,
)


def signed_statement(input_wire, rc, at, key=None, *, expires_at=None):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()

    def encoded(n):
        return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode().rstrip("=")

    jwk = dict(kty="RSA", use="sig", alg="RS256", kid="synthetic-social-v2", n=encoded(numbers.n), e=encoded(numbers.e))
    config = statement.SocialPreacceptedEnrollmentVerificationStatementV2Config(
        enabled=True,
        issuer=rc.verification_audience,
        audience=rc.evidence_config.issuer + statement.STATEMENT_CONSUME_PATH,
        client_id=rc.evidence_config.client_id,
        service_principal=rc.evidence_config.service_principal,
        trusted_jwks=(jwk,),
        freshness_profile=rc.evidence_config.freshness_profile,
    )
    p = v2.parse_preaccepted_enrollment_verification_input_v2(input_wire)
    header = statement.canonical_preaccepted_enrollment_verification_statement_protected_header_v2_bytes(
        kid=jwk["kid"]
    ).decode()
    payload = statement.canonical_preaccepted_enrollment_verification_statement_payload_v2_bytes(
        issuer=config.issuer,
        audience=config.audience,
        client_id=config.client_id,
        service_principal=config.service_principal,
        expected_context_wire=p.context.wire,
        expected_input_wire=p.wire,
        issued_at=at,
        expires_at=at + 10000 if expires_at is None else expires_at,
        freshness_profile=config.freshness_profile,
    ).decode()
    signing = (
        statement._base64url_encode(header.encode()) + "." + statement._base64url_encode(payload.encode())
    ).encode()
    signature = key.sign(signing, padding.PKCS1v15(), hashes.SHA256())
    compact = statement.compact_preaccepted_enrollment_verification_statement_v2(
        protected_header_wire=header,
        payload_wire=payload,
        signature=signature,
        freshness_profile=config.freshness_profile,
    )
    pin = StatementTrustPin(jwk["kid"], config._keys[0].fingerprint, 1, at - 1000, at + 600000)
    return FinalizationConfig(True, rc, config, (pin,)), compact


class FinalConnection(ReservationConnection):
    def __init__(self, graph, actual):
        super().__init__(graph, actual)
        root = actual.get_transaction()
        if root not in graph.root_xids:
            graph.root_sequence += 1
            graph.root_xids[root] = str(graph.root_sequence)
        self.xid = graph.root_xids[root]

    def execute(self, statement, values=None):
        sql = str(statement)
        if sql.startswith("SELECT public.execute_social_enrollment_v2_native_effects"):
            self.graph.calls.append(values["stage"])
            p = v2.parse_preaccepted_enrollment_verification_input_v2(self.graph.input_wire)
            common = dict(
                id=values["reservation"],
                challenge=p.context.challenge_id,
                subject=p.context.subject,
                device=p.context.device_id,
                event=values["event"],
                root=self.xid,
            )
            if values["stage"] == "association":
                self.actual.execute(
                    associations.SocialDeviceEd25519AssociationChain.__table__.insert().values(
                        subject=p.context.subject,
                        device_id=p.context.device_id,
                        authority_epoch=1,
                        last_association_id=p.association_id,
                        last_association_version=1,
                        current_association_id=p.association_id,
                        state="active",
                    )
                )
                self.actual.execute(
                    associations.SocialDeviceEd25519AssociationEvent.__table__.insert().values(
                        subject=p.context.subject,
                        device_id=p.context.device_id,
                        authority_epoch=1,
                        kind="initial",
                        association_id=p.association_id,
                        association_version=1,
                        predecessor_association_id=None,
                        ed25519_public_key=p.context.ed25519_public_key,
                        enrollment_challenge_id=p.context.challenge_id,
                        event_wire=values["event"],
                    )
                )
                self.actual.execute(
                    text(
                        "INSERT INTO social_enrollment_v2_native_associations VALUES(:id,:challenge,:subject,:device,1,:event,:root)"
                    ),
                    common,
                )
            elif values["stage"] == "receipt":
                common.update(
                    effect_id=json.loads(values["effect"])["effectId"],
                    receipt_id=json.loads(values["receipt"])["receiptId"],
                    effect=values["effect"],
                    receipt=values["receipt"],
                    ep=values["evidence_pin"],
                    sp=values["statement_pin"],
                )
                self.actual.execute(
                    text(
                        "INSERT INTO social_enrollment_v2_native_effects VALUES(:id,:challenge,:subject,:device,1,:effect_id,:receipt_id,:event,:effect,:receipt,:ep,:sp,:root)"
                    ),
                    common,
                )
            else:
                self.actual.execute(
                    text(
                        "UPDATE social_device_admission_challenges SET state='consumed' WHERE challenge_id=:challenge"
                    ),
                    common,
                )
                self.actual.execute(
                    text("INSERT INTO social_enrollment_v2_native_consumptions VALUES(:id,:root)"), common
                )
            if self.graph.after_stage:
                self.graph.after_stage(values["stage"])
            return Rows([])
        if getattr(statement, "is_update", False) and statement.table.name == native.durable.TABLE:
            result = super().execute(statement, values)
            self.actual.execute(
                text("INSERT INTO social_enrollment_v2_native_decisions VALUES(:id,:root)"),
                dict(id=self.graph.reservation.reservation_id, root=self.xid),
            )
            self.graph.calls.append("cas")
            if self.graph.after_stage:
                self.graph.after_stage("cas")
            return result
        if sql.startswith("SELECT") and "public.social_enrollment_v2_native_" in sql:
            return self.actual.execute(text(sql.replace("public.", "")), values or {})
        if sql.startswith("SELECT * FROM public.social_device_admission_challenges"):
            return self.actual.execute(text(sql.replace("public.", "").replace(" FOR UPDATE", "")), values or {})
        if sql.startswith("SELECT revision FROM public.social_device_admission_challenge_revisions"):
            return Rows([(1,)])
        return super().execute(statement, values)


class FinalSession(ReservationSession):
    def connection(self):
        actual = self.actual.connection()
        if self.pinned is None or self.pinned.actual is not actual:
            self.pinned = FinalConnection(self.graph, actual)
        return self.pinned


class FinalGraph(ReservationGraph):
    def __init__(self, monkeypatch):
        super().__init__(monkeypatch)
        # The SQLite catalog double follows the production checkpoint API.
        # The original transaction guard remains active; native tests run the
        # complete PostgreSQL catalog checks without this fixture override.
        storage_check = native.durable.SqlAlchemyTransactionBoundAtomicAcceptanceStorage._check_transaction

        def checked_storage(store, *, finalization_schema=False):
            if type(finalization_schema) is not bool:
                raise ValueError("synthetic invalid catalog checkpoint")
            return storage_check(store)

        monkeypatch.setattr(
            native.durable.SqlAlchemyTransactionBoundAtomicAcceptanceStorage, "_check_transaction", checked_storage
        )
        self.calls = []
        self.root_xids = weakref.WeakKeyDictionary()
        self.root_sequence = 41
        self.after_stage = None
        self.catalog_identity = ("offline-catalog-double",)
        # Only catalog/native SQL effects are doubled. The original guarded
        # authority, Current-Full, revision, signatures and authentic reparsers run.
        monkeypatch.setattr(native, "attest_native_schema", lambda c: self.catalog_identity)
        watch = authority._watch_transactions
        monkeypatch.setattr(authority, "_watch_transactions", lambda owner, s, c: watch(owner, s.actual, c.actual))
        metadata = MetaData()
        for table in native.NATIVE_METADATA.sorted_tables:
            table.to_metadata(metadata, schema=None, referred_schema_fn=lambda *args: BLANK_SCHEMA)
        with self.engine.begin() as c:
            for table in metadata.sorted_tables:
                if table.name in native.NATIVE_COLUMNS:
                    table.create(c)
        with FinalSession(self) as s, s.begin():
            self.reservation = reserve(self, self.owner(s))
        at = int(self.now.timestamp()) * 1000
        self.final_config, self.statement = signed_statement(self.input_wire, self.config, at)

    def finalizer(self, session, config=None, clock=None):
        return V2FinalizationOwner(
            session, config=config or self.final_config, clock=clock or (lambda: int(self.now.timestamp() * 1000))
        )

    def arguments(self):
        return dict(
            reservation_id=self.reservation.reservation_id,
            reservation_revision=1,
            verification_input_wire=self.input_wire,
            evidence_compact_jws=self.reservation.evidence_compact_jws,
            statement_compact_jws=self.statement,
            issuance_id=self.issuance_id,
        )


@pytest.fixture
def final_graph(monkeypatch):
    graph = FinalGraph(monkeypatch)
    yield graph
    graph.engine.dispose()


def test_real_native_provenance_signatures_model_receipt_and_actual_shared_rows(final_graph):
    g = final_graph
    with FinalSession(g) as s, s.begin():
        owner = g.finalizer(s)
        result = owner.finalize(**g.arguments())
        stored = owner.authority.locked_row(g.reservation.reservation_id)
        assert result.receipt_wire == stored.receipt.wire
        assert g.calls == ["association", "receipt", "consumption", "cas"]
        assert result.final_admission == "denied" and result.publication_status == "provisional_until_caller_commit"
        assert not result.historical_recovery
        p = v2.parse_preaccepted_enrollment_verification_input_v2(g.input_wire)
        model = canonical.model_atomic_acceptance_and_cas_v1(
            reservation_wire=canonical._canonical(
                {
                    **json.loads(stored.reservation.wire),
                    "state": "pending",
                    "decidedAt": None,
                    "statementDigest": None,
                    "effectId": None,
                    "effectDigest": None,
                    "receiptId": None,
                }
            ),
            finalization_observation_wire=stored.finalization_observation_wire,
            expected_input_wire=g.input_wire,
            expected_context_wire=p.context.wire,
            evidence_compact_jws=g.reservation.evidence_compact_jws,
            evidence_config=g.config.evidence_config,
            statement_compact_jws=g.statement,
            statement_config=g.final_config.statement_config,
            decided_at=stored.reservation.decided_at,
        )
        assert result.receipt_wire == model.receipt.wire
        history = associations.SqlAlchemyEd25519AssociationStore(owner.authority.port).lock_history(
            p.context.subject, p.context.device_id
        )
        assert history.current.association_id == p.association_id and history.authority_epoch == 1


def test_accepted_retry_precedes_live_authority_and_has_zero_mutations(final_graph, monkeypatch):
    g = final_graph
    with FinalSession(g) as s, s.begin():
        first = g.finalizer(s).finalize(**g.arguments())
    g.calls.clear()
    g.now += timedelta(seconds=601)

    def deny_live(*args, **kwargs):
        raise AssertionError("historical retry requested live authority")

    monkeypatch.setattr(NativeV2AuthorityReader, "read", deny_live)
    with FinalSession(g) as s, s.begin():
        retry = g.finalizer(s).finalize(**g.arguments())
        assert retry.receipt_wire == first.receipt_wire and retry.historical_recovery
    assert not g.calls


@pytest.mark.parametrize("boundary", ["association", "receipt", "consumption", "cas"])
def test_expiry_at_each_mutation_poison_and_caller_rollback(final_graph, boundary):
    g = final_graph

    def expire(stage):
        if stage == boundary:
            g.now += timedelta(seconds=10)

    g.after_stage = expire
    with FinalSession(g) as s:
        root = s.begin()
        owner = g.finalizer(s)
        with pytest.raises(FinalizationDenied) as caught:
            owner.finalize(**g.arguments())
        assert caught.value.__cause__ is None and caught.value.__context__ is None
        with pytest.raises(FinalizationDenied):
            g.finalizer(s)
        root.rollback()
    with g.engine.connect() as c:
        for table in native.NATIVE_COLUMNS:
            assert c.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 0
        assert c.execute(select(associations.SocialDeviceEd25519AssociationEvent)).all() == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("reservation_revision", True),
        ("reservation_id", "f" * 64),
        ("issuance_id", "e" * 64),
        ("statement_compact_jws", "not-a-signature"),
        ("verification_input_wire", "{}"),
    ],
)
def test_changed_request_or_artifact_denies_before_effect(final_graph, field, value):
    g = final_graph
    args = g.arguments()
    args[field] = value
    with FinalSession(g) as s, s.begin():
        with pytest.raises(FinalizationDenied):
            g.finalizer(s).finalize(**args)
    assert not g.calls


def test_completed_wait_resamples_success_and_exclusive_expiry(final_graph):
    g = final_graph
    g.wait = lambda: setattr(g, "now", g.now + timedelta(milliseconds=1))
    with FinalSession(g) as s, s.begin():
        result = g.finalizer(s).finalize(**g.arguments())
        assert json.loads(result.receipt_wire)["decidedAt"] == int(g.now.timestamp() * 1000)


def test_same_root_provisional_row_is_not_accepted_historical_recovery(final_graph):
    g = final_graph
    with FinalSession(g) as s:
        root = s.begin()
        g.finalizer(s).finalize(**g.arguments())
        g.now += timedelta(seconds=10)
        with pytest.raises(FinalizationDenied):
            g.finalizer(s).finalize(**g.arguments())
        root.rollback()


def test_catalog_plan_keeps_complete_before_and_after_boundaries_for_each_effect(final_graph, monkeypatch):
    g = final_graph
    with FinalSession(g) as session, session.begin():
        owner = g.finalizer(session)
        args = g.arguments()
        stored = owner.authority.discover_finalization(
            args["reservation_id"],
            args["reservation_revision"],
            args["verification_input_wire"],
            args["evidence_compact_jws"],
            args["statement_compact_jws"],
        )
        candidate = owner.authority.prepare_finalization(stored, args["statement_compact_jws"], args["issuance_id"])
        observed = []
        schema = owner.effects.check
        recheck = owner.authority.recheck
        sql = owner.effects.guard.sql

        def checked_schema():
            observed.append(("schema", None))
            return schema()

        def checked_authority(plan, *, phase):
            observed.append(("authority", phase))
            return recheck(plan, phase=phase)

        def checked_sql(expression, values=None):
            if expression.startswith("SELECT public.execute_social_enrollment_v2_native_effects"):
                observed.append(("effect", values["stage"]))
            return sql(expression, values)

        monkeypatch.setattr(owner.effects, "check", checked_schema)
        monkeypatch.setattr(owner.authority, "recheck", checked_authority)
        monkeypatch.setattr(owner.effects.guard, "sql", checked_sql)
        owner.effects.execute(candidate)
        assert observed == [
            ("schema", None),
            ("authority", "prepared"),
            ("effect", "association"),
            ("schema", None),
            ("authority", "association_written"),
            ("schema", None),
            ("authority", "association_written"),
            ("effect", "receipt"),
            ("schema", None),
            ("authority", "receipt_written"),
            ("schema", None),
            ("authority", "receipt_written"),
            ("effect", "consumption"),
            ("schema", None),
            ("authority", "effects_written"),
        ]
        assert g.calls == ["association", "receipt", "consumption"]
        session.rollback()  # An effects-only draft never becomes an accepted decision.
