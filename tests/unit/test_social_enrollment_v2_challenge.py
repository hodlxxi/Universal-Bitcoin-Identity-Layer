"""Real native provenance and canonical consumers, with explicit SQLite doubles.

PostgreSQL catalog/locks and the revision INSERT trigger are doubled. Genuine
native PostgreSQL serialization, grants and trigger execution are not proved.
"""

import json
import unittest
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone

from app.services import social_enrollment_v2_challenge as challenge


class DisabledChallengeContractTests(unittest.TestCase):
    def test_disabled_default_has_no_identity_or_runtime_activation(self):
        config = challenge.EnrollmentChallengeConfig()
        self.assertFalse(config.enabled)
        self.assertEqual(config.lifetime_ms, 60000)
        self.assertEqual(
            (config.client_id, config.backend_id, config.service_principal, config.issuer, config.audience),
            ("", "", "", "", ""),
        )
        self.assertIsNone(challenge.build_enrollment_v2_challenge_composition())
        self.assertFalse(challenge.RUNTIME_ENABLED)
        self.assertFalse(challenge.DM_TRANSPORT_ENABLED)

    def test_only_literal_builder_enable_boolean(self):
        for value in (0, 1, "true", None, (), {}):
            with self.subTest(value=value), self.assertRaises(challenge.EnrollmentChallengeUnavailable):
                challenge.build_enrollment_v2_challenge_composition(enabled=value)

    def test_config_enable_flag_cannot_coerce(self):
        for value in (0, 1, "false", None):
            with self.subTest(value=value), self.assertRaises(challenge.EnrollmentChallengeUnavailable):
                challenge.EnrollmentChallengeConfig(enabled=value)

    def test_lifetime_is_a_bounded_exact_integer(self):
        for value in (True, False, 0, -1, 60001, 60000.0, "60000", None):
            with self.subTest(value=value), self.assertRaises(challenge.EnrollmentChallengeUnavailable):
                challenge.EnrollmentChallengeConfig(lifetime_ms=value)
        self.assertEqual(challenge.EnrollmentChallengeConfig(lifetime_ms=1).lifetime_ms, 1)
        self.assertEqual(challenge.EnrollmentChallengeConfig(lifetime_ms=60000).lifetime_ms, 60000)

    def test_identity_fields_are_not_coerced(self):
        for name in ("client_id", "backend_id", "service_principal", "issuer", "audience"):
            with self.subTest(name=name), self.assertRaises(challenge.EnrollmentChallengeUnavailable):
                challenge.EnrollmentChallengeConfig(**{name: True})

    def test_partial_empty_configuration_denies(self):
        with self.assertRaises(challenge.EnrollmentChallengeUnavailable):
            challenge.EnrollmentChallengeConfig(enabled=True)
        with self.assertRaises(challenge.EnrollmentChallengeUnavailable):
            challenge.EnrollmentChallengeConfig(backend_id="backend")

    def test_configuration_is_immutable(self):
        with self.assertRaises(FrozenInstanceError):
            challenge.EnrollmentChallengeConfig().enabled = True

    def test_committed_challenge_has_no_admission_or_bearer_authority(self):
        result = challenge.CommittedEnrollmentChallenge(
            "private-context", "private-challenge", "private-approval", 1, 2
        )
        self.assertEqual(result.publication_status, "committed")
        self.assertEqual(result.final_admission, "denied")
        self.assertEqual(result.bearer_authority, "none")
        self.assertEqual(result.challenge_revision, 1)
        self.assertNotIn("private-", repr(result))
        with self.assertRaises(FrozenInstanceError):
            result.expires_at = 60000


@contextmanager
def _graph(monkeypatch):
    from sqlalchemy import delete, select, text

    from app.services import social_device_challenge_store as store
    from app.services import social_enrollment_v2_finalization_authority as final_authority
    from tests.unit.test_social_device_challenge_revision_storage import Rows
    from tests.unit.test_social_enrollment_v2_reservation import (
        ReservationConnection,
        ReservationGraph,
        ReservationSession,
    )

    class ChallengeConnection(ReservationConnection):
        def execute(self, statement, values=None):
            sql = str(statement)
            if sql == challenge.LOCK_SQL:
                self.graph.events.append(sql)
                if self.graph.lock_wait is not None:
                    callback, self.graph.lock_wait = self.graph.lock_wait, None
                    callback()
                return Rows([])
            if sql == challenge.LOOKUP_SQL:
                self.graph.events.append(sql)
                return self.actual.execute(
                    text(
                        "SELECT challenge_id FROM social_device_admission_challenges "
                        "WHERE json_extract(context_wire, '$.sessionBinding') = :binding "
                        "ORDER BY challenge_id LIMIT 2"
                    ),
                    values,
                )
            if sql.startswith("SELECT challenge_id, revision FROM public.social_device_admission_challenge_revisions"):
                return self.actual.execute(text(sql.replace("public.", "")), values)
            result = super().execute(statement, values)
            if getattr(statement, "is_insert", False) and statement.table.name == "social_device_admission_challenges":
                key = statement.compile().params["challenge_id"]
                self.graph.created_ids.append(key)
                if self.graph.produce_revision:
                    # Explicit synthetic counterpart to the native AFTER INSERT
                    # trigger; actual SQLite write uses the parent's SAME root.
                    self.actual.execute(
                        text("INSERT INTO social_device_admission_challenge_revisions VALUES (:id,1)"), {"id": key}
                    )
                if self.graph.after_create is not None:
                    self.graph.after_create()
            return result

    class ChallengeSession(ReservationSession):
        def connection(self):
            actual = self.actual.connection()
            if self.pinned is None or self.pinned.actual is not actual:
                self.pinned = ChallengeConnection(self.graph, actual)
            return self.pinned

    graph = ReservationGraph(monkeypatch)
    try:
        delivery = graph.issue()
        graph.phone_bearer = delivery["viewerAccessToken"]
        graph.native_expires_at = delivery["receipt"]["expiresAt"]
        graph.created_ids = []
        graph.lock_wait = graph.after_create = None
        graph.produce_revision = True
        graph.session_class = ChallengeSession
        # Start before challenge creation. This changes only the synthetic
        # fixture's prepopulated row, never any production/deployed history.
        with graph.engine.begin() as connection:
            connection.execute(delete(store.SocialDeviceAdmissionChallengeRow))
            connection.execute(
                text(
                    "CREATE TABLE social_device_admission_challenge_revisions "
                    "(challenge_id TEXT PRIMARY KEY, revision INTEGER NOT NULL)"
                )
            )
        watch = final_authority._watch_transactions
        monkeypatch.setattr(
            final_authority,
            "_watch_transactions",
            lambda owner, session, connection: watch(owner, session.actual, connection.actual),
        )
        graph.lifecycle._factory = lambda: ChallengeSession(graph)
        graph.challenge_config = challenge.EnrollmentChallengeConfig(
            enabled=True,
            client_id=graph.config.evidence_config.client_id,
            backend_id=graph.config.backend_id,
            service_principal=graph.config.evidence_config.service_principal,
            issuer=graph.config.evidence_config.issuer,
            audience=graph.config.verification_audience,
        )

        def service(config=None):
            return challenge.build_enrollment_v2_challenge_composition(
                enabled=True,
                lifecycle=graph.lifecycle,
                config=config or graph.challenge_config,
                clock=lambda: int(graph.now.timestamp() * 1000),
            )

        def rows():
            with graph.engine.connect() as connection:
                return connection.execute(select(store.SocialDeviceAdmissionChallengeRow)).mappings().all()

        graph.challenge_service = service
        graph.challenge_rows = rows
        yield graph
    finally:
        graph.engine.dispose()


def _create(graph):
    return graph.challenge_service().challenge(graph.issuance_id, viewer_bearer=graph.phone_bearer)


def test_real_native_challenge_and_revision_are_saved_before_publication(monkeypatch):
    from sqlalchemy import text

    from app.services import social_messaging_device_admission_contract as admission
    from app.services.social_messaging_device_ed25519_association_lifecycle import association_id_v1
    from app.services.social_messaging_device_proof_profile import parse_enrollment_v2

    with _graph(monkeypatch) as graph:
        result = _create(graph)
        context = admission.parse_verification_context_v1(result.context_wire)
        enrollment = parse_enrollment_v2(result.enrollment_wire)
        rows = graph.challenge_rows()
        assert len(rows) == 1 and rows[0]["context_wire"] == result.context_wire
        assert rows[0]["challenge_wire"] == result.enrollment_wire and rows[0]["state"] == "issued"
        assert context.association_id == association_id_v1(result.enrollment_wire, 1, None)
        assert result.expires_at == result.issued_at + 60000
        assert context.challenge_id == enrollment.enrollment_challenge_id == graph.created_ids[0]
        assert result.publication_status == "committed" and result.final_admission == "denied"
        with graph.engine.connect() as connection:
            revision = connection.execute(
                text("SELECT challenge_id,revision FROM social_device_admission_challenge_revisions")
            ).one()
            assert tuple(revision) == (context.challenge_id, 1)
            assert (
                connection.execute(text("SELECT count(*) FROM social_device_ed25519_association_chains")).scalar_one()
                == 0
            )


def test_retry_returns_original_bytes_ids_and_expiry_without_new_entropy(monkeypatch):
    import pytest

    with _graph(monkeypatch) as graph:
        first = _create(graph)
        graph.now += timedelta(seconds=1)
        monkeypatch.setattr(challenge.secrets, "token_hex", lambda size: pytest.fail("retry requested fresh entropy"))
        assert _create(graph) == first
        assert len(graph.created_ids) == len(graph.challenge_rows()) == 1


def test_expired_original_cannot_mint_another_sixty_seconds(monkeypatch):
    import pytest

    with _graph(monkeypatch) as graph:
        first = _create(graph)
        graph.now = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=first.expires_at)
        monkeypatch.setattr(
            challenge.secrets, "token_hex", lambda size: pytest.fail("expired retry requested fresh entropy")
        )
        with pytest.raises(challenge.EnrollmentChallengeUnavailable):
            _create(graph)
        assert len(graph.created_ids) == len(graph.challenge_rows()) == 1
        assert graph.challenge_rows()[0]["challenge_wire"] == first.enrollment_wire


def test_original_native_deadline_caps_the_whole_challenge(monkeypatch):
    with _graph(monkeypatch) as graph:
        graph.now = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=graph.native_expires_at - 400)
        result = _create(graph)
        assert result.expires_at == graph.native_expires_at
        assert result.expires_at - result.issued_at == 400


def test_unrelated_or_corrupted_bearer_and_missing_issuance_never_create_rows(monkeypatch):
    import pytest

    with _graph(monkeypatch) as graph:
        calls = (
            (graph.issuance_id, "malformed"),
            (graph.issuance_id, graph.desktop),
            ("01" * 32, graph.phone_bearer),
        )
        for issuance, bearer in calls:
            with pytest.raises(
                challenge.EnrollmentChallengeUnavailable, match="^social enrollment v2 challenge unavailable$"
            ) as error:
                graph.challenge_service().challenge(issuance, viewer_bearer=bearer)
            assert error.value.__context__ is None
            assert graph.challenge_rows() == [] and graph.created_ids == []


def test_native_expiry_during_table_lock_wait_denies_before_insert(monkeypatch):
    import pytest

    with _graph(monkeypatch) as graph:
        graph.lock_wait = lambda: setattr(
            graph, "now", datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=graph.native_expires_at)
        )
        with pytest.raises(challenge.EnrollmentChallengeUnavailable):
            _create(graph)
        assert graph.challenge_rows() == [] and graph.created_ids == []


def test_missing_native_companion_rolls_back_parent_instead_of_defaulting_revision(monkeypatch):
    import pytest
    from sqlalchemy import text

    with _graph(monkeypatch) as graph:
        graph.produce_revision = False
        with pytest.raises(challenge.EnrollmentChallengeUnavailable):
            _create(graph)
        assert graph.challenge_rows() == []
        with graph.engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT count(*) FROM social_device_admission_challenge_revisions")
                ).scalar_one()
                == 0
            )


def test_expiry_after_insert_rolls_back_both_parent_and_synthetic_companion(monkeypatch):
    import pytest
    from sqlalchemy import text

    with _graph(monkeypatch) as graph:
        graph.after_create = lambda: setattr(graph, "now", graph.now + timedelta(seconds=60))
        with pytest.raises(challenge.EnrollmentChallengeUnavailable):
            _create(graph)
        assert graph.challenge_rows() == []
        with graph.engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT count(*) FROM social_device_admission_challenge_revisions")
                ).scalar_one()
                == 0
            )


def test_expiry_during_commit_delivery_retains_original_without_renewal(monkeypatch):
    import pytest

    with _graph(monkeypatch) as graph:
        base = graph.session_class

        class SlowClose(base):
            def __exit__(self, *args):
                super().__exit__(*args)
                graph.now += timedelta(seconds=60)

        graph.lifecycle._factory = lambda: SlowClose(graph)
        with pytest.raises(challenge.EnrollmentChallengeUnavailable):
            _create(graph)
        assert len(graph.challenge_rows()) == 1
        original = graph.challenge_rows()[0]["challenge_wire"]
        graph.lifecycle._factory = lambda: base(graph)
        with pytest.raises(challenge.EnrollmentChallengeUnavailable):
            _create(graph)
        assert graph.challenge_rows()[0]["challenge_wire"] == original
        assert len(graph.created_ids) == 1


def test_ambiguous_history_is_denied_without_selecting_latest_or_new_entropy(monkeypatch):
    import pytest
    from sqlalchemy import text

    from app.services.social_messaging_device_ed25519_association_lifecycle import association_id_v1

    with _graph(monkeypatch) as graph:
        first = _create(graph)
        context, enrollment = json.loads(first.context_wire), json.loads(first.enrollment_wire)
        context["challengeId"] = enrollment["enrollmentChallengeId"] = "cd" * 32
        enrollment_wire = json.dumps(enrollment, sort_keys=True, separators=(",", ":"))
        context["associationId"] = association_id_v1(enrollment_wire, 1, None)
        context_wire = json.dumps(context, sort_keys=True, separators=(",", ":"))
        with graph.engine.begin() as connection:
            connection.execute(
                text("INSERT INTO social_device_admission_challenges VALUES(:id,:context,:enrollment,NULL,'issued')"),
                {"id": context["challengeId"], "context": context_wire, "enrollment": enrollment_wire},
            )
            connection.execute(
                text("INSERT INTO social_device_admission_challenge_revisions VALUES(:id,1)"),
                {"id": context["challengeId"]},
            )
        monkeypatch.setattr(
            challenge.secrets, "token_hex", lambda size: pytest.fail("ambiguous retry requested fresh entropy")
        )
        with pytest.raises(challenge.EnrollmentChallengeUnavailable):
            _create(graph)
        assert len(graph.challenge_rows()) == 2 and len(graph.created_ids) == 1


def test_original_authentic_phone_vector_crosses_real_reservation_consumer(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from app.services import social_messaging_mobile_pre_enrollment_v2 as v2
    from app.services.social_messaging_device_proof_profile import canonical_enrollment_proof_signing_preimage_v2

    with _graph(monkeypatch) as graph:
        old = v2.parse_preaccepted_enrollment_verification_input_v2(graph.input_wire)
        nonces = iter((old.context.challenge_id, old.context.attempt_id))
        monkeypatch.setattr(challenge.secrets, "token_hex", lambda size: next(nonces))
        result = _create(graph)
        assert result.enrollment_wire == old.enrollment_wire
        # The public fixed vector's existing genuine Ed25519 signature verifies
        # over the newly produced bytes. No participant private key is needed.
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(old.enrollment.ed25519_public_key)).verify(
            bytes.fromhex(old.phone_proof.signature),
            canonical_enrollment_proof_signing_preimage_v2(result.enrollment_wire),
        )
        wire = v2.canonical_preaccepted_enrollment_verification_input_v2_bytes(
            approval_event_wire=result.approval_event_wire,
            context_wire=result.context_wire,
            enrollment_wire=result.enrollment_wire,
            phone_proof_wire=old.phone_proof_wire,
        ).decode("ascii")
        assert wire == graph.input_wire
        with graph.session_class(graph) as session, session.begin():
            reserved = graph.owner(session).reserve(wire, issuance_id=graph.issuance_id)
        assert reserved.final_admission == "denied" and len(graph.rows()) == 1


def test_owner_result_cannot_cross_completed_savepoint_boundary(monkeypatch):
    import pytest

    with _graph(monkeypatch) as graph:
        with graph.session_class(graph) as session, session.begin():
            owner = challenge.NativeV2EnrollmentChallengeOwner(
                session,
                lifecycle=graph.lifecycle,
                config=graph.challenge_config,
                clock=lambda: int(graph.now.timestamp() * 1000),
            )
            result = owner.create(graph.issuance_id, viewer_bearer=graph.phone_bearer)
            with session.begin_nested():
                pass
            with pytest.raises(challenge.EnrollmentChallengeUnavailable):
                owner.check_before_commit(result)
            session.rollback()


def test_configuration_is_server_owned_and_cannot_mismatch_native_backend(monkeypatch):
    import pytest

    with _graph(monkeypatch) as graph:
        for field in ("backend_id", "service_principal"):
            config = replace(graph.challenge_config, **{field: "other"})
            with pytest.raises(challenge.EnrollmentChallengeUnavailable):
                graph.challenge_service(config).challenge(graph.issuance_id, viewer_bearer=graph.phone_bearer)
        assert graph.created_ids == [] and graph.challenge_rows() == []


if __name__ == "__main__":
    unittest.main()
