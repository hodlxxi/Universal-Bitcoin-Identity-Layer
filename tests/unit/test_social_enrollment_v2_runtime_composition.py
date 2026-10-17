"""Transaction-bound publication; native SQL/locking remains a separate proof.

The unittest cases need only the standard library. The pytest functions also
exercise real V2 owners/signatures on the existing isolated SQLite SQL doubles.
"""

import unittest
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
from types import SimpleNamespace

from app.services import social_enrollment_v2_runtime_composition as composition


class MemorySession:
    def __init__(self, *, fail=None, after_commit=None, after_close=None):
        self.fail = fail
        self.after_commit = after_commit
        self.after_close = after_close
        self.events = []
        self.pending = []
        self.durable = []
        self.root = None
        self.new = self.dirty = self.deleted = ()
        self.is_active = True

    def __enter__(self):
        self.events.append("session-enter")
        return self

    def __exit__(self, *args):
        self.events.append("session-close")
        if self.after_close:
            self.after_close()
        if self.fail == "close":
            raise RuntimeError("private close failure")

    def get_transaction(self):
        return self.root

    def get_nested_transaction(self):
        return None

    def get_bind(self):
        return SimpleNamespace()

    def flush(self):
        self.events.append("flush")
        if self.fail == "flush":
            raise RuntimeError("private flush failure")

    @contextmanager
    def begin(self):
        self.events.append("begin")
        if self.fail == "begin":
            raise RuntimeError("private begin failure")
        self.root = object()
        try:
            yield
            if self.fail == "commit":
                raise RuntimeError("private commit failure")
            self.durable.extend(self.pending)
            self.events.append("commit")
            if self.after_commit:
                self.after_commit()
            if self.fail == "uncertain":
                raise RuntimeError("commit persisted but acknowledgment lost")
        except Exception:
            self.events.append("rollback")
            raise
        finally:
            self.root = None
            self.pending.clear()


class TransactionPublicationTests(unittest.TestCase):
    def setUp(self):
        self.at = 100
        self.session = MemorySession()
        self.value = object()
        self.opened = 0
        self.window = (100, 200)

    def factory(self):
        self.opened += 1
        return self.session

    def operation(self, session, now):
        self.assertIs(session, self.session)
        self.assertEqual(now(), self.at)
        session.pending.append("one-effect")

        def before_commit(value):
            self.assertIs(value, self.value)
            self.assertEqual(session.events[-1], "flush")
            self.assertEqual(session.durable, [])
            session.events.append("precommit")
            return self.window

        return self.value, before_commit

    def run_owned(self, operation=None):
        return composition._run_owned(self.factory, lambda: self.at, operation or self.operation)

    def denied(self, operation=None):
        with self.assertRaises(composition.EnrollmentCompositionUnavailable) as caught:
            self.run_owned(operation)
        self.assertEqual(str(caught.exception), composition.DENIED_MESSAGE)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)

    def test_result_follows_flush_check_commit_and_session_close(self):
        self.assertIs(self.run_owned(), self.value)
        self.assertEqual(
            self.session.events, ["session-enter", "begin", "flush", "precommit", "commit", "session-close"]
        )
        self.assertEqual(self.session.durable, ["one-effect"])
        self.assertEqual(self.opened, 1)

    def test_partial_operation_failure_rolls_back(self):
        def failed(session, now):
            session.pending.append("partial")
            raise RuntimeError("sensitive internal failure")

        self.denied(failed)
        self.assertEqual(self.session.durable, [])
        self.assertIn("rollback", self.session.events)

    def test_flush_failure_rolls_back(self):
        self.session.fail = "flush"
        self.denied()
        self.assertEqual(self.session.durable, [])

    def test_precommit_failure_rolls_back(self):
        def failed(session, now):
            def check(value):
                raise RuntimeError("private authority failure after writes")

            session.pending.append("partial")
            return self.value, check

        self.denied(failed)
        self.assertEqual(self.session.durable, [])

    def test_begin_failure_has_no_result(self):
        self.session.fail = "begin"
        self.denied()
        self.assertEqual(self.session.durable, [])

    def test_commit_failure_has_no_result_and_no_retry(self):
        self.session.fail = "commit"
        self.denied()
        self.assertEqual(self.opened, 1)
        self.assertEqual(self.session.durable, [])

    def test_uncertain_commit_has_no_result_and_no_automatic_retry(self):
        self.session.fail = "uncertain"
        self.denied()
        self.assertEqual(self.opened, 1)
        self.assertEqual(self.session.durable, ["one-effect"])

    def test_close_failure_discards_transient_result(self):
        self.session.fail = "close"
        self.denied()
        self.assertEqual(self.session.durable, ["one-effect"])

    def test_last_valid_millisecond_can_publish(self):
        self.at = 199
        self.assertIs(self.run_owned(), self.value)

    def test_exclusive_expiry_before_commit_rolls_back(self):
        self.at = 200
        self.denied()
        self.assertEqual(self.session.durable, [])

    def test_expiry_during_commit_retains_history_but_publishes_no_current_result(self):
        self.session.after_commit = lambda: setattr(self, "at", 200)
        self.denied()
        self.assertEqual(self.session.durable, ["one-effect"])
        self.assertEqual(self.opened, 1)

    def test_expiry_during_session_close_also_prevents_publication(self):
        self.session.after_close = lambda: setattr(self, "at", 200)
        self.denied()
        self.assertEqual(self.session.durable, ["one-effect"])

    def test_historical_receipt_has_no_new_freshness_window(self):
        self.window = None
        self.at = 500000
        self.assertIs(self.run_owned(), self.value)

    def test_clock_before_original_observation_denies(self):
        self.at = 99
        self.denied()
        self.assertEqual(self.session.durable, [])

    def test_clock_regression_denies_even_inside_original_interval(self):
        def operation(session, now):
            value, check = self.operation(session, now)
            self.at = 99
            return value, check

        self.denied(operation)
        self.assertEqual(self.session.durable, [])

    def test_invalid_clock_never_opens_session(self):
        for value in (True, False, -1, 1.0, "100", None, composition._MAX_SAFE_INTEGER + 1):
            with self.subTest(value=value):
                self.at = value
                self.denied()
                self.assertEqual(self.opened, 0)

    def test_invalid_window_denies(self):
        for value in ([100, 200], (100,), (True, 200), (100, False), (100, 100), (200, 100)):
            with self.subTest(value=value):
                self.session = MemorySession()
                self.window = value
                self.denied()
                self.assertEqual(self.session.durable, [])

    def test_existing_root_is_never_adopted(self):
        self.session.root = object()
        self.denied()
        self.assertNotIn("begin", self.session.events)

    def test_external_connection_transaction_is_never_adopted(self):
        self.session.get_bind = lambda: SimpleNamespace(in_transaction=lambda: True)
        self.denied()
        self.assertNotIn("begin", self.session.events)

    def test_dirty_or_unusable_session_denies_before_begin(self):
        for name, value in (
            ("new", (object(),)),
            ("dirty", (object(),)),
            ("deleted", (object(),)),
            ("is_active", False),
        ):
            with self.subTest(name=name):
                self.session = MemorySession()
                setattr(self.session, name, value)
                self.denied()
                self.assertNotIn("begin", self.session.events)

    def test_disabled_builder_loads_no_configuration_or_factory(self):
        self.assertIsNone(composition.build_social_enrollment_v2_composition())
        self.assertIsNone(composition.build_social_enrollment_v2_composition(session_factory=self.factory))
        self.assertEqual(self.opened, 0)
        self.assertIs(composition.RUNTIME_ENABLED, False)
        self.assertIs(composition.DM_TRANSPORT_ENABLED, False)

    def test_only_literal_enable_boolean_is_accepted(self):
        for value in (0, 1, "true", "false", None, (), {}):
            with self.subTest(value=value), self.assertRaises(composition.EnrollmentCompositionUnavailable):
                composition.build_social_enrollment_v2_composition(enabled=value)

    def test_committed_result_cannot_grant_bearer_or_admission(self):
        for result in (
            composition.CommittedReservation("private-wire", "private-id", 100, 200),
            composition.CommittedFinalization("private-receipt", True),
        ):
            self.assertEqual(result.publication_status, "committed")
            self.assertEqual(result.final_admission, "denied")
            self.assertEqual(result.bearer_authority, "none")
            self.assertNotIn("private-", repr(result))
            with self.assertRaises(FrozenInstanceError):
                result.final_admission = "accepted"


class CatalogPolicyPublicationTests(unittest.TestCase):
    def test_policy_is_present_only_inside_original_root_and_removed_before_commit(self):
        from app.services import social_enrollment_v2_catalog_roles as roles
        from tests.unit.test_social_enrollment_v2_catalog_roles import BoundConnection, pin

        class Session(MemorySession):
            def __init__(self):
                super().__init__()
                self.bound = BoundConnection()

            def connection(self):
                return self.bound

            @contextmanager
            def begin(self):
                with super().begin():
                    self.root = SimpleNamespace(is_active=True)
                    yield
                    self.outside = roles.catalog_pin_for(self.bound)

        session = Session()
        value = object()

        def operation(current, now):
            self.assertEqual(roles.catalog_pin_for(current.connection()), pin())

            def check(result):
                self.assertIs(result, value)
                self.assertEqual(roles.catalog_pin_for(current.connection()), pin())
                return (100, 200)

            return value, check

        result = composition._run_owned(lambda: session, lambda: 100, operation, challenge_writer_role=pin())
        self.assertIs(result, value)
        self.assertIsNone(session.outside)
        self.assertIsNone(roles.catalog_pin_for(session.bound))
        self.assertIn("commit", session.events)

    def test_invalid_policy_never_reaches_operation_and_rolls_back(self):
        session = MemorySession()

        def operation(*args):
            self.fail("invalid policy reached business operation")

        with self.assertRaises(composition.EnrollmentCompositionUnavailable):
            composition._run_owned(lambda: session, lambda: 100, operation, challenge_writer_role={"role_oid": 20001})
        self.assertIn("rollback", session.events)
        self.assertNotIn("commit", session.events)


@contextmanager
def _real_graph(monkeypatch):
    from tests.unit.test_social_enrollment_v2_finalization import FinalGraph

    graph = FinalGraph(monkeypatch)
    try:
        yield graph
    finally:
        graph.engine.dispose()


def _real_composition(graph, *, session_factory=None):
    from app.services.social_enrollment_v2_reservation_signer import DedicatedRS256EvidenceSigner
    from tests.unit.test_social_enrollment_v2_finalization import FinalSession

    return composition.build_social_enrollment_v2_composition(
        enabled=True,
        session_factory=session_factory or (lambda: FinalSession(graph)),
        signer=DedicatedRS256EvidenceSigner(private_key=graph.evidence_key, config=graph.config),
        config=graph.final_config,
        clock=lambda: int(graph.now.timestamp() * 1000),
    )


def test_real_reservation_retry_reuses_original_bytes_deadline_and_signature(monkeypatch):
    with _real_graph(monkeypatch) as graph:
        service = _real_composition(graph)
        signed = graph.sign_calls
        first = service.reserve(graph.input_wire, issuance_id=graph.issuance_id)
        graph.now += timedelta(milliseconds=1)
        again = service.reserve(graph.input_wire, issuance_id=graph.issuance_id)
        assert first == again
        assert first.evidence_compact_jws == graph.reservation.evidence_compact_jws
        assert first.expires_at == graph.reservation.expires_at
        assert first.publication_status == "committed"
        assert graph.sign_calls == signed
        assert len(graph.rows()) == 1


def test_real_new_reservation_signs_once_and_commits(monkeypatch):
    from sqlalchemy import delete

    from app.services.social_preaccepted_enrollment_v2_atomic_acceptance_storage import (
        SocialPreacceptedEnrollmentV2AtomicAcceptanceRow,
    )

    with _real_graph(monkeypatch) as graph:
        # Remove the fixture's pending row only in synthetic SQLite so this
        # test starts before reservation. No production code deletes history.
        with graph.engine.begin() as connection:
            connection.execute(delete(SocialPreacceptedEnrollmentV2AtomicAcceptanceRow))
        signed = graph.sign_calls
        result = _real_composition(graph).reserve(graph.input_wire, issuance_id=graph.issuance_id)
        assert graph.sign_calls == signed + 1
        assert result.publication_status == "committed"
        assert len(graph.rows()) == 1
        assert graph.rows()[0]._mapping["state"] == "pending"


def test_real_finalization_commits_then_exact_retry_returns_identical_history(monkeypatch):
    with _real_graph(monkeypatch) as graph:
        service = _real_composition(graph)
        first = service.finalize(**graph.arguments())
        stages = tuple(graph.calls)
        graph.now += timedelta(minutes=5)
        retry = service.finalize(**graph.arguments())
        assert retry.receipt_wire == first.receipt_wire
        assert first.publication_status == retry.publication_status == "committed"
        assert first.historical_recovery is False
        assert retry.historical_recovery is True
        assert tuple(graph.calls) == stages
        assert first.final_admission == retry.final_admission == "denied"


def test_real_expiry_after_flush_rolls_back_actual_shared_effects(monkeypatch):
    import pytest
    from sqlalchemy import text

    from tests.unit.test_social_enrollment_v2_finalization import FinalSession

    with _real_graph(monkeypatch) as graph:

        class SlowFlush(FinalSession):
            def flush(self):
                self.actual.flush()
                graph.now += timedelta(seconds=10)

        service = _real_composition(graph, session_factory=lambda: SlowFlush(graph))
        with pytest.raises(composition.EnrollmentCompositionUnavailable):
            service.finalize(**graph.arguments())
        assert graph.rows()[0]._mapping["state"] == "pending"
        with graph.engine.connect() as connection:
            for table in (
                "social_enrollment_v2_native_effects",
                "social_device_ed25519_association_chains",
                "social_device_ed25519_association_events",
                "social_device_enrollment_admission_receipts",
            ):
                assert connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 0
            state = connection.execute(text("SELECT state FROM social_device_admission_challenges")).scalar_one()
            assert state == "issued"


def test_real_commit_acknowledgment_loss_recovers_without_reexecuting(monkeypatch):
    import pytest

    from tests.unit.test_social_enrollment_v2_finalization import FinalSession

    with _real_graph(monkeypatch) as graph:

        class LostAcknowledgment(FinalSession):
            @contextmanager
            def begin(self):
                with self.actual.begin():
                    yield
                raise RuntimeError("commit acknowledged by database; response lost")

        service = _real_composition(graph, session_factory=lambda: LostAcknowledgment(graph))
        with pytest.raises(composition.EnrollmentCompositionUnavailable):
            service.finalize(**graph.arguments())
        assert graph.rows()[0]._mapping["state"] == "accepted"
        stages = tuple(graph.calls)
        recovered = _real_composition(graph).finalize(**graph.arguments())
        assert recovered.historical_recovery is True
        assert recovered.publication_status == "committed"
        assert tuple(graph.calls) == stages


def test_finalizer_precommit_rejects_copied_result(monkeypatch):
    import pytest

    from app.services.social_enrollment_v2_finalization_contract import FinalizationDenied
    from tests.unit.test_social_enrollment_v2_finalization import FinalSession

    with _real_graph(monkeypatch) as graph:
        with FinalSession(graph) as session, session.begin():
            owner = graph.finalizer(session)
            result = owner.finalize(**graph.arguments())
            with pytest.raises(FinalizationDenied):
                owner.check_before_commit(replace(result))
            session.rollback()


def test_finalizer_precommit_requires_active_original_root(monkeypatch):
    import pytest

    from app.services.social_enrollment_v2_finalization_contract import FinalizationDenied
    from tests.unit.test_social_enrollment_v2_finalization import FinalSession

    with _real_graph(monkeypatch) as graph:
        with FinalSession(graph) as session, session.begin():
            owner = graph.finalizer(session)
            result = owner.finalize(**graph.arguments())
        with pytest.raises(FinalizationDenied):
            owner.check_before_commit(result)


def test_finalizer_precommit_rejects_mutated_historical_flag(monkeypatch):
    import pytest

    from app.services.social_enrollment_v2_finalization_contract import FinalizationDenied
    from tests.unit.test_social_enrollment_v2_finalization import FinalSession

    with _real_graph(monkeypatch) as graph:
        with FinalSession(graph) as session, session.begin():
            owner = graph.finalizer(session)
            result = owner.finalize(**graph.arguments())
            object.__setattr__(result, "historical_recovery", True)
            with pytest.raises(FinalizationDenied):
                owner.check_before_commit(result)
            session.rollback()


def test_finalizer_precommit_window_is_original_statement_expiry(monkeypatch):
    from tests.unit.test_social_enrollment_v2_finalization import FinalSession

    with _real_graph(monkeypatch) as graph:
        with FinalSession(graph) as session, session.begin():
            owner = graph.finalizer(session)
            result = owner.finalize(**graph.arguments())
            observed, expiry = owner.check_before_commit(result)
            assert observed == int(graph.now.timestamp() * 1000)
            assert expiry == graph.reservation.expires_at


def test_finalizer_publication_uses_shorter_statement_not_reservation_deadline(monkeypatch):
    from tests.unit.test_social_enrollment_v2_finalization import FinalSession, signed_statement

    with _real_graph(monkeypatch) as graph:
        at = int(graph.now.timestamp() * 1000)
        graph.final_config, graph.statement = signed_statement(graph.input_wire, graph.config, at, expires_at=at + 5000)
        with FinalSession(graph) as session, session.begin():
            owner = graph.finalizer(session)
            result = owner.finalize(**graph.arguments())
            _, expiry = owner.check_before_commit(result)
            assert expiry == at + 5000
            assert expiry < graph.reservation.expires_at


if __name__ == "__main__":
    unittest.main()
