from dataclasses import FrozenInstanceError
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select, update

from app.models import CurrentEntitlementEvidence, OAuthBrowserGeneration, OAuthClient, OAuthToken, Session, User
from app.services.social_messaging_device_storage import SocialMessagingDeviceBindingRow
from app.services.social_session_issuance_v2_authority import LockedV2Authority, validated_facts
from app.services.social_session_issuance_v2_contract import V2IssuanceUnavailable
from app.services.social_session_issuance_v2_storage import V2Issuance, V2Parent
from tests.unit.test_social_session_issuance_v2_storage import NOW, VECTOR, SessionDouble, graph


def test_reader_is_internal_immutable_and_transaction_bound(graph):
    graph.create()
    delivered = graph.issue()
    with SessionDouble(graph) as s, s.begin():
        r = graph.reader(s)
        result = r.read(delivered["receipt"]["issuanceId"])
        facts = validated_facts(result, r)
        assert result.provisional_until_caller_commit is True
        with pytest.raises(AttributeError):
            facts.revision = "0" * 64
        with pytest.raises(AttributeError):
            object.__setattr__(facts, "revision", "0" * 64)
        with pytest.raises(V2IssuanceUnavailable):
            LockedV2Authority()
        with pytest.raises(V2IssuanceUnavailable):
            validated_facts(object.__new__(LockedV2Authority), r)
        with pytest.raises(V2IssuanceUnavailable):
            validated_facts(SimpleNamespace(facts=facts), r)
    with pytest.raises(V2IssuanceUnavailable):
        result.facts


def test_stale_cached_owner_is_refreshed_and_denied(graph):
    graph.create()
    delivered = graph.issue()
    with SessionDouble(graph) as s, s.begin():
        cached = s.actual.execute(select(User)).scalar_one()
        assert cached.is_active is True
        r = graph.reader(s)
        assert r.read(delivered["receipt"]["issuanceId"]).facts.subject == cached.pubkey
        s.connection().actual.execute(User.__table__.update().values(is_active=False))
        assert cached.is_active is True
        with pytest.raises(V2IssuanceUnavailable):
            r.read(delivered["receipt"]["issuanceId"])
        assert cached.is_active is False


def test_exact_owner_invalidation_graph_fails_at_targeted_check(graph):
    graph.create()
    delivered = graph.issue()
    # Each case begins from this same known-good complete committed graph;
    # synthetic rollback restores it without pretending native trigger coverage.
    cases = (
        (OAuthToken, dict(is_revoked=True)),
        (Session, dict(is_active=False)),
        (OAuthBrowserGeneration, dict(is_active=False)),
        (OAuthClient, dict(is_active=False)),
        (SocialMessagingDeviceBindingRow, dict(active=False, retired_at=NOW.replace(tzinfo=None))),
    )
    for model, values in cases:
        with SessionDouble(graph) as s:
            transaction = s.begin()
            r = graph.reader(s)
            assert r.read(delivered["receipt"]["issuanceId"]).facts.operation_id == "99" * 32
            s.connection().actual.execute(model.__table__.update().values(**values))
            with pytest.raises(V2IssuanceUnavailable):
                r.read(delivered["receipt"]["issuanceId"])
            transaction.rollback()


def test_missing_native_parent_and_revision_cannot_be_reconstructed(graph):
    graph.create()
    delivered = graph.issue()
    for model, statement in (
        (V2Parent, V2Parent.__table__.delete()),
        (V2Issuance, V2Issuance.__table__.update().values(revision="0" * 64)),
    ):
        with SessionDouble(graph) as s:
            transaction = s.begin()
            r = graph.reader(s)
            assert r.read(delivered["receipt"]["issuanceId"]).facts.revision
            s.connection().actual.execute(statement)
            with pytest.raises(V2IssuanceUnavailable):
                r.read(delivered["receipt"]["issuanceId"])
            transaction.rollback()


def test_resamples_after_synthetic_wait_success_and_crossing_expiry(graph):
    graph.create()
    delivered = graph.issue()
    with SessionDouble(graph) as s, s.begin():
        r = graph.reader(s)
        graph.after_wait = lambda: setattr(graph, "now", NOW + timedelta(seconds=2))
        result = r.read(delivered["receipt"]["issuanceId"])
        assert result.facts.observed_at_ms == int(graph.now.timestamp()) * 1000
        graph.after_wait = lambda: setattr(graph, "now", NOW + timedelta(seconds=300))
        with pytest.raises(V2IssuanceUnavailable):
            r.read(delivered["receipt"]["issuanceId"])


def test_valid_graph_denies_backend_and_physical_swap_during_lock_work(graph):
    graph.create()
    delivered = graph.issue()
    for field in ("xid", "physical"):
        with SessionDouble(graph) as s, s.begin():
            r = graph.reader(s)
            assert r.read(delivered["receipt"]["issuanceId"]).facts.token_id

            def swap():
                if field == "xid":
                    s.connection().xid = "43"
                else:
                    s.connection().connection.dbapi_connection = SimpleNamespace(autocommit=False)

            graph.after_wait = swap
            with pytest.raises(V2IssuanceUnavailable):
                r.read(delivered["receipt"]["issuanceId"])


def test_provenance_uses_prevalidation_snapshot_not_later_cached_orm_fields(graph, monkeypatch):
    from sqlalchemy.orm.attributes import set_committed_value

    graph.create()
    delivery = graph.issue()
    with SessionDouble(graph) as s, s.begin():
        r = graph.reader(s)
        cached = s.actual.execute(select(V2Issuance)).scalar_one()
        original = cached.revision
        check = r._check
        calls = 0

        def change_cached_after_validation():
            nonlocal calls
            check()
            calls += 1
            if calls >= 2:
                set_committed_value(cached, "revision", "ee" * 32)

        monkeypatch.setattr(r, "_check", change_cached_after_validation)
        facts = r.read(delivery["receipt"]["issuanceId"]).facts
        assert cached.revision == "ee" * 32
        assert facts.revision == original


def test_provisional_facts_expire_inside_the_original_transaction(graph):
    with SessionDouble(graph) as s, s.begin():
        s.actual.execute(
            update(CurrentEntitlementEvidence).values(valid_until=(NOW + timedelta(seconds=3)).replace(tzinfo=None))
        )
    graph.create()
    delivered = graph.issue()
    with SessionDouble(graph) as s, s.begin():
        r = graph.reader(s)
        result = r.read(delivered["receipt"]["issuanceId"])
        original = result.facts
        assert original.full_expires_at_ms < original.phone_expires_at_ms
        graph.now = NOW + timedelta(milliseconds=original.full_expires_at_ms - int(NOW.timestamp()) * 1000)
        with pytest.raises(V2IssuanceUnavailable):
            result.facts


def test_preexisting_savepoint_pins_success_then_fails_after_rollback(graph):
    graph.create()
    delivered = graph.issue()
    with SessionDouble(graph) as s, s.begin():
        nested = s.begin_nested()
        r = graph.reader(s)
        result = r.read(delivered["receipt"]["issuanceId"])
        assert result.facts.issuer == "https://ubid.example"
        assert result.facts.backend_id == "backend"
        with pytest.raises(V2IssuanceUnavailable):
            validated_facts(result, graph.reader(s))
        assert result.facts.token_id
        nested.rollback()
        with pytest.raises(V2IssuanceUnavailable):
            result.facts


def test_exact_original_context_and_binding_key_mismatch_deny_complete_graph(graph):
    from app.services.social_session_issuance_v2_authority import NativeV2AuthorityReader

    graph.create()
    delivered = graph.issue()
    with SessionDouble(graph) as s, s.begin():
        assert graph.reader(s).read(delivered["receipt"]["issuanceId"]).facts.binding_id
        changed = NativeV2AuthorityReader(
            s,
            client_id="social-client",
            backend_id="backend",
            principal="other",
            issuer="https://ubid.example",
            clock=lambda: graph.now,
        )
        with pytest.raises(V2IssuanceUnavailable):
            changed.read(delivered["receipt"]["issuanceId"])
    with SessionDouble(graph) as s, s.begin():
        assert graph.reader(s).read(delivered["receipt"]["issuanceId"]).facts.binding_id
        s.connection().actual.execute(SocialMessagingDeviceBindingRow.__table__.update().values(public_key="42" * 32))
        with pytest.raises(V2IssuanceUnavailable):
            graph.reader(s).read(delivered["receipt"]["issuanceId"])


@pytest.mark.parametrize("outcome", ["live", "expired", "retired"])
def test_exact_binding_lock_refreshes_after_owner_locks_and_resamples_time(graph, monkeypatch, outcome):
    graph.create()
    delivered = graph.issue()
    with SessionDouble(graph) as s, s.begin():
        cached = s.actual.execute(select(SocialMessagingDeviceBindingRow)).scalar_one()
        binding_id = cached.binding_id
        reader = graph.reader(s)
        original_execute = s.execute
        events = []

        def routed_execute(statement, **kwargs):
            sql = str(statement)
            if "FROM social_messaging_device_bindings" in sql:
                # This is the real old primitive, not a replacement binding port.
                assert "FOR UPDATE" in sql
                assert statement.compile().params["binding_id_1"] == binding_id
                assert any("FROM sessions" in event and "FOR UPDATE" in event for event in events)
                assert kwargs["bind_arguments"] == {"bind": reader.guard.connection}
                assert statement.get_execution_options()["populate_existing"] is True
                if outcome == "retired":
                    s.connection().actual.execute(
                        SocialMessagingDeviceBindingRow.__table__.update().values(
                            active=False, retired_at=NOW.replace(tzinfo=None)
                        )
                    )
                    assert cached.active is True  # Deliberately stale identity map.
                graph.now = NOW + timedelta(seconds=300 if outcome == "expired" else 2)
                events.append("binding wait completed (synthetic)")
            events.append(sql)
            return original_execute(statement, **kwargs)

        def observed_clock():
            events.append("clock")
            return graph.now

        monkeypatch.setattr(s, "execute", routed_execute)
        reader.clock = observed_clock
        if outcome == "live":
            facts = reader.read(delivered["receipt"]["issuanceId"]).facts
            assert facts.binding_id == binding_id
            assert facts.observed_at_ms == int(graph.now.timestamp()) * 1000
        else:
            with pytest.raises(V2IssuanceUnavailable):
                reader.read(delivered["receipt"]["issuanceId"])
            assert reader.failed and reader.guard.poisoned
        completed = events.index("binding wait completed (synthetic)")
        if outcome == "retired":
            assert cached.active is False
        else:
            assert "clock" in events[completed + 1 :]
