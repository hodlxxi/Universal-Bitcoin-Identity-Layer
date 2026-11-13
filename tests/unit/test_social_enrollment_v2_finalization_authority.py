"""Locked provenance and registry/continuity failures with constrained doubles."""

from datetime import timedelta

import pytest
from sqlalchemy import text

from app.services import social_enrollment_v2_finalization_authority as authority
from app.services import social_preaccepted_enrollment_verification_statement_v2 as statement
from app.services.social_enrollment_v2_finalization_contract import FinalizationDenied
from tests.unit.test_social_enrollment_v2_finalization import FinalSession, final_graph


def prepare(g, owner):
    a = owner.authority
    args = g.arguments()
    stored = a.discover_finalization(args["reservation_id"], 1, g.input_wire, args["evidence_compact_jws"], g.statement)
    return a.prepare_finalization(stored, g.statement, g.issuance_id)


@pytest.mark.parametrize("forgery", ["detached", "cross_owner", "public_mutation"])
def test_registry_bound_plan_denies_forgery_before_native_dml(final_graph, forgery):
    g = final_graph
    with FinalSession(g) as s, s.begin():
        first = g.finalizer(s)
        second = g.finalizer(s)
        plan = prepare(g, first)
        with pytest.raises((FinalizationDenied, AttributeError)):
            if forgery == "detached":
                first.effects.execute(object.__new__(authority.LockedFinalizationPlan))
            elif forgery == "cross_owner":
                second.effects.execute(plan)
            else:
                object.__setattr__(plan, "facts", {"accepted": True})
        assert not g.calls


@pytest.mark.parametrize("change", ["root_xid", "savepoint", "inactive_savepoint"])
def test_transaction_aba_poison_until_caller_rollback(final_graph, change):
    g = final_graph
    with FinalSession(g) as s:
        root = s.begin()
        owner = g.finalizer(s)
        original_xid = s.connection().xid
        if change == "root_xid":
            s.connection().xid = str(int(original_xid) + 1)
        else:
            nested = s.begin_nested()
            if change == "inactive_savepoint":
                nested.rollback()
                # Original None has returned; the new owner observes events.
        with pytest.raises(FinalizationDenied):
            owner.finalize(**g.arguments())
        if change == "root_xid":
            s.connection().xid = original_xid
        with pytest.raises(FinalizationDenied):
            g.finalizer(s)
        root.rollback()
    assert not g.calls


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE current_entitlement_evidence SET source_evidence_sha256='" + "f" * 64 + "'",
        "UPDATE oauth_tokens SET is_revoked=1",
        "UPDATE social_messaging_device_bindings SET active=0,retired_at=expires_at",
    ],
)
def test_changed_live_native_provenance_is_not_rescued_by_frozen_evidence(final_graph, sql):
    g = final_graph
    with g.engine.begin() as c:
        c.execute(text(sql))
    with FinalSession(g) as s, s.begin():
        with pytest.raises(FinalizationDenied):
            g.finalizer(s).finalize(**g.arguments())
    assert not g.calls


def test_completed_wait_crossing_exact_exclusive_expiry_denies(final_graph):
    g = final_graph
    g.wait = lambda: setattr(g, "now", g.now + timedelta(seconds=10))
    with FinalSession(g) as s, s.begin():
        with pytest.raises(FinalizationDenied):
            g.finalizer(s).finalize(**g.arguments())
    assert not g.calls


def test_slow_real_signature_verification_resamples_before_native_effect(final_graph, monkeypatch):
    g = final_graph
    real = statement.verify_social_preaccepted_enrollment_verification_statement_v2

    def slow(*args, **kwargs):
        result = real(*args, **kwargs)
        g.now += timedelta(seconds=10)
        return result

    monkeypatch.setattr(statement, "verify_social_preaccepted_enrollment_verification_statement_v2", slow)
    with FinalSession(g) as s, s.begin():
        with pytest.raises(FinalizationDenied):
            g.finalizer(s).finalize(**g.arguments())
    assert not g.calls


def test_completed_savepoint_aba_is_observed_even_after_original_none_returns(final_graph):
    g = final_graph
    with FinalSession(g) as s, s.begin():
        owner = g.finalizer(s)
        nested = s.begin_nested()
        nested.rollback()
        assert s.get_nested_transaction() is None
        with pytest.raises(FinalizationDenied):
            owner.finalize(**g.arguments())
    assert not g.calls


def test_model_output_inside_registered_plan_is_an_immutable_primitive_snapshot(final_graph):
    g = final_graph
    with FinalSession(g) as s, s.begin():
        owner = g.finalizer(s)
        candidate = prepare(g, owner)
        record = owner.authority.resolve(candidate)
        with pytest.raises(AttributeError):
            object.__setattr__(
                record.canonical_plan.observation, "observed_at", record.canonical_plan.observation.observed_at + 1
            )
        with pytest.raises(AttributeError):
            object.__setattr__(record.stored.reservation, "expires_at", record.stored.reservation.expires_at + 1)
        assert g.input_wire not in repr(record.stored)
    assert not g.calls


def test_discovered_dataclass_mutation_cannot_rewrite_authority(final_graph):
    g = final_graph
    with FinalSession(g) as s, s.begin():
        owner = g.finalizer(s)
        a = owner.authority
        stored = a.discover_finalization(
            g.reservation.reservation_id, 1, g.input_wire, g.reservation.evidence_compact_jws, g.statement
        )
        object.__setattr__(stored.reservation, "reservation_revision", True)
        with pytest.raises(FinalizationDenied):
            a.prepare_finalization(stored, g.statement, g.issuance_id)
    assert not g.calls


def test_mapper_bind_routing_is_denied_before_effect(final_graph):
    from sqlalchemy import create_engine

    from app.models import User

    g = final_graph
    other = create_engine("sqlite:///:memory:")
    try:
        with FinalSession(g) as s, s.begin():
            owner = g.finalizer(s)
            s.actual.bind_mapper(User, other)
            with pytest.raises(FinalizationDenied):
                owner.finalize(**g.arguments())
        assert not g.calls
    finally:
        other.dispose()
