"""Native graph, real guarded transaction checks; offline catalog doubles only."""

import json
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.models import CurrentEntitlementEvidence, OAuthBrowserGeneration, OAuthClient, OAuthToken, Session, User
from app.services import social_device_ed25519_association_storage as association
from app.services import social_messaging_device_ed25519_association_lifecycle as lifecycle
from app.services.social_enrollment_v2_reservation_contract import ReservationDenied
from app.services.social_messaging_device_storage import SocialMessagingDeviceBindingRow
from app.services.social_session_issuance_v2_storage import V2Acceptance, V2Issuance, V2Parent
from tests.unit.test_social_enrollment_v2_reservation import ReservationSession, reservation_graph
from tests.unit.test_social_session_issuance_v2_storage import NOW


@pytest.mark.parametrize("change", ["xid", "physical", "connection", "root", "savepoint", "dirty", "reconnect", "bind"])
def test_guard_denies_aba_replacement_and_poisoned_owner(reservation_graph, change):
    g = reservation_graph
    with ReservationSession(g) as s:
        tx = s.begin()
        owner = g.owner(s)
        candidate = owner.authority.prepare(g.input_wire, g.issuance_id)
        c = s.connection()
        if change == "xid":
            c.xid = "43"
        elif change == "physical":
            c.connection.dbapi_connection = SimpleNamespace(autocommit=False)
        elif change == "connection":
            s.pinned = None
        elif change == "root":
            tx.rollback()
            tx = s.begin()
        elif change == "savepoint":
            nested = s.begin_nested()
            nested.rollback()
            s.begin_nested()
        elif change == "dirty":
            user = s.actual.execute(select(User)).scalar_one()
            user.is_active = False
        elif change == "reconnect":
            c.invalidated = True
        elif change == "bind":
            s.get_bind = lambda: SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))
        with pytest.raises(ReservationDenied):
            owner.signer.sign(candidate, owner=owner.authority)
        assert owner.authority.failed and owner.authority.guard.poisoned
        # Restoring an ABA identity never revives the poisoned capability.
        c.xid = "42"
        c.invalidated = False
        with pytest.raises(ReservationDenied):
            owner.signer.sign(candidate, owner=owner.authority)
        tx.rollback()


def test_supported_preexisting_savepoint_then_rollback_denies(reservation_graph):
    g = reservation_graph
    with ReservationSession(g) as s, s.begin():
        nested = s.begin_nested()
        owner = g.owner(s)
        candidate = owner.authority.prepare(g.input_wire, g.issuance_id)
        nested.rollback()
        with pytest.raises(ReservationDenied):
            owner.signer.sign(candidate, owner=owner.authority)


@pytest.mark.parametrize(
    "model,values",
    [
        (OAuthToken, dict(is_revoked=True)),
        (User, dict(is_active=False)),
        (OAuthBrowserGeneration, dict(is_active=False)),
        (OAuthClient, dict(is_active=False)),
        (Session, dict(is_active=False)),
        (CurrentEntitlementEvidence, dict(revoked_at=(NOW - timedelta(seconds=5)).replace(tzinfo=None))),
        (CurrentEntitlementEvidence, dict(source_evidence_sha256="ee" * 32)),
        (SocialMessagingDeviceBindingRow, dict(active=False, retired_at=NOW.replace(tzinfo=None))),
        (SocialMessagingDeviceBindingRow, dict(public_key="42" * 32)),
        (V2Issuance, dict(revision="ee" * 32)),
        (V2Parent, dict(browser_id="ee" * 32)),
        (V2Acceptance, dict(approval_id="ee" * 32)),
    ],
)
def test_missing_stale_revoked_rotated_and_replaced_native_graph_deny(reservation_graph, model, values):
    g = reservation_graph
    with ReservationSession(g) as s, s.begin():
        owner = g.owner(s)
        cached = s.actual.execute(select(model)).scalars().first()
        owner.authority.prepare(g.input_wire, g.issuance_id)
        s.connection().actual.execute(model.__table__.update().values(**values))
        with pytest.raises(ReservationDenied):
            owner.reserve(g.input_wire, issuance_id=g.issuance_id)
        assert owner.failed and owner.authority.guard.poisoned
        assert g.sign_calls == 0


@pytest.mark.parametrize(
    "failure",
    [
        "missing_revision",
        "wrong_revision",
        "bool_revision",
        "challenge_state",
        "challenge_bytes",
        "history",
        "ambiguous_history",
    ],
)
def test_native_challenge_and_complete_history_are_required(reservation_graph, failure):
    from app.services.social_device_challenge_store import SocialDeviceAdmissionChallengeRow

    g = reservation_graph
    with ReservationSession(g) as s, s.begin():
        owner = g.owner(s)
        if failure == "missing_revision":
            g.revision_catalog.companion = []
        elif failure in ("wrong_revision", "bool_revision"):
            g.revision_catalog.companion[0]["revision"] = 2 if failure == "wrong_revision" else True
        elif failure == "challenge_state":
            s.connection().actual.execute(
                SocialDeviceAdmissionChallengeRow.__table__.update().values(state="cancelled")
            )
        elif failure == "challenge_bytes":
            row = json.loads(g.revision_catalog.row["context_wire"])
            row["attemptId"] = "ee" * 32
            s.connection().actual.execute(
                SocialDeviceAdmissionChallengeRow.__table__.update().values(
                    context_wire=json.dumps(row, sort_keys=True, separators=(",", ":"))
                )
            )
        else:
            p = json.loads(json.loads(g.input_wire)["enrollment"])
            s.connection().actual.execute(
                association.SocialDeviceEd25519AssociationChain.__table__.insert().values(
                    subject=p["subject"],
                    device_id=p["deviceId"],
                    authority_epoch=2,
                    last_association_id="aa" * 32,
                    last_association_version=1,
                    current_association_id=None,
                    state="revoked",
                )
            )
            # A revoked chain with absent event/current is NOT absent history;
            # the REAL history replayer rejects this damaged/ambiguous chain.
        with pytest.raises(ReservationDenied):
            owner.reserve(g.input_wire, issuance_id=g.issuance_id)
        assert owner.failed and g.sign_calls == 0


def test_actual_combined_lock_order_and_guarded_binding_refresh(reservation_graph):
    g = reservation_graph
    with ReservationSession(g) as s, s.begin():
        owner = g.owner(s)
        g.events.clear()
        statements = []
        original = s.execute

        def routed(statement, **kwargs):
            statements.append(str(statement))
            assert kwargs["bind_arguments"]["bind"] is owner.authority.guard.connection
            return original(statement, **kwargs)

        s.execute = routed
        owner.reserve(g.input_wire, issuance_id=g.issuance_id)
        assert g.events.index(next(sql for sql in g.events if sql.startswith("LOCK TABLE"))) < g.events.index(
            next(sql for sql in g.events if "pg_advisory_xact_lock" in sql)
        )
        binding_sql = next(sql for sql in statements if "FROM social_messaging_device_bindings" in sql)
        assert "FOR UPDATE" in binding_sql
        first_challenge = next(i for i, sql in enumerate(g.events) if "FROM social_device_admission_challenges" in sql)
        first_history = next(
            i for i, sql in enumerate(g.events) if "FROM social_device_ed25519_association_chains" in sql
        )
        assert first_challenge < first_history


def test_real_revoked_history_without_current_association_denies(reservation_graph):
    from app.services import social_messaging_device_proof_profile as profile

    g = reservation_graph
    wire = json.loads(g.input_wire)["enrollment"]
    e = profile.parse_enrollment_v2(wire)
    state = lifecycle.initial_association_v1(lifecycle.AssociationLifecycleV1(()), wire)
    current = lifecycle.association_snapshot_v1(state).current
    state = lifecycle.revoke_association_v1(
        state, expected_association_id=current.association_id, expected_authority_epoch=1
    )
    assert lifecycle.association_snapshot_v1(state).current is None
    with ReservationSession(g) as s, s.begin():
        c = s.connection().actual
        c.execute(
            association.SocialDeviceEd25519AssociationChain.__table__.insert().values(
                subject=e.subject,
                device_id=e.device_id,
                authority_epoch=2,
                last_association_id=current.association_id,
                last_association_version=1,
                current_association_id=None,
                state="revoked",
            )
        )
        for event in state.events:
            enrolled = event.enrollment_wire is not None
            c.execute(
                association.SocialDeviceEd25519AssociationEvent.__table__.insert().values(
                    subject=e.subject,
                    device_id=e.device_id,
                    authority_epoch=event.authority_epoch,
                    kind=event.kind,
                    association_id=event.association_id,
                    association_version=event.association_version,
                    predecessor_association_id=event.predecessor_association_id,
                    ed25519_public_key=e.ed25519_public_key if enrolled else None,
                    enrollment_challenge_id=e.enrollment_challenge_id if enrolled else None,
                    event_wire=lifecycle.canonical_association_event_v1_bytes(event),
                )
            )
        owner = g.owner(s)
        with pytest.raises(ReservationDenied):
            owner.reserve(g.input_wire, issuance_id=g.issuance_id)
        assert owner.failed and g.sign_calls == 0


def test_absent_caller_root_never_autobegins_or_acquires_connection(reservation_graph):
    g = reservation_graph
    with ReservationSession(g) as s:
        assert not s.in_transaction() and s.pinned is None
        with pytest.raises(ReservationDenied):
            g.owner(s)
        assert not s.in_transaction() and s.pinned is None


@pytest.mark.parametrize("relation", range(3))
@pytest.mark.parametrize("unsafe", ["row_security", "force_row_security", "runtime_owns_or_inherits"])
def test_history_visibility_and_owner_privileges_deny_before_signing(reservation_graph, relation, unsafe):
    g = reservation_graph
    # No business row needs to be visible to demonstrate the catalog gap.
    # The same native lookup must reject filtering/DDL authority before it
    # interprets an empty history SELECT as a complete absence proof.
    g.history_security = {relation: {unsafe: True}}
    with ReservationSession(g) as s, s.begin():
        owner = g.owner(s)
        with pytest.raises(ReservationDenied):
            owner.reserve(g.input_wire, issuance_id=g.issuance_id)
        assert owner.failed and owner.authority.guard.poisoned
        assert g.sign_calls == 0
    assert not g.rows()
