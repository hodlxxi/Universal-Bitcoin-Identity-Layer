from dataclasses import replace
import inspect
from pathlib import Path

import pytest

from app.services.canonical_admission_edge import AdmissionEdgeLifecycle
from app.services.canonical_genesis_record import parse_canonical_genesis_record
from app.services.legacy_covenant_canonical_migration_planner import (
    CanonicalReadSnapshot,
    InvalidMigrationPlannerInput,
    LegacyCovenantCanonicalMigrationPlanner,
    LegacyWalletObservation,
    LegacyWalletOutpoint,
    MigrationDecision,
    native_p2wsh_script_pubkey,
)
from app.services.trusted_covenant_registration import (
    TrustedCovenantRegistrationLifecycle,
)
from tests.unit.test_canonical_admission_edge import (
    CHILD,
    edge,
    genesis,
    registration,
)


def _snapshot(admission_edges, registrations, *, users=()):
    root = parse_canonical_genesis_record(Path("docs/data/e923_canonical_genesis_record_v1.json").read_bytes())
    return CanonicalReadSnapshot.from_canonical_records(
        genesis_records=(root,),
        evaluated_at=genesis().evaluated_at,
        admission_edges=tuple(admission_edges),
        registrations=tuple(registrations),
        browser_user_xonly_keys=users,
    )


def _observed_wallet(value):
    scripts = (
        value.mirrored_pair.earlier_leg.raw_script_hex,
        value.mirrored_pair.later_leg.raw_script_hex,
    )
    amount = value.outpoints[0].amount_sats
    return LegacyWalletObservation(
        "ordinary-observation-wallet",
        tuple(f"wsh(raw({script}))#checksum" for script in scripts),
        (
            LegacyWalletOutpoint(
                "a" * 64,
                0,
                amount,
                6,
                native_p2wsh_script_pubkey(scripts[0]),
            ),
            LegacyWalletOutpoint(
                "b" * 64,
                1,
                amount,
                6,
                native_p2wsh_script_pubkey(scripts[1]),
            ),
        ),
    )


def _decision(snapshot, value):
    plan = LegacyCovenantCanonicalMigrationPlanner().plan(
        (_observed_wallet(value),),
        snapshot,
    )
    assert len(plan.relationships) == 1
    return plan.relationships[0]


def test_effective_source_validated_admission_is_already_canonical():
    value = registration()
    admission = edge(value, lifecycle=AdmissionEdgeLifecycle.EFFECTIVE)
    snapshot = _snapshot((admission,), (value,))
    result = _decision(snapshot, value)
    assert result.decision is MigrationDecision.ALREADY_CANONICAL
    assert dict(snapshot.reachable_depths)[CHILD[2:]] == 1


@pytest.mark.parametrize(
    "lifecycle",
    (
        AdmissionEdgeLifecycle.PROPOSED,
        AdmissionEdgeLifecycle.DISPUTED,
        AdmissionEdgeLifecycle.SUPERSEDED,
        AdmissionEdgeLifecycle.REVOKED,
    ),
)
def test_historical_admission_edge_with_active_registration_is_not_current_authority(
    lifecycle,
):
    value = registration()
    admission = edge(value, lifecycle=lifecycle)
    snapshot = _snapshot((admission,), (value,))
    result = _decision(snapshot, value)
    assert result.decision is MigrationDecision.CANONICAL_CONFLICT
    assert result.decision is not MigrationDecision.ALREADY_CANONICAL
    assert "historical_admission_edge_not_current_authority" in result.reasons
    assert "active_registration_without_effective_admission" in result.reasons
    assert CHILD[2:] not in dict(snapshot.reachable_depths)


def test_active_registration_without_any_effective_admission_fails_closed():
    value = registration()
    result = _decision(_snapshot((), (value,)), value)
    assert result.decision is MigrationDecision.CANONICAL_CONFLICT
    assert result.reasons == ("active_registration_without_effective_admission",)


def test_effective_edge_still_requires_exact_active_registration_source():
    value = registration()
    admission = edge(value, lifecycle=AdmissionEdgeLifecycle.EFFECTIVE)
    with pytest.raises(InvalidMigrationPlannerInput):
        _snapshot((admission,), ())
    inactive = registration(state=TrustedCovenantRegistrationLifecycle.REVOKED)
    with pytest.raises(InvalidMigrationPlannerInput):
        _snapshot((admission,), (inactive,))


def test_multiple_effective_admissions_for_one_child_fail_closed():
    value = registration()
    first = edge(value, lifecycle=AdmissionEdgeLifecycle.EFFECTIVE)
    second = replace(
        first,
        edge_id="00000000-0000-4000-8000-000000000029",
    )
    with pytest.raises(InvalidMigrationPlannerInput):
        _snapshot((first, second), (value,))


def test_browser_user_does_not_convert_historical_edge_to_current_authority():
    value = registration()
    admission = edge(value, lifecycle=AdmissionEdgeLifecycle.REVOKED)
    without_user = _decision(_snapshot((admission,), (value,)), value)
    with_user = _decision(
        _snapshot((admission,), (value,), users=(CHILD[2:],)),
        value,
    )
    assert without_user.decision is with_user.decision is MigrationDecision.CANONICAL_CONFLICT
    assert without_user.reasons == with_user.reasons


def test_no_balance_ratio_authority_is_introduced():
    source = inspect.getsource(LegacyCovenantCanonicalMigrationPlanner)
    assert "get_save_and_check_balances_for_pubkey" not in source
    assert "balance_ratio" not in source
    assert "access_level" not in source
