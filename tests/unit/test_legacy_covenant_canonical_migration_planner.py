from hashlib import sha256
import inspect
import json

import pytest

from app.services.canonical_admission_edge import GENESIS_COMPRESSED_KEY, GENESIS_XONLY_KEY
from app.services.legacy_covenant_canonical_migration_planner import (
    CanonicalKnownRelationship,
    CanonicalReadSnapshot,
    InvalidMigrationPlannerInput,
    LegacyCovenantCanonicalMigrationPlanner,
    LegacyRelationshipClass,
    LegacyWalletObservation,
    LegacyWalletOutpoint,
    MigrationDecision,
    native_p2wsh_script_pubkey,
)
import scripts.legacy_covenant_canonical_migration_plan as cli
from scripts.legacy_covenant_canonical_migration_plan import parse_args

CHILD = "032f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8c"
OTHER = "02019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92"
ROOT = GENESIS_COMPRESSED_KEY
EARLY, MIDDLE, LATE = 1777000, 1777777, 1778554


def _num(value):
    data = bytearray()
    while value:
        data.append(value & 255)
        value >>= 8
    if data[-1] & 128:
        data.append(0)
    return bytes((len(data),)) + bytes(data)


def _push(key):
    raw = bytes.fromhex(key)
    return bytes((len(raw),)) + raw


def _leg(receiver, sender, receiver_height, sender_height):
    return (
        b"\x63"
        + _num(receiver_height)
        + b"\xb1\x75"
        + _push(receiver)
        + b"\xac\x67"
        + _num(sender_height)
        + b"\xb1\x75"
        + _push(sender)
        + b"\xac\x68"
    ).hex()


def _cooperative(receiver, sender, receiver_height, sender_height):
    first, second = sorted((receiver, sender))
    return (
        b"\x63\x52"
        + _push(first)
        + _push(second)
        + b"\x52\xae\x67\x63"
        + _num(receiver_height)
        + b"\xb1\x75"
        + _push(receiver)
        + b"\xac\x67"
        + _num(sender_height)
        + b"\xb1\x75"
        + _push(sender)
        + b"\xac\x68\x68"
    ).hex()


def _pair(delta=777, *, same_window=False, cooperative=False, sponsor=ROOT, child=CHILD, heights=None):
    if heights is None:
        early, middle, late = EARLY, EARLY + delta, EARLY + 2 * delta
    else:
        early, middle, late = heights
    builder = _cooperative if cooperative else _leg
    first = builder(child, sponsor, early, middle)
    if same_window:
        second = builder(sponsor, child, early, middle)
    else:
        second = builder(sponsor, child, middle, late)
    return first, second


def _outpoint(script, txid, vout, *, sats=1000, confirmations=6):
    return LegacyWalletOutpoint(txid, vout, sats, confirmations, native_p2wsh_script_pubkey(script))


def _wallet(name="wallet-a", scripts=None, outpoints=None, extras=()):
    scripts = scripts or ()
    return LegacyWalletObservation(
        name,
        tuple(f"wsh(raw({script}))#checksum" for script in scripts) + tuple(extras),
        tuple(outpoints or ()),
    )


def _canon(*, depths=None, known=(), users=()):
    return CanonicalReadSnapshot(
        True,
        tuple(sorted((depths or {GENESIS_XONLY_KEY: 0}).items())),
        tuple(known),
        frozenset(users),
    )


def _plan(wallets, canonical=None):
    return LegacyCovenantCanonicalMigrationPlanner().plan(tuple(wallets), canonical or _canon())


def _funded_pair(*, delta=777, same_window=False, cooperative=False, confirmations=6, heights=None):
    scripts = _pair(delta, same_window=same_window, cooperative=cooperative, heights=heights)
    points = (
        _outpoint(scripts[0], "a" * 64, 0, confirmations=confirmations),
        _outpoint(scripts[1], "b" * 64, 1, confirmations=confirmations),
    )
    return scripts, points


def test_cross_wallet_script_and_outpoint_deduplication_does_not_double_sats():
    scripts, points = _funded_pair()
    plan = _plan((_wallet("one", scripts, points), _wallet("two", scripts, points)))
    assert plan.summary.unique_witness_script_count == 2
    assert plan.summary.unique_outpoint_count == 2
    assert plan.summary.duplicate_outpoint_occurrence_count == 2
    assert plan.relationships[0].current_sats == 2000
    assert plan.relationships[0].observed_in_wallet_count == 2


def test_exact_native_p2wsh_matching_only():
    script = _pair()[0]
    exact = native_p2wsh_script_pubkey(script)
    assert exact == "0020" + sha256(bytes.fromhex(script)).hexdigest()
    wrong = LegacyWalletOutpoint("a" * 64, 0, 1000, 6, "0020" + "0" * 64)
    plan = _plan((_wallet(scripts=_pair(), outpoints=(wrong,)),))
    assert plan.relationships[0].unique_outpoint_count == 0
    assert plan.relationships[0].decision is MigrationDecision.INCOMPLETE_FUNDING


def test_role_swapped_contiguous_legacy_777_is_eligible_from_genesis():
    scripts, points = _funded_pair()
    result = _plan((_wallet(scripts=scripts, outpoints=points),)).relationships[0]
    assert result.relationship_class is LegacyRelationshipClass.ROLE_SWAPPED_CONTIGUOUS_TRIPLE
    assert result.decision is MigrationDecision.ELIGIBLE_FOR_BOOTSTRAP


def test_role_swapped_same_window_is_distinct_and_not_current_canon():
    scripts, points = _funded_pair(same_window=True)
    result = _plan((_wallet(scripts=scripts, outpoints=points),)).relationships[0]
    assert result.relationship_class is LegacyRelationshipClass.ROLE_SWAPPED_SAME_WINDOW
    assert result.decision is MigrationDecision.UNSUPPORTED_PROFILE
    assert "same_window_not_current_canon" in result.reasons


def test_delta_144_is_inventory_only_under_current_legacy_777_human_canon():
    scripts, points = _funded_pair(delta=144)
    result = _plan((_wallet(scripts=scripts, outpoints=points),)).relationships[0]
    assert result.deltas == (144,)
    assert result.decision is MigrationDecision.UNSUPPORTED_PROFILE
    assert "delta_144_not_current_human_canon" in result.reasons


def test_delta_164_is_explicitly_unsupported():
    scripts, points = _funded_pair(delta=164)
    result = _plan((_wallet(scripts=scripts, outpoints=points),)).relationships[0]
    assert result.relationship_class is LegacyRelationshipClass.UNSUPPORTED_DELTA
    assert "delta_164_unsupported" in result.reasons


def test_cooperative_script_is_inventoried_not_accepted():
    scripts, points = _funded_pair(cooperative=True)
    result = _plan((_wallet(scripts=scripts, outpoints=points),)).relationships[0]
    assert result.relationship_class is LegacyRelationshipClass.NESTED_OR_COOPERATIVE
    assert result.decision is MigrationDecision.UNSUPPORTED_PROFILE


def test_only_one_script_is_incomplete_relation():
    script = _pair()[0]
    result = _plan((_wallet(scripts=(script,), outpoints=(_outpoint(script, "a" * 64, 0),)),)).relationships[0]
    assert result.relationship_class is LegacyRelationshipClass.SINGLE_SCRIPT_ONLY
    assert result.decision is MigrationDecision.INCOMPLETE_RELATION


def test_only_one_funded_leg_is_incomplete_funding():
    scripts = _pair()
    result = _plan((_wallet(scripts=scripts, outpoints=(_outpoint(scripts[0], "a" * 64, 0),)),)).relationships[0]
    assert result.decision is MigrationDecision.INCOMPLETE_FUNDING
    assert "only_one_funded_leg" in result.reasons


def test_confirmations_below_canon_threshold_are_blocked():
    scripts, points = _funded_pair(confirmations=0)
    result = _plan((_wallet(scripts=scripts, outpoints=points),)).relationships[0]
    assert result.decision is MigrationDecision.UNCONFIRMED_FUNDING


def test_exact_existing_canonical_relation_is_idempotently_recognized():
    scripts, points = _funded_pair()
    hashes = tuple(sorted(sha256(bytes.fromhex(value)).hexdigest() for value in scripts))
    known = CanonicalKnownRelationship(tuple(sorted((ROOT[2:], CHILD[2:]))), hashes, True, "canonical_test")
    result = _plan((_wallet(scripts=scripts, outpoints=points),), _canon(known=(known,))).relationships[0]
    assert result.decision is MigrationDecision.ALREADY_CANONICAL
    assert result.already_represented_in_canon is True
    assert (
        _plan((_wallet(scripts=scripts, outpoints=points),), _canon(known=(known,))).summary.eligible_candidate_count
        == 0
    )


def test_existing_trusted_registration_is_consumed_through_exact_canon_type():
    from tests.unit.test_canonical_admission_edge import registration

    value = registration()
    known = CanonicalKnownRelationship.from_registration(value)
    scripts = (value.mirrored_pair.earlier_leg.raw_script_hex, value.mirrored_pair.later_leg.raw_script_hex)
    points = (
        _outpoint(scripts[0], value.outpoints[0].txid, value.outpoints[0].vout, sats=value.outpoints[0].amount_sats),
        _outpoint(scripts[1], value.outpoints[1].txid, value.outpoints[1].vout, sats=value.outpoints[1].amount_sats),
    )
    result = _plan((_wallet(scripts=scripts, outpoints=points),), _canon(known=(known,))).relationships[0]
    assert result.decision is MigrationDecision.ALREADY_CANONICAL


def test_snapshot_factory_validates_genesis_edge_and_registration_sources():
    from tests.unit.test_canonical_admission_edge import edge, genesis, registration

    reg = registration()
    admission = edge(reg)
    genesis_evaluation = genesis()
    from app.services.canonical_genesis_record import parse_canonical_genesis_record
    from pathlib import Path

    root = parse_canonical_genesis_record(Path("docs/data/e923_canonical_genesis_record_v1.json").read_bytes())
    snapshot = CanonicalReadSnapshot.from_canonical_records(
        genesis_records=(root,),
        evaluated_at=genesis_evaluation.evaluated_at,
        admission_edges=(admission,),
        registrations=(reg,),
    )
    assert dict(snapshot.reachable_depths)[CHILD[2:]] == 1


def test_conflicting_canonical_state_fails_closed():
    scripts, points = _funded_pair()
    known = CanonicalKnownRelationship(tuple(sorted((ROOT[2:], CHILD[2:]))), ("f" * 64,), True, "canonical_conflict")
    result = _plan((_wallet(scripts=scripts, outpoints=points),), _canon(known=(known,))).relationships[0]
    assert result.decision is MigrationDecision.CANONICAL_CONFLICT


@pytest.mark.parametrize("user_present", (False, True))
def test_browser_user_does_not_determine_eligibility(user_present):
    scripts, points = _funded_pair()
    users = (CHILD[2:],) if user_present else ()
    result = _plan((_wallet(scripts=scripts, outpoints=points),), _canon(users=users)).relationships[0]
    assert result.decision is MigrationDecision.ELIGIBLE_FOR_BOOTSTRAP


def test_user_without_observed_canonical_bitcoin_evidence_creates_no_candidate():
    plan = _plan((), _canon(users=(CHILD[2:],)))
    assert plan.summary.relationship_count == 0
    assert plan.summary.eligible_candidate_count == 0


def test_balance_ratio_and_mutation_dependencies_are_never_called():
    class Forbidden:
        def __getattr__(self, name):
            raise AssertionError(f"mutation/legacy authority accessed: {name}")

    scripts, points = _funded_pair()
    planner = LegacyCovenantCanonicalMigrationPlanner()
    planner.forbidden_database = Forbidden()
    planner.forbidden_wallet = Forbidden()
    assert planner.plan((_wallet(scripts=scripts, outpoints=points),), _canon()).summary.eligible_candidate_count == 1


def test_xpub_descriptor_is_diagnostic_only_not_identity_or_eligibility():
    xpub = "xpub-sensitive-private-metadata"
    plan = _plan((_wallet(extras=(f"wpkh({xpub}/0/*)#checksum",)),))
    assert plan.summary.non_raw_descriptor_occurrence_count == 1
    assert plan.summary.participant_count == 0
    assert xpub not in plan.to_json()


def test_unreachable_candidate_is_not_eligible():
    scripts = _pair(sponsor=OTHER, child=CHILD, heights=(EARLY, MIDDLE, LATE))
    points = (_outpoint(scripts[0], "a" * 64, 0), _outpoint(scripts[1], "b" * 64, 1))
    result = _plan((_wallet(scripts=scripts, outpoints=points),)).relationships[0]
    assert result.decision is MigrationDecision.UNREACHABLE_FROM_GENESIS


def test_wrong_depth_cascade_heights_are_invalid():
    scripts, points = _funded_pair(heights=(EARLY + 1, MIDDLE + 1, LATE + 1))
    result = _plan((_wallet(scripts=scripts, outpoints=points),)).relationships[0]
    assert result.decision is MigrationDecision.INVALID
    assert "candidate_heights_do_not_match_depth" in result.reasons


def test_candidate_graph_can_extend_only_from_exact_eligible_relation():
    first_scripts, first_points = _funded_pair()
    depth_two = (1776223, 1777000, 1777777)
    second_scripts = _pair(sponsor=CHILD, child=OTHER, heights=depth_two)
    second_points = (
        _outpoint(second_scripts[0], "c" * 64, 0),
        _outpoint(second_scripts[1], "d" * 64, 1),
    )
    plan = _plan(
        (
            _wallet("later-first", second_scripts, second_points),
            _wallet("root", first_scripts, first_points),
        )
    )
    assert sum(value.decision is MigrationDecision.ELIGIBLE_FOR_BOOTSTRAP for value in plan.relationships) == 2


def test_deterministic_output_ignores_wallet_iteration_and_duplicate_provenance():
    scripts, points = _funded_pair()
    a = _wallet("a", scripts, points)
    b = _wallet("b", scripts, points)
    forward = _plan((a, b)).to_json()
    reverse = _plan((b, a)).to_json()
    assert forward == reverse
    assert json.loads(forward)["plan_sha256"] == json.loads(reverse)["plan_sha256"]


def test_serialized_output_minimizes_all_sensitive_source_material():
    scripts, points = _funded_pair()
    descriptor = f"wsh(raw({scripts[0]}))#checksum"
    output = _plan((_wallet(scripts=scripts, outpoints=points),)).to_json()
    for sensitive in (
        ROOT,
        ROOT[2:],
        CHILD,
        CHILD[2:],
        scripts[0],
        scripts[1],
        descriptor,
        "a" * 64,
        "b" * 64,
    ):
        assert sensitive not in output


def test_duplicate_outpoint_with_conflicting_wallet_claim_fails_closed():
    script = _pair()[0]
    one = _outpoint(script, "a" * 64, 0, sats=1000)
    two = _outpoint(script, "a" * 64, 0, sats=2000)
    with pytest.raises(InvalidMigrationPlannerInput):
        _plan((_wallet("a", (script,), (one,)), _wallet("b", (script,), (two,))))


def test_malformed_script_is_fail_closed_and_diagnostic():
    malformed = "63ff68"
    plan = _plan((_wallet(scripts=(malformed,)),))
    assert plan.summary.relationship_count == 0
    assert plan.summary.malformed_script_count == 1
    assert plan.diagnostic_scripts[0]["reason"] == "malformed_or_unsupported_script"


def test_malformed_raw_descriptor_is_opaque_diagnostic():
    sensitive = "raw(not-hex-private-value)"
    plan = _plan((_wallet(extras=(sensitive,)),))
    assert plan.diagnostic_scripts[0]["reason"] == "malformed_descriptor_or_script"
    assert sensitive not in plan.to_json()


def test_descriptor_classes_are_inventory_counts_only():
    script = _pair()[0]
    plan = _plan(
        (
            _wallet(
                scripts=(script,),
                extras=("addr(bc1qprivate)#x", "wpkh(xpub-private/0/*)#x", "combo(private)#x"),
            ),
        )
    )
    assert plan.summary.descriptor_class_counts == (("addr", 1), ("other", 1), ("raw", 1), ("wpkh", 1))
    assert "xpub-private" not in plan.to_json()


def test_empty_wallet_set_is_valid_and_does_not_invent_full_population():
    plan = _plan(())
    assert plan.summary.observation_wallet_count == 0
    assert plan.summary.relationship_count == 0
    assert plan.summary.eligible_candidate_count == 0
    assert json.loads(plan.to_json())["mode"] == "read_only_dry_run"


def test_cli_has_no_apply_write_bootstrap_or_activate_options():
    with pytest.raises(SystemExit):
        parse_args(["--apply"])
    with pytest.raises(SystemExit):
        parse_args(["--write"])
    with pytest.raises(SystemExit):
        parse_args(["--bootstrap"])
    with pytest.raises(SystemExit):
        parse_args(["--activate"])


def test_live_collector_contract_contains_only_read_rpc_calls_and_read_only_db():
    source = inspect.getsource(cli._collect_live)
    for allowed in ("listwallets", "listdescriptors", "listunspent"):
        assert allowed in source
    for forbidden in (
        "importdescriptors",
        "removewallet",
        "sendrawtransaction",
        "walletcreatefundedpsbt",
        ".commit(",
        ".delete(",
    ):
        assert forbidden not in source
    assert "default_transaction_read_only=on" in source


def test_cli_failure_is_generic_and_never_echoes_source_exception(monkeypatch, capsys):
    secret = "rpc-password-must-not-appear"

    def unavailable():
        raise RuntimeError(secret)

    monkeypatch.setattr(cli, "_collect_live", unavailable)
    assert cli.main(["--live"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "READ-ONLY DRY RUN unavailable\n"
    assert secret not in captured.err


def test_canonical_snapshot_rejects_inactive_genesis_claiming_root_reachability():
    snapshot = CanonicalReadSnapshot(False, ((GENESIS_XONLY_KEY, 0),))
    scripts, points = _funded_pair()
    assert _plan((_wallet(scripts=scripts, outpoints=points),), snapshot).relationships[0].decision is (
        MigrationDecision.UNREACHABLE_FROM_GENESIS
    )


def test_multiple_outpoints_for_one_required_leg_is_ambiguous():
    scripts, points = _funded_pair()
    extra = _outpoint(scripts[0], "c" * 64, 2)
    result = _plan((_wallet(scripts=scripts, outpoints=points + (extra,)),)).relationships[0]
    assert result.decision is MigrationDecision.AMBIGUOUS
    assert "multiple_outpoints_for_required_leg" in result.reasons


def test_unequal_leg_amounts_fail_closed():
    scripts = _pair()
    points = (_outpoint(scripts[0], "a" * 64, 0, sats=1000), _outpoint(scripts[1], "b" * 64, 1, sats=2000))
    result = _plan((_wallet(scripts=scripts, outpoints=points),)).relationships[0]
    assert result.decision is MigrationDecision.INCOMPLETE_FUNDING
    assert "required_leg_amounts_do_not_match" in result.reasons


def test_wallet_names_are_opaque_and_not_authority():
    scripts, points = _funded_pair()
    wallet_name = "production-secret-wallet-name"
    output = _plan((_wallet(wallet_name, scripts, points),)).to_json()
    assert wallet_name not in output
    assert json.loads(output)["summary"]["eligible_candidate_count"] == 1
