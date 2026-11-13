"""Canon V2 script-policy regression for real Alice/Bob and generic sponsorship."""

import hashlib
import json
from dataclasses import replace

import pytest

from app.services.canonical_sponsored_script_policy_v2 import (
    BOUNDARY,
    ORIENTATION,
    POLICY_VERSION,
    SCHEMA,
    InvalidCanonicalSponsoredScriptPolicyV2,
    canonical_sponsored_script_evidence_v2_bytes,
    canonical_sponsored_script_evidence_v2_sha256,
    validate_canonical_sponsored_scripts_v2,
)
from app.services.sponsored_admission_import_preflight import assess_sponsored_imported_pair

ALICE = "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
BOB = "02c870934f7aaa2fd1c40834989fd97933a8866ebcf35f3e529d95b50d320f80a3"
CHARLIE = "032f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8c"
DAVE = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

# Literal script from the actual Alice/Bob on-chain demonstration.
DEMO_EARLY = (
    "6303681d1bb17521023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
    "ac670371201bb1752102c870934f7aaa2fd1c40834989fd97933a8866ebcf35f3e529d95b50d320f80a3ac68"
)
DEMO_LATE = (
    "630371201bb1752102c870934f7aaa2fd1c40834989fd97933a8866ebcf35f3e529d95b50d320f80a3"
    "ac67037a231bb17521023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923ac68"
)


def _num(number):
    result = bytearray()
    while number:
        result.append(number & 255)
        number >>= 8
    if result[-1] & 128:
        result.append(0)
    return bytes((len(result),)) + result


def _leg(receiver, sender, early, late):
    return (
        b"\x63"
        + _num(early)
        + b"\xb1\x75"
        + bytes.fromhex("21" + receiver)
        + b"\xac\x67"
        + _num(late)
        + b"\xb1\x75"
        + bytes.fromhex("21" + sender)
        + b"\xac\x68"
    ).hex()


def _check(first=DEMO_EARLY, second=DEMO_LATE, *, sponsor=ALICE, depth=0):
    return validate_canonical_sponsored_scripts_v2(
        first, second, sponsor_compressed_pubkey=sponsor, sponsor_depth=depth
    )


def _rejected(reason, first=DEMO_EARLY, second=DEMO_LATE, *, sponsor=ALICE, depth=0):
    with pytest.raises(InvalidCanonicalSponsoredScriptPolicyV2) as exc:
        _check(first, second, sponsor=sponsor, depth=depth)
    assert exc.value.reason == reason


def test_real_alice_bob_exact_scripts_are_canon_v2_and_never_full():
    result = _check()
    assert result.schema == SCHEMA
    assert result.policy_version == POLICY_VERSION
    assert result.authorization_boundary == BOUNDARY
    assert result.orientation == ORIENTATION
    assert result.sponsor_participant_id == "E923"
    assert result.child_participant_id == BOB[2:]
    assert result.sponsor_xonly_pubkey == ALICE[2:]
    assert result.child_xonly_pubkey == BOB[2:]
    assert result.sponsor_depth == 0
    assert result.child_depth == 1
    assert (result.early_height, result.middle_height, result.late_height) == (
        1777000,
        1777777,
        1778554,
    )
    assert result.earlier_raw_script_hex == DEMO_EARLY
    assert result.later_raw_script_hex == DEMO_LATE
    assert len(result.pair_sha256) == 64
    assert result.grants_full is False


def test_swapped_import_order_has_identical_canonical_v2_record_and_commitment():
    forward = _check()
    reversed_order = _check(DEMO_LATE, DEMO_EARLY)
    assert forward == reversed_order
    assert canonical_sponsored_script_evidence_v2_bytes(forward) == (
        canonical_sponsored_script_evidence_v2_bytes(reversed_order)
    )
    assert canonical_sponsored_script_evidence_v2_sha256(forward) == (
        hashlib.sha256(canonical_sponsored_script_evidence_v2_bytes(forward)).hexdigest()
    )
    assert json.loads(canonical_sponsored_script_evidence_v2_bytes(forward))["child_depth"] == 1


@pytest.mark.parametrize(
    "sponsor,child,depth,early,middle,late",
    [
        (ALICE, BOB, 0, 1777000, 1777777, 1778554),
        (BOB, CHARLIE, 1, 1776223, 1777000, 1777777),
        (CHARLIE, DAVE, 2, 1775446, 1776223, 1777000),
    ],
)
def test_any_current_full_participant_may_be_candidate_sponsor_at_child_depth(
    sponsor, child, depth, early, middle, late
):
    result = _check(
        _leg(sponsor, child, early, middle),
        _leg(child, sponsor, middle, late),
        sponsor=sponsor,
        depth=depth,
    )
    assert result.child_depth == depth + 1
    assert result.sponsor_depth == depth
    assert result.sponsor_compressed_pubkey == sponsor
    assert result.child_compressed_pubkey == child
    assert result.sponsor_participant_id == ("E923" if depth == 0 else sponsor[2:])
    assert result.child_participant_id == child[2:]
    assert result.grants_full is False


def test_canon_v1_orientation_remains_separate_and_is_rejected_under_v2():
    legacy_early = _leg(BOB, ALICE, 1777000, 1777777)
    legacy_late = _leg(ALICE, BOB, 1777777, 1778554)
    old = assess_sponsored_imported_pair(
        legacy_early, legacy_late, sponsor_compressed_pubkey=ALICE, sponsor_depth=0
    )
    assert old.status == "canonical_script_shape_only"
    _rejected("v2_unilateral_role_mismatch", legacy_early, legacy_late)


def test_real_canon_v2_scripts_remain_unmodified_under_v1():
    old = assess_sponsored_imported_pair(
        DEMO_EARLY, DEMO_LATE, sponsor_compressed_pubkey=ALICE, sponsor_depth=0
    )
    assert old.status == "reverse_branch_roles_requires_policy_review"
    assert old.grants_full is False


def test_wrong_sponsor_depth_never_inherits_someone_elses_cascade():
    early = _leg(BOB, CHARLIE, 1776223, 1777000)
    late = _leg(CHARLIE, BOB, 1777000, 1777777)
    _rejected("cascade_schedule_mismatch", early, late, sponsor=BOB, depth=2)


@pytest.mark.parametrize(
    "first,second",
    [
        (DEMO_EARLY, DEMO_EARLY),
        ("00", DEMO_LATE),
        ("not-hex", DEMO_LATE),
        (DEMO_EARLY.upper(), DEMO_LATE),
    ],
)
def test_duplicate_or_malformed_pairs_fail_closed(first, second):
    _rejected("invalid_or_unsupported_mirror", first, second)


def test_bad_mirror_middle_or_delta_fails_closed():
    mismatched_middle = _leg(BOB, ALICE, 1777778, 1778555)
    _rejected("invalid_or_unsupported_mirror", DEMO_EARLY, mismatched_middle)


def test_wrong_parent_or_wrong_child_sponsor_identity_fails_closed():
    _rejected("non_genesis_root", sponsor=BOB)
    _rejected("invalid_or_unsupported_mirror", sponsor=CHARLIE, depth=1)


@pytest.mark.parametrize(
    "depth",
    [True, -1, 1.2, "1", None],
)
def test_depth_must_be_an_exact_nonnegative_int(depth):
    _rejected("invalid_sponsor_identity_or_depth", depth=depth)


@pytest.mark.parametrize("sponsor", [True, "02" + "z" * 64, ALICE.upper(), ALICE[2:]])
def test_sponsor_requires_canonical_compressed_key(sponsor):
    _rejected("invalid_sponsor_identity_or_depth", sponsor=sponsor)


def test_depth_must_remain_inside_positive_absolute_cltv_height_range():
    _rejected("depth_outside_cascade", sponsor=BOB, depth=2288)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "hodlxxi.canonical_sponsored_script_evidence.v1"),
        ("policy_version", "legacy"),
        ("network", "testnet"),
        ("graph_or_protocol_id", "foreign"),
        ("human_profile", "current_144"),
        ("orientation", "child_early_sponsor_middle_child_late"),
        ("authorization_boundary", "grants_full"),
    ],
)
def test_fixed_policy_metadata_cannot_be_forged(field, value):
    with pytest.raises(InvalidCanonicalSponsoredScriptPolicyV2, match="fixed_v2_policy"):
        replace(_check(), **{field: value})


@pytest.mark.parametrize(
    "field,value",
    [
        ("sponsor_participant_id", ALICE[2:]),
        ("sponsor_xonly_pubkey", BOB[2:]),
        ("child_participant_id", "E923"),
        ("child_compressed_pubkey", CHARLIE),
        ("child_xonly_pubkey", CHARLIE[2:]),
        ("child_depth", 2),
        ("early_height", 1776223),
        ("middle_height", 1777000),
        ("late_height", 1777777),
        ("earlier_script_sha256", "0" * 64),
        ("later_script_sha256", "0" * 64),
        ("pair_sha256", "0" * 64),
    ],
)
def test_forged_identity_schedule_or_digest_is_rejected(field, value):
    with pytest.raises(
        InvalidCanonicalSponsoredScriptPolicyV2, match="v2_evidence_binding_mismatch"
    ):
        replace(_check(), **{field: value})


def test_forged_script_field_is_reparsed_and_rejected():
    with pytest.raises(InvalidCanonicalSponsoredScriptPolicyV2):
        replace(_check(), earlier_raw_script_hex="00")


def test_untrusted_objects_cannot_be_serialized_as_evidence():
    with pytest.raises(InvalidCanonicalSponsoredScriptPolicyV2, match="invalid_v2_evidence_type"):
        canonical_sponsored_script_evidence_v2_bytes({"fake": "evidence"})
