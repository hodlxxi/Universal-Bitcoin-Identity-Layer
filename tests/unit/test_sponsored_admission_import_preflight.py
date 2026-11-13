"""Regression: real Alice/Bob legacy_777 scripts are mirrored, but reversed vs Canon V1."""

import pytest

from app.services.sponsored_admission_import_preflight import (
    SCHEMA,
    assess_sponsored_imported_pair,
)

ALICE = "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
BOB = "02c870934f7aaa2fd1c40834989fd97933a8866ebcf35f3e529d95b50d320f80a3"
CHARLIE = "032f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8c"
DAVE = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def _num(n):
    data = bytearray()
    while n:
        data.append(n & 255)
        n >>= 8
    if data[-1] & 128:
        data.append(0)
    return bytes((len(data),)) + data


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


# Two real demonstrator script templates: Alice has the first earlier window.
DEMO_EARLY = _leg(ALICE, BOB, 1777000, 1777777)
DEMO_LATE = _leg(BOB, ALICE, 1777777, 1778554)
assert DEMO_EARLY == (
    "6303681d1bb17521023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
    "ac670371201bb1752102c870934f7aaa2fd1c40834989fd97933a8866ebcf35f3e529d95b50d320f80a3ac68"
)


def _assess(a, b, *, sponsor=ALICE, depth=0):
    return assess_sponsored_imported_pair(a, b, sponsor_compressed_pubkey=sponsor, sponsor_depth=depth)


def test_real_alice_bob_scripts_fail_closed_as_reversed_canon_roles():
    for scripts in ((DEMO_EARLY, DEMO_LATE), (DEMO_LATE, DEMO_EARLY)):
        result = _assess(*scripts)
        assert result.schema == SCHEMA
        assert result.sponsor_xonly_pubkey == ALICE[2:]
        assert result.candidate_child_xonly_pubkey == BOB[2:]
        assert result.status == "reverse_branch_roles_requires_policy_review"
        assert result.child_depth == 1
        assert len(result.pair_sha256) == 64
        assert result.grants_full is False


def test_canonical_depth_one_order_is_only_structural_candidate_not_full():
    result = _assess(
        _leg(BOB, ALICE, 1777000, 1777777),
        _leg(ALICE, BOB, 1777777, 1778554),
    )
    assert result.status == "canonical_script_shape_only"
    assert result.candidate_child_xonly_pubkey == BOB[2:]
    assert result.grants_full is False


def test_wrong_window_fail_closed():
    result = _assess(
        _leg(BOB, ALICE, 1776223, 1777000),
        _leg(ALICE, BOB, 1777000, 1777777),
    )
    assert result.status == "wrong_admission_schedule"
    assert result.grants_full is False


def test_duplicate_or_malformed_pair_never_creates_candidate():
    for a, b in ((DEMO_EARLY, DEMO_EARLY), ("00", DEMO_LATE)):
        result = _assess(a, b)
        assert result.status == "invalid_or_unsupported_pair"
        assert result.candidate_child_xonly_pubkey is None
        assert result.pair_sha256 is None
        assert not result.grants_full


def test_cannot_replace_exceptional_genesis_subject():
    result = _assess(DEMO_EARLY, DEMO_LATE, sponsor=BOB, depth=0)
    assert result.status == "non_genesis_root"
    assert result.candidate_child_xonly_pubkey is None
    assert not result.grants_full


@pytest.mark.parametrize("depth", [True, -1, 1.5, "0"])
def test_depth_must_be_exact_nonnegative_integer(depth):
    with pytest.raises(ValueError):
        _assess(DEMO_EARLY, DEMO_LATE, depth=depth)


@pytest.mark.parametrize("key", [BOB.upper(), BOB[2:], "", "02" + "z" * 64])
def test_sponsor_key_must_be_exact_compressed_lowercase_hex(key):
    with pytest.raises(ValueError):
        _assess(DEMO_EARLY, DEMO_LATE, sponsor=key)


@pytest.mark.parametrize(
    "sponsor,child,sponsor_depth,early,middle,late",
    [
        (ALICE, BOB, 0, 1777000, 1777777, 1778554),
        (BOB, CHARLIE, 1, 1776223, 1777000, 1777777),
        (CHARLIE, DAVE, 2, 1775446, 1776223, 1777000),
    ],
)
def test_cascade_next_full_participant_can_sponsor_at_depth(
    sponsor, child, sponsor_depth, early, middle, late
):
    """Depth schedule is generic; no E923-only exception after root depth zero."""
    result = _assess(
        _leg(sponsor, child, early, middle),
        _leg(child, sponsor, middle, late),
        sponsor=sponsor,
        depth=sponsor_depth,
    )
    assert result.child_depth == sponsor_depth + 1
    assert result.sponsor_xonly_pubkey == sponsor[2:]
    assert result.candidate_child_xonly_pubkey == child[2:]
    assert result.status == "reverse_branch_roles_requires_policy_review"
    assert result.grants_full is False


@pytest.mark.parametrize(
    "sponsor,child,sponsor_depth,early,middle,late",
    [
        (BOB, CHARLIE, 1, 1776223, 1777000, 1777777),
        (CHARLIE, DAVE, 2, 1775446, 1776223, 1777000),
    ],
)
def test_canon_orientation_is_only_structural_at_deeper_depth(
    sponsor, child, sponsor_depth, early, middle, late
):
    result = _assess(
        _leg(child, sponsor, early, middle),
        _leg(sponsor, child, middle, late),
        sponsor=sponsor,
        depth=sponsor_depth,
    )
    assert result.status == "canonical_script_shape_only"
    assert result.child_depth == sponsor_depth + 1
    assert result.candidate_child_xonly_pubkey == child[2:]
    assert result.grants_full is False


def test_depth_two_does_not_accept_depth_one_cltv_heights():
    result = _assess(
        _leg(BOB, CHARLIE, 1777000, 1777777),
        _leg(CHARLIE, BOB, 1777777, 1778554),
        sponsor=BOB,
        depth=1,
    )
    assert result.status == "wrong_admission_schedule"
    assert result.grants_full is False
