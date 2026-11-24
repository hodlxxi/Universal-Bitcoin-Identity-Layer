"""No-second-signature automatic import pair correlation regressions."""

import pytest

from app.services.automatic_sponsored_import_v1 import (
    AutomaticSponsoredImportResult,
    match_imported_sponsored_pair,
)

ALICE = "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
BOB = "02c870934f7aaa2fd1c40834989fd97933a8866ebcf35f3e529d95b50d320f80a3"
CHARLIE = "032f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8c"
EARLY = (
    "6303681d1bb17521023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
    "ac670371201bb1752102c870934f7aaa2fd1c40834989fd97933a8866ebcf35f3e529d95b50d320f80a3ac68"
)
LATE = (
    "630371201bb1752102c870934f7aaa2fd1c40834989fd97933a8866ebcf35f3e529d95b50d320f80a3"
    "ac67037a231bb17521023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923ac68"
)


def _num(number):
    out = bytearray()
    while number:
        out.append(number & 255)
        number >>= 8
    if out[-1] & 128:
        out.append(0)
    return bytes((len(out),)) + bytes(out)


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


def test_first_import_waits_and_second_import_correlates_existing_onchain_demo():
    assert match_imported_sponsored_pair(EARLY, (EARLY,), sponsor_xonly_pubkey=ALICE[2:], sponsor_depth=0) is None
    matched = match_imported_sponsored_pair(LATE, (EARLY, LATE), sponsor_xonly_pubkey=ALICE[2:], sponsor_depth=0)
    assert matched is not None
    assert matched.child_xonly_pubkey == BOB[2:]
    assert matched.child_depth == 1
    assert matched.grants_full is False
    assert (matched.early_height, matched.middle_height, matched.late_height) == (1777000, 1777777, 1778554)


def test_reverse_order_is_same_exact_mirror_not_duplicate_candidate():
    forward = match_imported_sponsored_pair(LATE, (EARLY, LATE), sponsor_xonly_pubkey=ALICE[2:], sponsor_depth=0)
    reverse = match_imported_sponsored_pair(EARLY, (EARLY, LATE), sponsor_xonly_pubkey=ALICE[2:], sponsor_depth=0)
    assert forward == reverse


def test_bob_can_pair_charlie_at_the_next_cascade_depth():
    earlier = _leg(BOB, CHARLIE, 1776223, 1777000)
    later = _leg(CHARLIE, BOB, 1777000, 1777777)
    pair = match_imported_sponsored_pair(later, (earlier, later), sponsor_xonly_pubkey=BOB[2:], sponsor_depth=1)
    assert pair is not None
    assert pair.sponsor_xonly_pubkey == BOB[2:]
    assert pair.child_xonly_pubkey == CHARLIE[2:]
    assert pair.child_depth == 2
    assert pair.grants_full is False


@pytest.mark.parametrize(
    "sponsor,depth",
    [
        (BOB[2:], 0),
        (ALICE[2:], 1),
        (CHARLIE[2:], 2),
    ],
)
def test_wrong_sponsor_or_window_never_correlates(sponsor, depth):
    assert match_imported_sponsored_pair(LATE, (EARLY,), sponsor_xonly_pubkey=sponsor, sponsor_depth=depth) is None


@pytest.mark.parametrize("candidate", ["00", "NOT_HEX", "", "raw(51)"])
def test_unrelated_script_is_not_an_admission(candidate):
    assert (
        match_imported_sponsored_pair(candidate, (EARLY, LATE), sponsor_xonly_pubkey=ALICE[2:], sponsor_depth=0) is None
    )


def test_invalid_subject_depth_and_history_fail_closed():
    with pytest.raises(ValueError):
        match_imported_sponsored_pair(LATE, (EARLY,), sponsor_xonly_pubkey=ALICE[2:], sponsor_depth=True)
    with pytest.raises(ValueError):
        match_imported_sponsored_pair(LATE, [EARLY], sponsor_xonly_pubkey=ALICE[2:], sponsor_depth=0)


def test_pending_import_state_never_claims_full():
    for status in ("waiting_for_mirror", "pending_confirmed_utxo_verification"):
        record = AutomaticSponsoredImportResult(status, BOB[2:], 1)
        assert record.grants_full is False
