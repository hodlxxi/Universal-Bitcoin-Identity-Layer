"""Multiple funded mirror UTXOs: real-shape fixtures, strict no-Full preflight."""

import hashlib
import json
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import pytest

from app.services.canonical_multi_outpoint_mirror_v2 import (
    BOUNDARY,
    SCHEMA,
    CanonicalMultiOutpointMirrorV2,
    InvalidCanonicalMultiOutpointMirrorV2,
    canonical_multi_outpoint_mirror_v2_bytes,
    canonical_multi_outpoint_mirror_v2_sha256,
    create_canonical_multi_outpoint_mirror_v2,
    observe_canonical_multi_outpoint_mirror_v2,
    validate_canonical_multi_outpoint_snapshot_v2,
)
from app.services.canonical_sponsored_script_policy_v2 import validate_canonical_sponsored_scripts_v2
from app.services.covenant_relation import (
    EVALUATION_SCHEMA,
    OBSERVATION_SCHEMA,
    CovenantDirection,
    CovenantRelationEvaluation,
    CovenantRelationObservation,
)
from app.services.trusted_covenant_observation import TRUSTED_OUTPOINT_SCHEMA, TrustedCovenantOutpoint
from app.services.trusted_covenant_registration import p2wsh_script_pubkey_sha256
from tests.unit.test_canonical_admission_proposal_v2 import ALICE, BOB, DEMO_EARLY, DEMO_LATE, NOW

HEIGHT = 900000
BLOCK_HASH = "f" * 64


def _evidence():
    return validate_canonical_sponsored_scripts_v2(
        DEMO_EARLY, DEMO_LATE, sponsor_compressed_pubkey=ALICE, sponsor_depth=0
    )


def _bundle(
    *,
    outgoing=(100000, 100000, 100000),
    incoming=(150000, 150000),
):
    evidence = _evidence()
    anchors = []
    for direction, amounts, script in (
        (CovenantDirection.OUTGOING, outgoing, evidence.earlier_script_sha256),
        (CovenantDirection.INCOMING, incoming, evidence.later_script_sha256),
    ):
        for i, amount in enumerate(amounts):
            anchors.append(
                TrustedCovenantOutpoint(
                    TRUSTED_OUTPOINT_SCHEMA,
                    BOB[2:],
                    ALICE[2:],
                    direction,
                    format((1 if direction is CovenantDirection.OUTGOING else 100) + i, "064x"),
                    i,
                    amount,
                    p2wsh_script_pubkey_sha256(script),
                    None,
                )
            )
    return create_canonical_multi_outpoint_mirror_v2(evidence, tuple(reversed(anchors)))


def _observation(bundle, *, observed_at=NOW):
    return CovenantRelationEvaluation(
        EVALUATION_SCHEMA,
        "bitcoin",
        BOB[2:],
        ALICE[2:],
        observed_at,
        HEIGHT,
        tuple(
            CovenantRelationObservation(
                OBSERVATION_SCHEMA,
                item.subject_pubkey,
                item.counterparty_pubkey,
                item.direction,
                item.txid,
                item.vout,
                item.amount_sats,
                item.script_sha256,
                item.descriptor_sha256,
                6,
                True,
            )
            for item in bundle.outpoints
        ),
    )


class Rpc:
    def __init__(self, bundle):
        self.bundle = bundle
        self.calls = []
        self.fail_script = False
        self.fail_block = False
        self.spent = False
        self.height_calls = 0

    def getblockcount(self):
        self.height_calls += 1
        return HEIGHT if not self.fail_block or self.height_calls == 1 else HEIGHT + 1

    def getbestblockhash(self):
        return BLOCK_HASH

    def gettxout(self, txid, vout, include_mempool):
        self.calls.append((txid, vout, include_mempool))
        if self.spent:
            return None
        item = next(x for x in self.bundle.outpoints if (x.txid, x.vout) == (txid, vout))
        script_hash = (
            self.bundle.script_evidence.earlier_script_sha256
            if item.direction is CovenantDirection.OUTGOING
            else self.bundle.script_evidence.later_script_sha256
        )
        if self.fail_script:
            script_hash = "e" * 64
        return {
            "bestblock": BLOCK_HASH,
            "confirmations": 6,
            "value": Decimal(item.amount_sats) / Decimal(100000000),
            "scriptPubKey": {"hex": "0020" + script_hash},
        }


def test_real_script_shape_with_three_plus_two_outputs_and_300k_each():
    bundle = _bundle()
    assert bundle.schema == SCHEMA
    assert bundle.authorization_boundary == BOUNDARY
    assert len(bundle.outpoints) == 5
    assert not bundle.grants_full and not bundle.is_effective
    proof = validate_canonical_multi_outpoint_snapshot_v2(bundle, _observation(bundle), now=NOW)
    assert (proof.earlier_sats, proof.later_sats) == (300000, 300000)
    assert proof.trust_ceiling_sats == 300000
    assert proof.outpoint_count == 5
    assert proof.grants_full is False
    assert proof.source_is_authoritative is False


@pytest.mark.parametrize(
    "outgoing,incoming,expected",
    [
        ((50000, 100000), (30000, 70000), 100000),
        ((30000,), (50000,), 30000),
        ((50000, 50000), (25000, 25000), 50000),
        ((150000,), (300000,), 150000),
    ],
)
def test_ceiling_is_lower_of_two_aggregates_not_one_outpoint(outgoing, incoming, expected):
    bundle = _bundle(outgoing=outgoing, incoming=incoming)
    snapshot = validate_canonical_multi_outpoint_snapshot_v2(bundle, _observation(bundle), now=NOW)
    assert snapshot.trust_ceiling_sats == expected
    assert snapshot.earlier_sats == sum(outgoing)
    assert snapshot.later_sats == sum(incoming)


def test_serialization_independent_of_outpoint_input_order():
    original = _bundle()
    sorted_variant = replace(original, outpoints=tuple(reversed(original.outpoints)))
    assert original.outpoints == sorted_variant.outpoints
    assert canonical_multi_outpoint_mirror_v2_bytes(original) == canonical_multi_outpoint_mirror_v2_bytes(sorted_variant)
    assert canonical_multi_outpoint_mirror_v2_sha256(original) == canonical_multi_outpoint_mirror_v2_sha256(sorted_variant)
    data = json.loads(canonical_multi_outpoint_mirror_v2_bytes(original))
    assert len(data["outpoints"]) == 5
    assert data["script_evidence"]["orientation"] == "sponsor_early_child_middle_sponsor_late"


def test_rejects_missing_sides_or_wrong_script_direction():
    evidence = _evidence()
    original = _bundle()
    for items in (
        tuple(x for x in original.outpoints if x.direction is CovenantDirection.INCOMING),
        tuple(x for x in original.outpoints if x.direction is CovenantDirection.OUTGOING),
    ):
        with pytest.raises(InvalidCanonicalMultiOutpointMirrorV2, match="missing_mirror_side"):
            create_canonical_multi_outpoint_mirror_v2(evidence, items)
    forged = replace(original.outpoints[0], script_sha256="0" * 64)
    with pytest.raises(InvalidCanonicalMultiOutpointMirrorV2, match="outpoint_identity_or_script"):
        replace(original, outpoints=(forged, *original.outpoints[1:]))


def test_rejects_duplicate_outpoint_and_cross_pair_ownership():
    original = _bundle()
    with pytest.raises(InvalidCanonicalMultiOutpointMirrorV2, match="outpoint_duplicate"):
        replace(original, outpoints=original.outpoints + (original.outpoints[0],))
    wrong = replace(original.outpoints[0], subject_pubkey="a" * 64)
    with pytest.raises(InvalidCanonicalMultiOutpointMirrorV2, match="outpoint_identity_or_script"):
        replace(original, outpoints=(wrong, *original.outpoints[1:]))


@pytest.mark.parametrize("modifier", ["spent", "unconfirmed", "amount", "txid", "script", "direction"])
def test_observation_rejects_any_spent_unconfirmed_or_mismatched_UTXO(modifier):
    bundle = _bundle()
    snapshot = _observation(bundle)
    item = snapshot.observations[0]
    if modifier == "spent":
        replacement = replace(item, unspent=False)
    elif modifier == "unconfirmed":
        replacement = replace(item, confirmations=0)
    elif modifier == "amount":
        replacement = replace(item, amount_sats=item.amount_sats + 1)
    elif modifier == "txid":
        replacement = replace(item, txid="d" * 64)
    elif modifier == "script":
        replacement = replace(item, script_sha256="f" * 64)
    else:
        replacement = replace(item, direction=(
            CovenantDirection.OUTGOING if item.direction is CovenantDirection.INCOMING else CovenantDirection.INCOMING
        ))
    altered = replace(snapshot, observations=(replacement, *snapshot.observations[1:]))
    with pytest.raises(InvalidCanonicalMultiOutpointMirrorV2):
        validate_canonical_multi_outpoint_snapshot_v2(bundle, altered, now=NOW)


def test_rejects_stale_future_incomplete_or_foreign_observation():
    bundle = _bundle()
    current = _observation(bundle)
    checks = (
        (current, NOW + timedelta(seconds=121)),
        (current, NOW - timedelta(seconds=1)),
        (replace(current, observations=current.observations[:-1]), NOW),
        (
            replace(
                current,
                subject_pubkey="b" * 64,
                observations=tuple(replace(o, subject_pubkey="b" * 64) for o in current.observations),
            ),
            NOW,
        ),
    )
    for altered, at in checks:
        with pytest.raises(InvalidCanonicalMultiOutpointMirrorV2):
            validate_canonical_multi_outpoint_snapshot_v2(bundle, altered, now=at)


def test_exact_rpc_gettxout_adapter_reads_every_registered_p2wsh():
    bundle = _bundle()
    rpc = Rpc(bundle)
    receipt = observe_canonical_multi_outpoint_mirror_v2(bundle, bitcoin_rpc=rpc, now=NOW)
    assert receipt.trust_ceiling_sats == 300000
    assert receipt.outpoint_count == 5
    assert len(rpc.calls) == 5
    assert set(rpc.calls) == {(x.txid, x.vout, False) for x in bundle.outpoints}
    assert not receipt.grants_full and not receipt.source_is_authoritative


@pytest.mark.parametrize("failure", ["spent", "fail_script", "fail_block"])
def test_rpc_fails_closed_on_missing_wrong_script_or_moving_block(failure):
    bundle = _bundle()
    rpc = Rpc(bundle)
    setattr(rpc, failure, True)
    with pytest.raises(InvalidCanonicalMultiOutpointMirrorV2):
        observe_canonical_multi_outpoint_mirror_v2(bundle, bitcoin_rpc=rpc, now=NOW)


def test_rejects_forged_policy_or_wrong_evidence_hash():
    bundle = _bundle()
    with pytest.raises(InvalidCanonicalMultiOutpointMirrorV2, match="script_policy_digest"):
        replace(bundle, script_evidence_sha256="0" * 64)
    with pytest.raises(InvalidCanonicalMultiOutpointMirrorV2, match="schema_or_boundary"):
        replace(bundle, authorization_boundary="grants_full")
    with pytest.raises(InvalidCanonicalMultiOutpointMirrorV2, match="bundle_type"):
        canonical_multi_outpoint_mirror_v2_bytes({"fake": True})


def test_declares_legacy_two_outpoint_proposal_boundary_without_issuing_full():
    """A new aggregate record does not mutate the strict legacy registration."""
    bundle = _bundle()
    assert len(bundle.outpoints) > 2
    assert not bundle.is_effective
    assert validate_canonical_multi_outpoint_snapshot_v2(
        bundle, _observation(bundle), now=NOW
    ).grants_full is False
