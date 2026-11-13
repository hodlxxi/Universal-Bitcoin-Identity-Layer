"""Canon V2 proposed admission: exact funding/lineage bindings, never Full."""

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from app.services.canonical_admission_proposal_v2 import (
    BOUNDARY,
    SCHEMA,
    VERSION,
    CanonicalAdmissionProposalV2,
    InvalidCanonicalAdmissionProposalV2,
    SponsorBasisV2,
    canonical_admission_proposal_v2_bytes,
    canonical_admission_proposal_v2_sha256,
    create_canonical_admission_proposal_v2,
    validate_canonical_admission_proposal_v2_sources,
)
from app.services.canonical_covenant_funding_set import (
    CovenantFundingSetLifecycle,
    RecognizedCovenantFundingOutpoint,
    create_canonical_covenant_funding_set,
)
from app.services.canonical_genesis_record import (
    GRAPH_ID,
    canonical_genesis_record_sha256,
    evaluate_canonical_genesis,
    parse_canonical_genesis_record,
)
from app.services.canonical_sponsored_script_policy_v2 import (
    validate_canonical_sponsored_scripts_v2,
)
from app.services.covenant_relation import CovenantDirection
from app.services.mirrored_covenant_pair import (
    CovenantDeltaProfile,
    validate_mirrored_covenant_pair,
)
from app.services.trusted_covenant_observation import TrustedBitcoinCovenantObservationAdapter
from app.services.trusted_covenant_registration import (
    RegisteredCovenantOutpoint,
    TrustedCovenantRegistrationLifecycle,
    create_trusted_covenant_registration,
)

ALICE = "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
BOB = "02c870934f7aaa2fd1c40834989fd97933a8866ebcf35f3e529d95b50d320f80a3"
CHARLIE = "032f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8c"
NOW = datetime(2026, 11, 13, 19, 10, 0, tzinfo=timezone.utc)
BLOCK_HASH = "f" * 64
ID1 = "00000000-0000-4000-8000-000000000011"
ID2 = "00000000-0000-4000-8000-000000000012"
FUND1 = "00000000-0000-4000-8000-000000000021"
FUND2 = "00000000-0000-4000-8000-000000000022"
PROPOSAL1 = "00000000-0000-4000-8000-000000000031"
PROPOSAL2 = "00000000-0000-4000-8000-000000000032"
EARLY_TX = "a" * 64
LATE_TX = "b" * 64


def _num(value):
    output = bytearray()
    while value:
        output.append(value & 255)
        value >>= 8
    if output[-1] & 128:
        output.append(0)
    return bytes((len(output),)) + bytes(output)


def _leg(receiver, sender, first_height, second_height):
    return (
        b"\x63" + _num(first_height) + b"\xb1\x75"
        + bytes.fromhex("21" + receiver) + b"\xac\x67"
        + _num(second_height) + b"\xb1\x75"
        + bytes.fromhex("21" + sender) + b"\xac\x68"
    ).hex()


DEMO_EARLY = _leg(ALICE, BOB, 1777000, 1777777)
DEMO_LATE = _leg(BOB, ALICE, 1777777, 1778554)


def _genesis():
    raw = Path("docs/data/e923_canonical_genesis_record_v1.json").read_bytes()
    record = parse_canonical_genesis_record(raw)
    evidence = evaluate_canonical_genesis(
        (record,), graph_or_protocol_id=GRAPH_ID, evaluated_at=record.effective_at
    )
    assert evidence.selected_effective_record_sha256 == canonical_genesis_record_sha256(record)
    return evidence


class StubRpc:
    def __init__(self, early, late):
        self.outputs = {
            (EARLY_TX, 0): self._out(early),
            (LATE_TX, 1): self._out(late),
        }
        self.calls = []

    @staticmethod
    def _out(script):
        return {
            "bestblock": BLOCK_HASH,
            "confirmations": 6,
            "value": Decimal("0.00050000"),
            "scriptPubKey": {
                "hex": "0020" + hashlib.sha256(bytes.fromhex(script)).hexdigest()
            },
        }

    def getblockcount(self):
        return 900000

    def getbestblockhash(self):
        return BLOCK_HASH

    def gettxout(self, txid, vout, include_mempool):
        self.calls.append((txid, vout, include_mempool))
        return self.outputs.get((txid, vout))


def _sources(*, sponsor=ALICE, child=BOB, depth=0, at=NOW):
    early, mid, late = (
        (1777000, 1777777, 1778554) if depth == 0 else (1776223, 1777000, 1777777)
    )
    scripts = (_leg(sponsor, child, early, mid), _leg(child, sponsor, mid, late))
    policy = validate_canonical_sponsored_scripts_v2(
        *scripts, sponsor_compressed_pubkey=sponsor, sponsor_depth=depth
    )
    pair = validate_mirrored_covenant_pair(
        *scripts, subject_pubkey=child,
        allowed_delta_profiles=(CovenantDeltaProfile.LEGACY_777,)
    )
    reg = create_trusted_covenant_registration(
        pair,
        (
            RegisteredCovenantOutpoint(
                CovenantDirection.INCOMING, LATE_TX, 1, 50000, pair.incoming_leg_script_sha256
            ),
            RegisteredCovenantOutpoint(
                CovenantDirection.OUTGOING, EARLY_TX, 0, 50000, pair.outgoing_leg_script_sha256
            ),
        ),
        registration_id=ID1 if depth == 0 else ID2,
        lifecycle_state=TrustedCovenantRegistrationLifecycle.ACTIVE,
        registered_at=at,
        lifecycle_changed_at=at,
    )
    funding = create_canonical_covenant_funding_set(
        funding_set_id=FUND1 if depth == 0 else FUND2,
        trusted_registration=reg,
        lifecycle_state=CovenantFundingSetLifecycle.EFFECTIVE,
        created_at=at,
        lifecycle_changed_at=at,
        effective_at=at,
        recognized_outpoints=tuple(
            RecognizedCovenantFundingOutpoint(
                x.direction, x.txid, x.vout, x.amount_sats,
                x.witness_script_sha256, x.descriptor_sha256
            ) for x in reg.outpoints
        ),
    )
    rpc = StubRpc(*scripts)
    from app.services.trusted_covenant_registration import trusted_outpoints_from_registration
    snapshot = TrustedBitcoinCovenantObservationAdapter(rpc, clock=lambda: at).observe(
        trusted_outpoints_from_registration(reg)
    )
    return policy, reg, funding, snapshot, rpc


def _make(*, sources=None, basis=None, depth=0, at=NOW):
    if sources is None:
        sources = _sources(depth=depth, at=at)
    policy, reg, funding, snapshot, _ = sources
    if basis is None:
        basis = _genesis()
    proposal = create_canonical_admission_proposal_v2(
        proposal_id=PROPOSAL1 if depth == 0 else PROPOSAL2,
        proposed_at=at,
        script_evidence=policy,
        registration=reg,
        funding_set=funding,
        sponsor_basis=basis,
        observation=snapshot,
        sponsor_import_event_sha256="1" * 64,
        sponsor_key_proof_reference_sha256="2" * 64,
        child_acceptance_reference_sha256="3" * 64,
    )
    return proposal, sources, basis


def _validate(proposal, sources, basis, *, now=NOW):
    _, reg, funding, snapshot, _ = sources
    return validate_canonical_admission_proposal_v2_sources(
        proposal, registration=reg, funding_set=funding,
        sponsor_basis=basis, observation=snapshot, now=now
    )


def test_real_alice_bob_scripts_bind_to_two_exact_50k_outputs_without_full():
    proposal, sources, basis = _make()
    assert proposal.schema == SCHEMA
    assert proposal.version == VERSION
    assert proposal.authorization_boundary == BOUNDARY
    assert proposal.basis_kind is SponsorBasisV2.GENESIS
    assert proposal.script_evidence.child_compressed_pubkey == BOB
    assert proposal.script_evidence.earlier_raw_script_hex == DEMO_EARLY
    assert proposal.script_evidence.later_raw_script_hex == DEMO_LATE
    assert proposal.outpoints[0].direction is CovenantDirection.OUTGOING
    assert proposal.outpoints[1].direction is CovenantDirection.INCOMING
    assert (proposal.outpoints[0].txid, proposal.outpoints[1].txid) == (EARLY_TX, LATE_TX)
    assert proposal.mirror_sats_per_leg == 50000
    assert not proposal.grants_full and not proposal.is_effective
    assert _validate(proposal, sources, basis) == proposal
    assert set(sources[-1].calls) == {
        (EARLY_TX, 0, False), (LATE_TX, 1, False)
    }


def test_snapshot_digest_and_canonical_serialization_are_stable():
    proposal, _, _ = _make()
    payload = canonical_admission_proposal_v2_bytes(proposal)
    assert payload == canonical_admission_proposal_v2_bytes(proposal)
    assert canonical_admission_proposal_v2_sha256(proposal) == hashlib.sha256(payload).hexdigest()
    parsed = json.loads(payload)
    assert parsed["outpoints"][0]["direction"] == "outgoing"
    assert parsed["outpoints"][1]["direction"] == "incoming"
    assert parsed["script_evidence"]["child_depth"] == 1
    assert parsed["authorization_boundary"] == BOUNDARY


def test_bob_is_structurally_a_depth_one_sponsor_of_charlie_with_parent_link():
    parent, _, _ = _make()
    child_sources = _sources(sponsor=BOB, child=CHARLIE, depth=1)
    child, _, _ = _make(sources=child_sources, basis=parent, depth=1)
    assert child.basis_kind is SponsorBasisV2.PARENT_PROPOSAL
    assert child.basis_record_id == parent.proposal_id
    assert child.basis_record_sha256 == canonical_admission_proposal_v2_sha256(parent)
    assert child.script_evidence.sponsor_compressed_pubkey == BOB
    assert child.script_evidence.child_compressed_pubkey == CHARLIE
    assert child.script_evidence.child_depth == 2
    assert not child.grants_full
    assert _validate(child, child_sources, parent) == child


def test_a_proposal_is_not_authority_even_with_supplied_receipt_digests():
    parent, _, _ = _make()
    assert parent.grants_full is False
    assert parent.is_effective is False
    assert parent.sponsor_key_proof_reference_sha256 == "2" * 64
    assert parent.child_acceptance_reference_sha256 == "3" * 64


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "hodlxxi.canonical_admission_edge.v1"),
        ("version", "v1"),
        ("authorization_boundary", "grants_full"),
        ("registration_sha256", "0" * 64),
        ("funding_set_sha256", "0" * 64),
        ("observation_sha256", "0" * 64),
        ("basis_record_sha256", "0" * 64),
        ("mirror_sats_per_leg", 49999),
        ("observed_block_height", -1),
        ("proposal_id", "bad"),
        ("child_acceptance_reference_sha256", "2" * 64),
    ],
)
def test_tampering_metadata_fails_closed_or_breaks_source_binding(field, value):
    proposal, sources, basis = _make()
    try:
        mutated = replace(proposal, **{field: value})
    except InvalidCanonicalAdmissionProposalV2:
        return
    with pytest.raises(InvalidCanonicalAdmissionProposalV2):
        _validate(mutated, sources, basis)


def test_revoked_registration_and_funding_are_rejected():
    proposal, sources, basis = _make()
    _, reg, funding, snapshot, rpc = sources
    revoked = replace(reg, lifecycle_state=TrustedCovenantRegistrationLifecycle.REVOKED)
    with pytest.raises(InvalidCanonicalAdmissionProposalV2):
        _validate(proposal, (sources[0], revoked, funding, snapshot, rpc), basis)
    revfund = replace(funding, lifecycle_state=CovenantFundingSetLifecycle.REVOKED)
    with pytest.raises(InvalidCanonicalAdmissionProposalV2):
        _validate(proposal, (sources[0], reg, revfund, snapshot, rpc), basis)


def test_missing_spent_unconfirmed_or_wrong_utxo_binding_fails_closed():
    proposal, sources, basis = _make()
    policy, reg, funding, snapshot, rpc = sources
    original = snapshot.observations[0]
    for updated in (
        replace(original, unspent=False),
        replace(original, confirmations=0),
        replace(original, txid="c" * 64),
        replace(original, amount_sats=49999),
        replace(original, script_sha256="0" * 64),
    ):
        changed = replace(snapshot, observations=(updated, snapshot.observations[1]))
        with pytest.raises(InvalidCanonicalAdmissionProposalV2):
            _validate(proposal, (policy, reg, funding, changed, rpc), basis)


def test_expired_or_future_snapshot_is_rejected():
    proposal, sources, basis = _make()
    with pytest.raises(InvalidCanonicalAdmissionProposalV2, match="observation_missing_or_stale"):
        _validate(proposal, sources, basis, now=NOW + timedelta(seconds=121))
    with pytest.raises(InvalidCanonicalAdmissionProposalV2, match="observation_missing_or_stale"):
        _validate(proposal, sources, basis, now=NOW - timedelta(seconds=1))


def test_extraneous_recognized_outpoint_is_not_a_two_leg_admission():
    proposal, sources, basis = _make()
    policy, reg, funding, snapshot, rpc = sources
    extra = replace(
        funding.recognized_outpoints[0], txid="c" * 64, vout=2
    )
    amended = replace(
        funding, recognized_outpoints=funding.recognized_outpoints + (extra,)
    )
    with pytest.raises(InvalidCanonicalAdmissionProposalV2, match="funding_set_not_exact_two"):
        _validate(proposal, (policy, reg, amended, snapshot, rpc), basis)


def test_wrong_current_sponsor_parent_or_depth_cannot_be_substituted():
    parent, _, genesis = _make()
    child_sources = _sources(sponsor=BOB, child=CHARLIE, depth=1)
    child, _, _ = _make(sources=child_sources, basis=parent, depth=1)
    with pytest.raises(InvalidCanonicalAdmissionProposalV2):
        _validate(child, child_sources, genesis)
    forged_parent = replace(parent, proposal_id=PROPOSAL2)
    with pytest.raises(InvalidCanonicalAdmissionProposalV2):
        _validate(child, child_sources, forged_parent)


def test_separately_forged_proof_references_never_elevate_rights():
    proposal, sources, basis = _make()
    changed = replace(proposal, child_acceptance_reference_sha256="4" * 64)
    assert changed.grants_full is False
    assert changed.is_effective is False
    assert _validate(changed, sources, basis) == changed


def test_malformed_script_source_cannot_be_reframed_as_proposal():
    proposal, _, _ = _make()
    with pytest.raises(InvalidCanonicalAdmissionProposalV2):
        replace(proposal, script_evidence=replace(
            proposal.script_evidence, earlier_raw_script_hex="00"
        ))


def test_wrong_source_owner_does_not_pass_registration_binding():
    proposal, sources, basis = _make()
    different = _sources(sponsor=BOB, child=CHARLIE, depth=1)
    with pytest.raises(InvalidCanonicalAdmissionProposalV2):
        _validate(proposal, different, basis)


def test_untrusted_proposal_object_cannot_be_hashed_as_canonical_v2_record():
    with pytest.raises(InvalidCanonicalAdmissionProposalV2):
        canonical_admission_proposal_v2_bytes({"untrusted": True})
