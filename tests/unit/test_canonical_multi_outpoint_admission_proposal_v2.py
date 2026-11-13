"""Proposed-only multi-output intent: all UTXOs bound into two signatures."""

import json
from dataclasses import replace
from datetime import timedelta

import pytest

from app.services.canonical_admission_consent_v2 import (
    CanonicalAdmissionConsentVerifierUnavailable,
    canonical_admission_consent_message_v2,
)
from app.services.canonical_multi_outpoint_admission_proposal_v2 import (
    BOUNDARY,
    SCHEMA,
    CanonicalMultiOutpointAdmissionProposalV2,
    InvalidCanonicalMultiAdmissionProposalV2,
    canonical_multi_outpoint_admission_proposal_v2_bytes,
    canonical_multi_outpoint_admission_proposal_v2_sha256,
    create_canonical_multi_outpoint_admission_proposal_v2,
    issue_multi_outpoint_admission_challenge_v2,
    validate_canonical_multi_outpoint_admission_proposal_v2_sources,
    verify_multi_outpoint_admission_signatures_v2,
)
from app.services.canonical_multi_outpoint_mirror_v2 import (
    create_canonical_multi_outpoint_mirror_v2,
)
from app.utils import derive_legacy_address_from_pubkey
from tests.unit.test_canonical_admission_consent_v2 import CHILD_SIG, SPONSOR_SIG, StrictRpc
from tests.unit.test_canonical_admission_proposal_v2 import (
    ALICE,
    BOB,
    CHARLIE,
    NOW,
    _genesis,
    _make,
    _sources,
)
from tests.unit.test_canonical_multi_outpoint_mirror_v2 import _bundle, _observation

ROOT_ID = "00000000-0000-4000-8000-000000000051"
CHILD_ID = "00000000-0000-4000-8000-000000000052"


def _new(mirror=None, *, basis=None, proposal_id=ROOT_ID, observation=None):
    mirror = _bundle() if mirror is None else mirror
    observation = _observation(mirror) if observation is None else observation
    basis = _genesis() if basis is None else basis
    return create_canonical_multi_outpoint_admission_proposal_v2(
        proposal_id=proposal_id,
        proposed_at=NOW,
        mirror=mirror,
        observation=observation,
        sponsor_basis=basis,
        sponsor_import_reference_sha256="1" * 64,
        sponsor_key_proof_reference_sha256="2" * 64,
        child_acceptance_reference_sha256="3" * 64,
    )


def _rpc(proposal, challenge):
    evidence = proposal.mirror.script_evidence
    sponsor = (
        derive_legacy_address_from_pubkey(evidence.sponsor_compressed_pubkey),
        SPONSOR_SIG,
        canonical_admission_consent_message_v2(challenge, role="sponsor"),
    )
    child = (
        derive_legacy_address_from_pubkey(evidence.child_compressed_pubkey),
        CHILD_SIG,
        canonical_admission_consent_message_v2(challenge, role="child"),
    )
    return StrictRpc((sponsor, child))


def _verify(proposal, challenge, rpc, *, sponsor_signature=SPONSOR_SIG, child_signature=CHILD_SIG, at=NOW):
    return verify_multi_outpoint_admission_signatures_v2(
        proposal,
        challenge,
        sponsor_signature=sponsor_signature,
        child_signature=child_signature,
        rpc=rpc,
        now=at,
    )


def test_three_plus_two_actual_funding_bound_into_exact_proposal_digest():
    proposal = _new()
    assert proposal.schema == SCHEMA
    assert proposal.authorization_boundary == BOUNDARY
    assert len(proposal.mirror.outpoints) == 5
    assert proposal.snapshot.earlier_sats == 300000
    assert proposal.snapshot.later_sats == 300000
    assert proposal.snapshot.trust_ceiling_sats == 300000
    assert not proposal.grants_full and not proposal.is_effective
    payload = json.loads(canonical_multi_outpoint_admission_proposal_v2_bytes(proposal))
    assert len(payload["mirror"]["outpoints"]) == 5
    assert payload["snapshot"]["trust_ceiling_sats"] == 300000
    assert payload["basis_kind"] == "genesis_record"
    digest = canonical_multi_outpoint_admission_proposal_v2_sha256(proposal)
    assert len(digest) == 64
    assert digest != proposal.mirror_sha256
    assert (
        validate_canonical_multi_outpoint_admission_proposal_v2_sources(
            proposal, mirror=proposal.mirror, observation=_observation(proposal.mirror),
            sponsor_basis=_genesis(), now=NOW
        )
        == proposal
    )


def test_signed_sponsor_and_child_both_commit_all_five_outputs():
    proposal = _new()
    challenge = issue_multi_outpoint_admission_challenge_v2(proposal, now=NOW)
    assert not challenge.is_trusted_issuance
    digest = canonical_multi_outpoint_admission_proposal_v2_sha256(proposal)
    assert challenge.proposal_sha256 == digest
    rpc = _rpc(proposal, challenge)
    proof = _verify(proposal, challenge, rpc)
    assert len(rpc.calls) == 2
    assert proof.proposal_sha256 == digest
    assert proof.sponsor_message_sha256 != proof.child_message_sha256
    assert proof.sponsor_signature_sha256 != proof.child_signature_sha256
    assert not proof.grants_full and not proof.replay_protected


def test_changing_one_of_five_amounts_changes_signed_proposal_digest():
    proposal = _new()
    old_challenge = issue_multi_outpoint_admission_challenge_v2(proposal, now=NOW)
    rpc = _rpc(proposal, old_challenge)
    changed_output = replace(proposal.mirror.outpoints[0], amount_sats=proposal.mirror.outpoints[0].amount_sats + 1)
    changed_mirror = replace(
        proposal.mirror,
        outpoints=(changed_output, *proposal.mirror.outpoints[1:]),
    )
    revised = _new(changed_mirror, observation=_observation(changed_mirror))
    assert canonical_multi_outpoint_admission_proposal_v2_sha256(proposal) != (
        canonical_multi_outpoint_admission_proposal_v2_sha256(revised)
    )
    with pytest.raises(InvalidCanonicalMultiAdmissionProposalV2, match="signed_proposal_or_keys_mismatch"):
        _verify(revised, old_challenge, rpc)
    assert rpc.calls == []


@pytest.mark.parametrize(
    "old,new",
    [
        ("sponsor_import_reference_sha256", "4" * 64),
        ("sponsor_key_proof_reference_sha256", "5" * 64),
        ("child_acceptance_reference_sha256", "6" * 64),
        ("proposal_id", CHILD_ID),
    ],
)
def test_proposal_context_is_part_of_both_signatures(old, new):
    proposal = _new()
    challenge = issue_multi_outpoint_admission_challenge_v2(proposal, now=NOW)
    changed = replace(proposal, **{old: new})
    with pytest.raises(InvalidCanonicalMultiAdmissionProposalV2, match="signed_proposal_or_keys_mismatch"):
        _verify(changed, challenge, _rpc(proposal, challenge))


def test_role_swap_absent_and_invalid_signatures_are_rejected():
    proposal = _new()
    challenge = issue_multi_outpoint_admission_challenge_v2(proposal, now=NOW)
    rpc = _rpc(proposal, challenge)
    with pytest.raises(InvalidCanonicalMultiAdmissionProposalV2):
        _verify(proposal, challenge, rpc, sponsor_signature=CHILD_SIG, child_signature=SPONSOR_SIG)
    with pytest.raises(InvalidCanonicalMultiAdmissionProposalV2, match="same_signature_for_two_roles"):
        _verify(proposal, challenge, rpc, child_signature=SPONSOR_SIG)
    with pytest.raises(InvalidCanonicalMultiAdmissionProposalV2, match="signature_shape"):
        _verify(proposal, challenge, rpc, child_signature="")


def test_no_rpc_accepted_for_missing_server_or_false_or_non_boolean():
    proposal = _new()
    challenge = issue_multi_outpoint_admission_challenge_v2(proposal, now=NOW)
    with pytest.raises(CanonicalAdmissionConsentVerifierUnavailable):
        _verify(proposal, challenge, object())

    class WrongRpc:
        def verifymessage(self, *args):
            return 1

    with pytest.raises(CanonicalAdmissionConsentVerifierUnavailable, match="not_boolean"):
        _verify(proposal, challenge, WrongRpc())
    with pytest.raises(InvalidCanonicalMultiAdmissionProposalV2, match="signer_rejected"):
        _verify(proposal, challenge, StrictRpc(()))


def test_expired_or_future_challenge_fails_before_any_verification():
    proposal = _new()
    challenge = issue_multi_outpoint_admission_challenge_v2(proposal, now=NOW)
    rpc = _rpc(proposal, challenge)
    for at in (NOW - timedelta(seconds=1), NOW + timedelta(seconds=300)):
        with pytest.raises(InvalidCanonicalMultiAdmissionProposalV2, match="expired_or_unissued"):
            _verify(proposal, challenge, rpc, at=at)
    assert not rpc.calls


def test_two_issues_of_same_proposal_get_distinct_random_nonces():
    proposal = _new()
    a = issue_multi_outpoint_admission_challenge_v2(proposal, now=NOW)
    b = issue_multi_outpoint_admission_challenge_v2(proposal, now=NOW)
    assert a.nonce_hex != b.nonce_hex
    assert canonical_admission_consent_message_v2(a, role="sponsor") != (
        canonical_admission_consent_message_v2(b, role="sponsor")
    )


def test_stale_spent_or_forged_current_observation_not_a_valid_proposal_source():
    proposal = _new()
    observation = _observation(proposal.mirror)
    tampered = replace(
        observation,
        observations=(
            replace(observation.observations[0], unspent=False),
            *observation.observations[1:],
        ),
    )
    with pytest.raises(Exception):
        validate_canonical_multi_outpoint_admission_proposal_v2_sources(
            proposal, mirror=proposal.mirror, observation=tampered,
            sponsor_basis=_genesis(), now=NOW
        )
    with pytest.raises(Exception):
        validate_canonical_multi_outpoint_admission_proposal_v2_sources(
            proposal, mirror=proposal.mirror, observation=observation,
            sponsor_basis=_genesis(), now=NOW + timedelta(seconds=121)
        )


def test_parent_multi_proposal_allows_bob_to_sponsor_charlie_structurally():
    parent = _new()
    policy, registration, _, observation, _ = _sources(
        sponsor=BOB, child=CHARLIE, depth=1
    )
    from app.services.trusted_covenant_registration import trusted_outpoints_from_registration

    mirror = create_canonical_multi_outpoint_mirror_v2(
        policy, trusted_outpoints_from_registration(registration)
    )
    child = _new(
        mirror,
        basis=parent,
        proposal_id=CHILD_ID,
        observation=observation,
    )
    assert child.basis_record_id == parent.proposal_id
    assert child.basis_record_sha256 == canonical_multi_outpoint_admission_proposal_v2_sha256(parent)
    assert child.mirror.script_evidence.child_depth == 2
    assert child.mirror.script_evidence.sponsor_compressed_pubkey == BOB
    assert not child.grants_full and not child.is_effective


def test_existing_strict_v2_parent_may_be_referenced_without_rewriting_it():
    legacy, _, _ = _make()
    policy, registration, _, observation, _ = _sources(
        sponsor=BOB, child=CHARLIE, depth=1
    )
    from app.services.trusted_covenant_registration import trusted_outpoints_from_registration

    mirror = create_canonical_multi_outpoint_mirror_v2(
        policy, trusted_outpoints_from_registration(registration)
    )
    proposal = _new(mirror, basis=legacy, proposal_id=CHILD_ID, observation=observation)
    assert proposal.basis_record_id == legacy.proposal_id
    assert proposal.mirror.script_evidence.child_depth == 2
    assert not proposal.grants_full


def test_wrong_parent_or_root_cannot_be_spliced_into_multileg_proposal():
    mirror = _bundle()
    strict_parent, _, _ = _make()
    with pytest.raises(InvalidCanonicalMultiAdmissionProposalV2, match="root_basis_type"):
        _new(mirror, basis=strict_parent)
    policy, reg, _, obs, _ = _sources(sponsor=BOB, child=CHARLIE, depth=1)
    from app.services.trusted_covenant_registration import trusted_outpoints_from_registration

    child_mirror = create_canonical_multi_outpoint_mirror_v2(
        policy, trusted_outpoints_from_registration(reg)
    )
    with pytest.raises(InvalidCanonicalMultiAdmissionProposalV2, match="parent_proposal_type"):
        _new(child_mirror, basis=_genesis(), proposal_id=CHILD_ID, observation=obs)


def test_malformed_proposal_types_and_detached_fields_fail_closed():
    proposal = _new()
    with pytest.raises(InvalidCanonicalMultiAdmissionProposalV2, match="proposal_type"):
        canonical_multi_outpoint_admission_proposal_v2_bytes({"proposal": proposal})
    with pytest.raises(InvalidCanonicalMultiAdmissionProposalV2, match="snapshot_mirror_or_basis_binding"):
        replace(proposal, mirror_sha256="0" * 64)
    with pytest.raises(InvalidCanonicalMultiAdmissionProposalV2, match="schema_or_boundary"):
        replace(proposal, authorization_boundary="grants_full")
    with pytest.raises(InvalidCanonicalMultiAdmissionProposalV2):
        replace(proposal, sponsor_import_reference_sha256="2" * 64)
