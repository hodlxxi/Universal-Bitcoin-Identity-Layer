"""Issue #588: signed historic N+M intent vs a later fresh Core scan.

Offline observation fixtures are NOT trusted live Bitcoin evidence. These
pure tests do not establish signer sessions, EFFECTIVE admission or Full.
"""

from dataclasses import replace
from datetime import timedelta

import pytest

from app.services.canonical_multi_outpoint_admission_proposal_v2 import (
    InvalidCanonicalMultiAdmissionProposalV2,
    canonical_multi_outpoint_admission_proposal_v2_sha256,
    issue_multi_outpoint_admission_challenge_v2,
    validate_canonical_multi_outpoint_admission_fresh_sources_v2,
    validate_canonical_multi_outpoint_admission_proposal_v2_sources,
    verify_multi_outpoint_admission_signatures_v2,
)
from tests.unit.test_canonical_admission_consent_v2 import CHILD_SIG, SPONSOR_SIG
from tests.unit.test_canonical_admission_proposal_v2 import NOW, _genesis
from tests.unit.test_canonical_multi_outpoint_admission_proposal_v2 import _new, _rpc
from tests.unit.test_canonical_multi_outpoint_mirror_v2 import _observation


def _fresh(proposal, *, seconds=45):
    at = NOW + timedelta(seconds=seconds)
    return _observation(proposal.mirror, observed_at=at), at


def test_signed_proposal_digest_remains_fixed_but_fresh_scan_is_new():
    proposal = _new()
    original_digest = canonical_multi_outpoint_admission_proposal_v2_sha256(proposal)
    observation, at = _fresh(proposal)
    with pytest.raises(InvalidCanonicalMultiAdmissionProposalV2, match="source_or_parent_mismatch"):
        validate_canonical_multi_outpoint_admission_proposal_v2_sources(
            proposal, mirror=proposal.mirror, observation=observation, sponsor_basis=_genesis(), now=at
        )
    latest = validate_canonical_multi_outpoint_admission_fresh_sources_v2(
        proposal, sponsor_basis=_genesis(), fresh_observation=observation, now=at
    )
    assert latest.observed_at == at
    assert latest.observation_sha256 != proposal.snapshot.observation_sha256
    assert latest.trust_ceiling_sats == proposal.snapshot.trust_ceiling_sats == 300000
    assert latest.outpoint_count == 5
    assert canonical_multi_outpoint_admission_proposal_v2_sha256(proposal) == original_digest


def test_original_role_separated_signatures_cover_intent_after_new_scan():
    proposal = _new()
    observation, at = _fresh(proposal)
    latest = validate_canonical_multi_outpoint_admission_fresh_sources_v2(
        proposal, sponsor_basis=_genesis(), fresh_observation=observation, now=at
    )
    nonce = issue_multi_outpoint_admission_challenge_v2(proposal, now=NOW)
    verified = verify_multi_outpoint_admission_signatures_v2(
        proposal,
        nonce,
        sponsor_signature=SPONSOR_SIG,
        child_signature=CHILD_SIG,
        rpc=_rpc(proposal, nonce),
        now=at,
    )
    assert verified.proposal_sha256 == canonical_multi_outpoint_admission_proposal_v2_sha256(proposal)
    assert latest.observation_sha256 != proposal.snapshot.observation_sha256
    assert not verified.grants_full


@pytest.mark.parametrize("field", ("amount", "script", "spent", "unconfirmed", "txid"))
def test_forged_or_spent_outpoint_does_not_pass_revalidation(field):
    proposal = _new()
    observation, at = _fresh(proposal)
    outpoint = observation.observations[0]
    changes = {
        "amount": {"amount_sats": outpoint.amount_sats + 1},
        "script": {"script_sha256": "a" * 64},
        "spent": {"unspent": False},
        "unconfirmed": {"confirmations": 0},
        "txid": {"txid": "d" * 64},
    }
    tampered = replace(
        observation, observations=(replace(outpoint, **changes[field]), *observation.observations[1:])
    )
    with pytest.raises(Exception):
        validate_canonical_multi_outpoint_admission_fresh_sources_v2(
            proposal, sponsor_basis=_genesis(), fresh_observation=tampered, now=at
        )


@pytest.mark.parametrize("seconds", (-1, 300, 301))
def test_early_or_expired_candidate_does_not_accept_late_scan(seconds):
    proposal = _new()
    observation, at = _fresh(proposal, seconds=seconds)
    with pytest.raises(InvalidCanonicalMultiAdmissionProposalV2):
        validate_canonical_multi_outpoint_admission_fresh_sources_v2(
            proposal, sponsor_basis=_genesis(), fresh_observation=observation, now=at
        )


def test_revalidation_requires_observation_within_thirty_seconds():
    proposal = _new()
    observation, at = _fresh(proposal, seconds=40)
    with pytest.raises(InvalidCanonicalMultiAdmissionProposalV2, match="fresh_signed_funding_or_basis_mismatch"):
        validate_canonical_multi_outpoint_admission_fresh_sources_v2(
            proposal,
            sponsor_basis=_genesis(),
            fresh_observation=observation,
            now=at + timedelta(seconds=31),
        )


def test_wrong_genesis_source_cannot_be_replaced_after_signing():
    proposal = _new()
    observation, at = _fresh(proposal)
    with pytest.raises(Exception):
        validate_canonical_multi_outpoint_admission_fresh_sources_v2(
            proposal, sponsor_basis=object(), fresh_observation=observation, now=at
        )


def test_reorg_or_earlier_block_height_is_denied():
    proposal = _new()
    observation, at = _fresh(proposal)
    moved = replace(observation, observed_block_height=proposal.snapshot.observed_block_height - 1)
    with pytest.raises(InvalidCanonicalMultiAdmissionProposalV2):
        validate_canonical_multi_outpoint_admission_fresh_sources_v2(
            proposal, sponsor_basis=_genesis(), fresh_observation=moved, now=at
        )
