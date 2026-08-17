"""Genuine in-memory PR6.17 -> PR6.18 -> PR6.19 composition; no DB or real RPC."""

from datetime import timedelta

from app.services.hodlxxi_v1_snapshot_proof_composition import (
    HodlxxiV1SnapshotProofCompositionRequest,
    compose_hodlxxi_v1_snapshot_authorization_proof,
)
from app.services.trusted_crt_bitcoin_observation_snapshot import TrustedCrtBitcoinObservationSnapshotAdapter
from tests.unit.test_trusted_crt_bitcoin_observation_snapshot import Clock, NOW, RPC, plan


def test_depth_three_genuine_in_memory_composition():
    source_plan = plan(3)
    resolution = TrustedCrtBitcoinObservationSnapshotAdapter(rpc=RPC(source_plan), clock=Clock()).observe(
        source_plan=source_plan
    )
    result = compose_hodlxxi_v1_snapshot_authorization_proof(
        HodlxxiV1SnapshotProofCompositionRequest(
            source_plan, resolution, NOW + timedelta(seconds=2), NOW + timedelta(minutes=5)
        )
    )
    assert result.depth == 3
    assert len(result.edge_evidence) == 3
    assert result.authorization_proof.current_full_membership_satisfied is True
