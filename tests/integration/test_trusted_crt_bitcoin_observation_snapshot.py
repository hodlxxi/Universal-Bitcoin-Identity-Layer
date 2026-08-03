"""In-memory composition of genuine PR6.17 sources with a fake read-only RPC."""

from app.services.trusted_crt_bitcoin_observation_snapshot import (
    TrustedCrtBitcoinObservationSnapshotAdapter,
    TrustedCrtBitcoinObservationState,
)
from tests.unit.test_trusted_crt_bitcoin_observation_snapshot import Clock, RPC, plan


def test_genuine_source_plan_composes_without_database_or_network():
    source_plan = plan(3)
    rpc = RPC(source_plan)
    result = TrustedCrtBitcoinObservationSnapshotAdapter(rpc=rpc, clock=Clock()).observe(
        source_plan=source_plan,
    )
    assert result.state is TrustedCrtBitcoinObservationState.OBSERVED
    assert tuple(item.depth for item in result.snapshot.observed_relations) == (1, 2, 3)
    assert result.snapshot.source_plan_manifest_sha256 == source_plan.manifest_sha256
