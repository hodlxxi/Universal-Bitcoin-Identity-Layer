from pathlib import Path

DOC = Path(__file__).parents[2] / "docs/TRUSTED_COVENANT_OBSERVATION_V1.md"


def test_documentation_contains_required_contract_and_safety_terms():
    text = " ".join(DOC.read_text().split())
    required = (
        "exact-outpoint trust model",
        "hodlxxi.trusted_covenant_outpoint.v1",
        "hodlxxi.trusted_covenant_observation_adapter.v1",
        "hodlxxi.covenant_entitlement_materializer.v1",
        "wallet-wide scanning is forbidden",
        "Alice incoming + Bob outgoing != FULL",
        "gettxout(txid, vout, include_mempool=False)",
        "positional `False`",
        "not currently present in the queried UTXO set",
        "same-height reorganization",
        "unfunded_declared",
        "FULL",
        "LIMITED",
        "300 seconds",
        "60 seconds",
        "5 seconds",
        "created_at = max(materializer clock, observed_at)",
        "do not grant FULL before `observed_at`",
        "Future trusted-outpoint registration",
        "Future production entitlement-resolver wiring also remains outside this PR",
        "dormant",
    )
    assert not [term for term in required if term not in text]
    assert "whether, how, or when an output was spent" in text


def test_documentation_contains_every_required_non_claim():
    text = DOC.read_text()
    non_claims = (
        "discover covenant relationships",
        "prove legal or KYC identity",
        "prove private-key ownership",
        "prove key possession",
        "parse Bitcoin Script",
        "infer roles from OP_IF/OP_ELSE",
        "scan a wallet",
        "list wallet descriptors",
        "aggregate wallet balances",
        "query an explorer",
        "create a route or MCP tool",
        "automatically run a materializer",
        "wire the evidence resolver into production",
        "create, sign, fund, or broadcast transactions",
        "modify Bitcoin Core or its wallet",
        "apply a migration",
        "deploy or restart anything",
    )
    assert not [claim for claim in non_claims if claim not in text]
