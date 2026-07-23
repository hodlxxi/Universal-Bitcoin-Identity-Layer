from pathlib import Path

DOC = Path(__file__).parents[2] / "docs/CANONICAL_COVENANT_RELATION_V1.md"


def test_documentation_contains_contract_terms_and_boundaries():
    text = DOC.read_text()
    required = (
        "hodlxxi.covenant_relation_observation.v1",
        "hodlxxi.covenant_relation_evaluation.v1",
        "hodlxxi.covenant_relation_decision.v1",
        "exact pair",
        "Alice incoming + Bob outgoing != FULL",
        "one-confirmation",
        "integer satoshi",
        "dormant",
        "future trusted observation adapter",
        "future entitlement materializer",
        "unfunded_declared",
    )
    assert not [term for term in required if term not in text]


def test_documentation_contains_every_required_non_claim():
    text = DOC.read_text()
    non_claims = (
        "establish KYC or legal identity",
        "establish key possession",
        "establish private-key ownership",
        "prove descriptor ownership",
        "prove a raw descriptor is valid",
        "parse Bitcoin Script",
        "infer participant roles from OP_IF/OP_ELSE",
        "query Bitcoin Core",
        "query an explorer",
        "inspect a wallet",
        "verify a UTXO",
        "verify funding",
        "verify confirmations",
        "write entitlement evidence",
        "grant FULL access",
        "expose a public route or MCP tool",
        "create, sign, fund, or broadcast a transaction",
        "apply a migration",
        "deploy or restart anything",
    )
    assert not [claim for claim in non_claims if claim not in text]
