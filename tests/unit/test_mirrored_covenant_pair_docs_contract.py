from pathlib import Path

DOC = Path(__file__).parents[2] / "docs/MIRRORED_COVENANT_PAIR_V1.md"


def test_documented_contract_and_boundaries():
    text = DOC.read_text()
    required = (
        "hodlxxi.mirrored_covenant_leg.v1",
        "hodlxxi.mirrored_covenant_pair.v1",
        "hodlxxi.mirrored_covenant_pair_validator.v1",
        "current_144",
        "legacy_777",
        "cltv_only",
        "cooperative_2_of_2_cltv",
        "Lock heights 1–16 use `OP_1`–`OP_16`",
        "minimally encoded positive",
        "zero and negative ScriptNums are invalid lock heights",
        "shared middle height",
        "Alice incoming + Bob outgoing is not FULL",
        "one leg, not a pair",
        "unfunded declaration is not funding",
        "Script validation is not UTXO observation",
        "pair validation is not entitlement",
        "Raw Script hex is the authoritative source",
        "cannot be supplied independently",
        "direct leg and pair dataclass construction is",
        "canonical pair bytes are produced only after",
        "future PR6.8",
        "outpoint binding",
        "does not",
        "grant FULL access",
        "deploy, migrate, restart",
    )
    assert not [term for term in required if term not in text]
