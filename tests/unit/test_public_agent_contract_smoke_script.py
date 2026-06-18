from __future__ import annotations

import os
from pathlib import Path

SCRIPT = Path("scripts/smoke_public_agent_contract.sh")
DOC = Path("docs/ops/PUBLIC_AGENT_CONTRACT_SMOKE.md")


def test_public_agent_contract_smoke_script_exists_and_is_executable():
    assert SCRIPT.exists()
    assert os.access(SCRIPT, os.X_OK)


def test_public_agent_contract_smoke_script_contract_markers():
    text = SCRIPT.read_text(encoding="utf-8")

    for marker in [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        'BASE="${BASE:-https://hodlxxi.com}"',
        "need curl",
        "need jq",
        "/.well-known/hodlxxi-operator.json",
        "hodlxxi.operator_continuity.v1",
        "operator_id",
        "E923",
        "key_status",
        "declared_unfunded",
        "time_locked_capital_proof_exposed",
        "scripts/verify_operator_continuity.sh",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
        "/.well-known/nostr-dm-policy.json",
        "/agent/readiness/self-scan",
        "hodlxxi.agent_readiness_report.v1",
        "runtime_ready",
        "key_custody",
        "server_plaintext_storage",
        "relay_publishing",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "authorization_servers",
        "/agent/request",
        "public agent contract smoke unpaid verifier",
        "payment_hash_present",
        "invoice_present",
        "/agent/jobs/$job_id",
        "/agent/verify/$job_id",
        "no_receipt",
        "receipt_not_issued",
        "00000000-0000-0000-0000-000000000000",
        "PASS: public agent contract smoke succeeded",
    ]:
        assert marker in text


def test_public_agent_contract_smoke_script_has_no_obvious_secret_markers():
    text = SCRIPT.read_text(encoding="utf-8").lower()

    forbidden = [
        "macaroon=",
        "private_key=",
        "seed phrase",
        "xprv",
        "lnd_password",
        "node_credentials",
        "dotenv",
        ".env",
    ]
    for marker in forbidden:
        assert marker not in text


def test_public_agent_contract_smoke_docs_explain_safe_operation():
    text = DOC.read_text(encoding="utf-8")
    lower = text.lower()

    assert "BASE=https://hodlxxi.com bash scripts/smoke_public_agent_contract.sh" in text
    assert "public-only" in lower
    assert "secret-free" in lower
    assert "creates one unpaid" in lower
    assert "does not pay" in lower
    assert "must not print invoice strings" in lower
    assert "PASS: public agent contract smoke succeeded" in text

    for non_proof in [
        "locked capital",
        "paid job completion",
        "private key custody",
        "legal identity",
    ]:
        assert non_proof in lower
