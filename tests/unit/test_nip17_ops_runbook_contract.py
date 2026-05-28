"""NIP-17 ops runbook contract tests."""

from pathlib import Path


def test_nip17_staging_runbook_documents_required_safety_gates():
    text = Path("docs/ops/NIP17_MESSAGING_STACK_STAGING_RUNBOOK.md").read_text(encoding="utf-8").lower()

    required = [
        "nip17_messages_enabled=false",
        "nip17_messages_enabled=true",
        "migrations/2026-05-28_nip17_envelopes.sql",
        "must never require custody of user private keys",
        "kind 1059",
        "kind 14",
        "plaintext",
        "rollback",
        "staging only",
        "production rollout gate",
        "sqlite",
        "postgresql",
        "sqlalchemy model",
        "checkfirst=true",
        "table_ok=true",
    ]

    for needle in required:
        assert needle in text
