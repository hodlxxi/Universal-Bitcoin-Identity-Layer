"""Offline tests for the dormant signed alias-namespace transaction owner."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.schema import CreateTable

from app.services import social_messaging_active_alias_namespace_lifecycle as lifecycle
from app.services import social_messaging_active_alias_namespace_lifecycle_storage as writer
from app.services import social_messaging_active_alias_namespace_storage as namespace

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations/2026-09-25_social_messaging_active_alias_namespace_lifecycle_v1.sql"
EARLIER_NAMESPACE_MIGRATION = ROOT / "migrations/2026-09-24_social_messaging_active_alias_namespace_v1.sql"
EARLIER_ROUTING_MIGRATION = ROOT / "migrations/2026-09-24_social_messaging_recipient_routing_registry_v1.sql"
VECTORS_PATH = ROOT / "tests/fixtures/social_messaging_active_alias_namespace_lifecycle_v1.json"
VECTORS = json.loads(VECTORS_PATH.read_text(encoding="ascii"))
PUBLIC_KEY = bytes.fromhex(VECTORS["publicKey"])
KEY_ID = VECTORS["keyId"]
ALIAS_SECRET = bytes(range(32))
ROTATED_SECRET = bytes(reversed(range(32)))
FIXED_NOW = 1_800_000_030_000
DENIED = writer.AliasNamespaceLifecycleStorageUnavailable
ERROR = "^social messaging alias namespace lifecycle storage unavailable$"


def command(name):
    item = VECTORS[name]
    return item["commandWire"].encode("ascii"), item["signature"]


def authenticated_values(name, *, secret, version):
    wire, signature = command(name)
    verifier = lifecycle.PinnedOfflineAliasLifecycleVerifierV1(
        public_key=PUBLIC_KEY,
        key_id=KEY_ID,
    )
    return writer._command_values(
        verifier,
        wire,
        signature,
        now_ms=FIXED_NOW,
        configured_version=version,
        configured_commitment=namespace.active_alias_namespace_secret_commitment(
            alias_secret=secret,
            alias_version=version,
        ),
    )


def owner_shell(command_name="provision"):
    value = object.__new__(writer.SqlAlchemyTransactionBoundActiveAliasNamespaceLifecycleOwner)
    value._failed = False
    value._used = False
    parsed = lifecycle.parse_canonical_alias_lifecycle_command_v1(command(command_name)[0])
    return value, parsed


def test_fixed_signed_vectors_cross_writer_verifier_and_existing_commitment_identity():
    provision = authenticated_values("provision", secret=ALIAS_SECRET, version=1)
    rotate = authenticated_values("rotate", secret=ALIAS_SECRET, version=2)
    assert provision["commandId"] == VECTORS["provision"]["commandId"]
    assert rotate["commandId"] == VECTORS["rotate"]["commandId"]
    assert provision["successorCommitment"] == namespace.active_alias_namespace_secret_commitment(
        alias_secret=ALIAS_SECRET,
        alias_version=1,
    )
    assert rotate["successorCommitment"] == namespace.active_alias_namespace_secret_commitment(
        alias_secret=ALIAS_SECRET,
        alias_version=2,
    )


def test_writer_reverifies_raw_command_before_locks_after_advisory_wait_and_after_row_wait():
    owner, parsed = owner_shell()
    wire, signature = command("provision")
    calls = []

    def verify(candidate_wire, candidate_signature):
        assert candidate_wire == wire and candidate_signature == signature
        calls.append("verify")
        return dict(parsed)

    owner._verify_fresh = verify
    owner._lock_writer = lambda: calls.append("advisory")
    owner._lock_active_rows = lambda: calls.append("active") or []
    owner._classify_locked = lambda *_args: calls.append("classify") or "absent"
    owner._stage = lambda *_args: calls.append("stage")
    owner._check_staged_state = lambda *_args: calls.append("check")

    result = owner.execute(wire, signature)
    assert calls == [
        "verify",
        "advisory",
        "verify",
        "active",
        "verify",
        "classify",
        "stage",
        "verify",
        "check",
    ]
    assert result.outcome == "staged"
    assert result.publication_status == "provisional_until_caller_commit"


def test_exact_committed_retry_never_executes_a_second_transition():
    owner, parsed = owner_shell()
    wire, signature = command("provision")
    calls = []
    owner._verify_fresh = lambda *_args: dict(parsed)
    owner._lock_writer = lambda: calls.append("advisory")
    owner._lock_active_rows = lambda: calls.append("active") or [{"alias_version": 1}]
    owner._classify_locked = lambda *_args: calls.append("classify") or "committed"
    owner._stage = lambda *_args: pytest.fail("committed retry must not stage")
    owner._check_staged_state = lambda *_args: pytest.fail("committed retry must not recheck staging")

    result = owner.execute(wire, signature)
    assert calls == ["advisory", "active", "classify"]
    assert result.outcome == "committed"
    assert result.publication_status == "committed_evidence"


def test_uncertain_commit_reconciliation_distinguishes_absent_without_executing():
    owner, parsed = owner_shell()
    wire, signature = command("provision")
    calls = []
    owner._authenticate_for_reconciliation = lambda *_args: calls.append("authenticate") or dict(parsed)
    owner._lock_writer = lambda: calls.append("advisory")
    owner._lock_active_rows = lambda: calls.append("active") or []
    owner._classify_locked = lambda *_args: calls.append("classify") or "absent"
    owner._stage = lambda *_args: pytest.fail("reconciliation must never stage")

    result = owner.reconcile_uncertain_commit(wire, signature)
    assert calls == ["authenticate", "advisory", "authenticate", "active", "classify"]
    assert result.outcome == "absent"
    assert result.publication_status == "no_committed_evidence"


def test_failure_poisoning_and_one_shot_success_prevent_reuse():
    owner, _parsed = owner_shell()
    wire, signature = command("provision")
    owner._verify_fresh = lambda *_args: (_ for _ in ()).throw(ValueError("sensitive"))
    with pytest.raises(DENIED, match=ERROR) as failure:
        owner.execute(wire, signature)
    assert failure.value.__cause__ is failure.value.__context__ is None
    assert owner._failed is True and owner._used is True
    with pytest.raises(DENIED, match=ERROR):
        owner.execute(wire, signature)


@pytest.mark.parametrize(
    "candidate_wire,candidate_signature,secret,version",
    [
        ({"verified": True}, VECTORS["provision"]["signature"], ALIAS_SECRET, 1),
        (command("provision")[0], True, ALIAS_SECRET, 1),
        (command("provision")[0], command("provision")[1], ROTATED_SECRET, 1),
        (command("provision")[0], command("provision")[1], ALIAS_SECRET, 2),
    ],
)
def test_caller_typed_objects_flags_and_configured_successor_mismatch_are_denied(
    candidate_wire,
    candidate_signature,
    secret,
    version,
):
    verifier = lifecycle.PinnedOfflineAliasLifecycleVerifierV1(
        public_key=PUBLIC_KEY,
        key_id=KEY_ID,
    )
    with pytest.raises(DENIED, match=ERROR):
        writer._command_values(
            verifier,
            candidate_wire,
            candidate_signature,
            now_ms=FIXED_NOW,
            configured_version=version,
            configured_commitment=namespace.active_alias_namespace_secret_commitment(
                alias_secret=secret,
                alias_version=version,
            ),
        )


def test_reconciliation_authenticates_signature_but_cannot_execute_expired_history():
    owner, _parsed = owner_shell("rotate")
    owner._configured_successor_alias_version = 2
    owner._configured_successor_commitment = namespace.active_alias_namespace_secret_commitment(
        alias_secret=ALIAS_SECRET,
        alias_version=2,
    )
    owner._verifier = lifecycle.PinnedOfflineAliasLifecycleVerifierV1(
        public_key=PUBLIC_KEY,
        key_id=KEY_ID,
    )
    wire, signature = command("rotate")
    assert owner._authenticate_for_reconciliation(wire, signature)["action"] == "rotate"
    with pytest.raises(DENIED, match=ERROR):
        writer._command_values(
            owner._verifier,
            wire,
            signature,
            now_ms=1_800_000_060_000,
            configured_version=2,
            configured_commitment=owner._configured_successor_commitment,
        )


def test_result_is_frozen_non_authorizing_and_repr_omits_commitments():
    result = writer._result(authenticated_values("provision", secret=ALIAS_SECRET, version=1), outcome="staged")
    with pytest.raises(FrozenInstanceError):
        result.outcome = "committed"
    assert result.bearer_authority == "none"
    assert result.transaction_authority == "caller_owned"
    assert result.successor_commitment not in repr(result)


def test_model_and_additive_migration_freeze_event_and_commit_invariants():
    sql = MIGRATION.read_text(encoding="ascii")
    table = writer.SocialMessagingActiveAliasNamespaceLifecycleEventRow.__table__
    ddl = str(CreateTable(table).compile(dialect=postgresql.dialect()))
    assert f"CREATE TABLE {writer.EVENT_TABLE}" in ddl
    assert f"CREATE TABLE {writer.EVENT_TABLE}" in sql
    for constraint in table.constraints:
        if constraint.name:
            assert constraint.name in sql
    assert "DEFERRABLE INITIALLY DEFERRED" in sql
    assert "pg_advisory_xact_lock" not in sql
    assert "sha256(" in sql
    assert "signature" in sql
    assert "staged_top_level_transaction_id xid8 NOT NULL" in sql
    assert "NEW.staged_top_level_transaction_id := pg_current_xact_id()" in sql
    assert "xmin" not in inspect.getsource(writer)
    assert sql.count("CREATE CONSTRAINT TRIGGER") == 2
    assert sql.count("CREATE TRIGGER") == 2
    assert "INSERT INTO" not in sql
    assert "PRIVATE KEY" not in sql.upper()
    assert "raw_secret" not in sql.lower()
    sqlite_ddl = str(CreateTable(table).compile(dialect=sqlite.dialect()))
    assert "~" not in sqlite_ddl


def test_source_has_fixed_transaction_lock_and_no_transaction_or_runtime_owner():
    source = inspect.getsource(writer)
    tree = ast.parse(source)
    lock_at = source.index("pg_advisory_xact_lock")
    active_at = source.index("def _lock_active_rows")
    assert lock_at < active_at
    assert writer.RUNTIME_ENABLED is False
    assert writer.TRANSACTION_OWNER == "caller"
    assert writer.PRIVATE_KEY_CUSTODY == "external_offline_only"
    assert writer.WRITER_ADVISORY_LOCK_KEY == int.from_bytes(
        hashlib.sha256(writer.WRITER_ADVISORY_LOCK_DOMAIN).digest()[:8],
        "big",
        signed=True,
    )
    assert not any(
        hasattr(writer.SqlAlchemyTransactionBoundActiveAliasNamespaceLifecycleOwner, name)
        for name in ("begin", "commit", "rollback", "close")
    )
    assert not any(
        isinstance(node, ast.Name) and node.id in {"create_engine", "sessionmaker"} for node in ast.walk(tree)
    )
    assert "Ed25519PrivateKey" not in source
    assert "DATABASE_URL" not in source


def test_protected_vectors_and_earlier_migration_bytes_are_unchanged():
    assert hashlib.sha256(VECTORS_PATH.read_bytes()).hexdigest() == (
        "10831b6ea9dec88f7f6fa7d57102a2245973e36662b0cf2761736381061190e0"
    )
    assert hashlib.sha256(EARLIER_NAMESPACE_MIGRATION.read_bytes()).hexdigest() == (
        "120284b9d357934c3b1bb8ce57d7f3b47cd7b7412cb8163cd45e6d9cacc37f4c"
    )
    assert hashlib.sha256(EARLIER_ROUTING_MIGRATION.read_bytes()).hexdigest() == (
        "971f5e048cfd7614e04ce728caa9a422a545975df3895716bbaffb60c81bb4e9"
    )
