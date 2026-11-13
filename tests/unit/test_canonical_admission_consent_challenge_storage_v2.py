"""Dormant Canon V2 DB-issued challenge ledger; no Full or runtime access."""

from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.canonical_admission_consent_challenge_storage_v2 import (
    CONSUME_SQL,
    INSERT_SQL,
    LOCK_SQL,
    RUNTIME_ENABLED,
    CanonicalAdmissionChallengeLedgerUnavailable,
    CanonicalAdmissionChallengeReplayV2,
    SqlAlchemyCanonicalAdmissionChallengeLedgerV2,
)
from app.services.canonical_admission_consent_v2 import (
    InvalidCanonicalAdmissionConsentV2,
    canonical_admission_consent_message_v2,
)
from tests.unit.test_canonical_admission_consent_v2 import CHILD_SIG, SPONSOR_SIG, StrictRpc
from tests.unit.test_canonical_admission_proposal_v2 import ALICE, BOB, NOW, _make
from app.utils import derive_legacy_address_from_pubkey


class FakeResult:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def mappings(self):
        return self

    def one_or_none(self):
        return self.value


class FakeTransactionSession:
    """Simulates SQL results only; NOT a concurrency or PostgreSQL execution test."""

    def __init__(self):
        self.row = None
        self.commands = []
        self.active = True
        self.dialect_name = "postgresql"
        self.block_update = False

    def in_transaction(self):
        return self.active

    def get_bind(self):
        return SimpleNamespace(dialect=SimpleNamespace(name=self.dialect_name))

    def execute(self, statement, params):
        sql = str(statement)
        self.commands.append((sql, dict(params)))
        if sql == INSERT_SQL:
            assert self.row is None
            self.row = {
                **params,
                "consumed_at": None,
                "verification_sha256": None,
            }
            return FakeResult(params["challenge_sha256"])
        if sql == LOCK_SQL:
            return FakeResult(self.row)
        if sql == CONSUME_SQL:
            if self.block_update or self.row is None or self.row["consumed_at"] is not None:
                return FakeResult(None)
            self.row["consumed_at"] = params["consumed_at"]
            self.row["verification_sha256"] = params["verification_sha256"]
            return FakeResult(params["challenge_sha256"])
        raise AssertionError("unrecognized SQL statement")


class Clock:
    def __init__(self, at=NOW):
        self.at = at

    def __call__(self):
        return self.at


def setup():
    proposal, _, _ = _make()
    session = FakeTransactionSession()
    clock = Clock()
    ledger = SqlAlchemyCanonicalAdmissionChallengeLedgerV2(session, clock=clock)
    pending = ledger.issue(proposal, authenticated_sponsor_pubkey=ALICE)
    challenge = pending.challenge
    sponsor = (
        derive_legacy_address_from_pubkey(ALICE),
        SPONSOR_SIG,
        canonical_admission_consent_message_v2(challenge, role="sponsor"),
    )
    child = (
        derive_legacy_address_from_pubkey(BOB),
        CHILD_SIG,
        canonical_admission_consent_message_v2(challenge, role="child"),
    )
    return proposal, session, clock, ledger, pending, StrictRpc((sponsor, child))


def consume(ledger, proposal, pending, rpc, *, child=BOB, sponsor_sig=SPONSOR_SIG, child_sig=CHILD_SIG):
    return ledger.consume(
        proposal,
        challenge_sha256=pending.challenge_sha256,
        authenticated_child_pubkey=child,
        sponsor_signature=sponsor_sig,
        child_signature=child_sig,
        rpc=rpc,
    )


def test_dormant_issuance_and_atomic_reservation_without_ever_granting_full():
    proposal, session, _, ledger, pending, rpc = setup()
    assert RUNTIME_ENABLED is False
    assert pending.durable is False
    assert pending.grants_full is False
    assert session.commands[0][0] == INSERT_SQL
    assert session.row["challenge_sha256"] == pending.challenge_sha256
    assert session.row["nonce_hex"] == pending.challenge.nonce_hex
    assert session.row["issuer_session_pubkey"] == ALICE

    result = consume(ledger, proposal, pending, rpc)
    assert not result.grants_full
    assert not result.replay_protected
    assert result.challenge_sha256 == pending.challenge_sha256
    assert result.verification_sha256 == session.row["verification_sha256"]
    assert session.row["consumed_at"] == NOW
    assert [x[0] for x in session.commands] == [INSERT_SQL, LOCK_SQL, CONSUME_SQL]
    assert len(rpc.calls) == 2


def test_replay_cannot_reverify_or_update_second_time():
    proposal, session, _, ledger, pending, rpc = setup()
    consume(ledger, proposal, pending, rpc)
    rpc.calls.clear()
    with pytest.raises(CanonicalAdmissionChallengeReplayV2, match="not_issued_or_already_consumed"):
        consume(ledger, proposal, pending, rpc)
    assert len(session.commands) == 4
    assert not rpc.calls


def test_only_explicit_postgresql_transaction_is_supported():
    proposal, session, _, ledger, pending, rpc = setup()
    session.active = False
    with pytest.raises(CanonicalAdmissionChallengeLedgerUnavailable, match="postgres_transaction_required"):
        consume(ledger, proposal, pending, rpc)
    assert len(session.commands) == 1
    session.active = True
    session.dialect_name = "sqlite"
    with pytest.raises(CanonicalAdmissionChallengeLedgerUnavailable, match="postgres_transaction_required"):
        consume(ledger, proposal, pending, rpc)


def test_other_authenticated_child_cannot_consume_challenge():
    proposal, session, _, ledger, pending, rpc = setup()
    with pytest.raises(CanonicalAdmissionChallengeReplayV2, match="consumer_not_child"):
        consume(ledger, proposal, pending, rpc, child=ALICE)
    assert len(session.commands) == 1
    assert session.row["consumed_at"] is None


def test_sponsor_identity_must_match_authenticated_issuer_argument():
    proposal, _, _ = _make()
    ledger = SqlAlchemyCanonicalAdmissionChallengeLedgerV2(FakeTransactionSession(), clock=Clock())
    with pytest.raises(CanonicalAdmissionChallengeReplayV2, match="issuer_not_sponsor"):
        ledger.issue(proposal, authenticated_sponsor_pubkey=BOB)


def test_invalid_child_signature_does_not_consume_nonce():
    proposal, session, _, ledger, pending, rpc = setup()
    with pytest.raises(InvalidCanonicalAdmissionConsentV2, match="indistinguishable_signatures"):
        consume(ledger, proposal, pending, rpc, child_sig=SPONSOR_SIG)
    assert session.row["consumed_at"] is None
    assert len(session.commands) == 2


def test_expired_challenge_cannot_be_consumed():
    proposal, session, clock, ledger, pending, rpc = setup()
    clock.at = NOW + timedelta(seconds=301)
    with pytest.raises(InvalidCanonicalAdmissionConsentV2, match="challenge_expired_or_not_issued"):
        consume(ledger, proposal, pending, rpc)
    assert session.row["consumed_at"] is None


def test_forged_stored_nonce_is_never_trusted_as_issued():
    proposal, session, _, ledger, pending, rpc = setup()
    session.row["nonce_hex"] = "f" * 64
    with pytest.raises(CanonicalAdmissionChallengeReplayV2, match="stored_challenge_binding"):
        consume(ledger, proposal, pending, rpc)
    assert session.row["consumed_at"] is None
    assert not rpc.calls


def test_verified_but_losing_single_use_update_is_not_success():
    proposal, session, _, ledger, pending, rpc = setup()
    session.block_update = True
    with pytest.raises(CanonicalAdmissionChallengeReplayV2, match="challenge_consumption_conflict"):
        consume(ledger, proposal, pending, rpc)
    assert session.row["consumed_at"] is None
    assert len(rpc.calls) == 2


def test_wrong_proposal_cannot_use_original_issued_challenge():
    from dataclasses import replace

    proposal, session, _, ledger, pending, rpc = setup()
    other = replace(proposal, sponsor_import_event_sha256="f" * 64)
    with pytest.raises(CanonicalAdmissionChallengeReplayV2, match="stored_challenge_binding"):
        consume(ledger, other, pending, rpc)
    assert not rpc.calls
    assert session.row["consumed_at"] is None


def test_ledger_migration_is_dormant_and_has_unique_nonce_cas_and_write_guard():
    sql = Path("migrations/2026-11-13_canonical_admission_consent_challenge_v2.sql").read_text()
    assert "UNIQUE" in sql
    assert "nonce_hex CHAR(64) NOT NULL UNIQUE" in sql
    assert "verification_sha256 CHAR(64) UNIQUE" in sql
    assert "TRIGGER" in sql
    assert "OLD.consumed_at IS NOT NULL" in sql
    assert "NEW.issued_at" in sql
    assert "consumed_at IS NULL" in CONSUME_SQL
    assert "FOR UPDATE" in LOCK_SQL
    assert "CREATE TABLE public.canonical_admission_consent_challenges_v2" in sql
    assert "GRANT " not in sql
    assert "DROP TABLE" not in sql


def test_replay_protection_requires_caller_owned_commit_not_pending_return():
    proposal, session, _, ledger, pending, rpc = setup()
    tentative = consume(ledger, proposal, pending, rpc)
    assert tentative.replay_protected is False
    assert tentative.grants_full is False
    # Fake rollback of uncommitted row update. No API for durable authority.
    session.row["consumed_at"] = None
    session.row["verification_sha256"] = None
    assert tentative.replay_protected is False
