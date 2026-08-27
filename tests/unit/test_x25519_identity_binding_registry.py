from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import json

from coincurve import PrivateKey, PublicKeyXOnly
import pytest
from sqlalchemy import create_engine, delete, insert, select, text, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.schema import CreateTable

import app.services.x25519_identity_binding_registry as contract
import app.services.x25519_identity_binding_registry_storage as storage
from app.models import X25519IdentityBinding
from app.services.full_recipient_directory_provider import validate_x25519_public_key
from app.services.x25519_identity_binding_registry import (
    BindingRegistryUnavailable,
    BindingStatement,
    SnapshotBinding,
    X25519IdentityBindingRegistry,
    parse_and_verify_statement,
    statement_digest,
)
from app.services.x25519_identity_binding_registry_storage import (
    SqlAlchemyX25519IdentityBindingRepository,
)

NOW = datetime(2026, 8, 24, 12, tzinfo=timezone.utc)
SUBJECT_A = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
SUBJECT_B = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
KEY_A = "09" + "00" * 31
KEY_B = "0a" + "00" * 31
KEY_C = "0b" + "00" * 31
KEY_D = "0c" + "00" * 31


class AcceptingPublicKey:
    def __init__(self, _value):
        pass

    def verify(self, signature, digest):
        return len(signature) == 64 and len(digest) == 32


def payload(
    *,
    subject=SUBJECT_A,
    public_key=KEY_A,
    version=1,
    operation="register",
    prior=None,
    nonce="11" * 32,
    valid_from="2026-08-24T11:00:00Z",
    expires_at="2026-08-25T12:00:00Z",
):
    core = {
        "schema": contract.STATEMENT_SCHEMA,
        "version": 1,
        "subject": subject,
        "algorithm": contract.ALGORITHM,
        "publicKey": public_key,
        "bindingVersion": version,
        "validFrom": valid_from,
        "expiresAt": expires_at,
        "operation": operation,
        "priorBindingId": prior,
        "nonce": nonce,
    }
    return {
        **core,
        "digest": statement_digest(core),
        "signatureFormat": contract.SIGNATURE_FORMAT,
        "signature": "22" * 64,
    }


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def timestamp_text(value):
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat(timespec="seconds").replace("+00:00", "Z")


def real_subject(private_key):
    return PublicKeyXOnly.from_secret(private_key.secret).format().hex()


def signed_payload(private_key, **values):
    subject = values.pop("subject", real_subject(private_key))
    candidate = payload(subject=subject, **values)
    candidate["signature"] = private_key.sign_schnorr(
        bytes.fromhex(candidate["digest"]),
        b"\x00" * 32,
    ).hex()
    return candidate


def signed_statement(private_key, **values):
    candidate = signed_payload(private_key, **values)
    return parse_and_verify_statement(encoded(candidate), authenticated_subject=candidate["subject"])


@pytest.fixture
def repository():
    engine = create_engine("sqlite://")
    X25519IdentityBinding.__table__.create(engine)
    return SqlAlchemyX25519IdentityBindingRepository(sessionmaker(bind=engine))


def parsed(monkeypatch, **values):
    monkeypatch.setattr(contract, "PublicKeyXOnly", AcceptingPublicKey)
    candidate = payload(**values)
    return parse_and_verify_statement(encoded(candidate), authenticated_subject=candidate["subject"])


def persisted_values(statement, **changes):
    values = {
        "binding_id": statement.binding_id,
        "contract_version": statement.schema,
        "subject_pubkey": statement.subject,
        "algorithm": statement.algorithm,
        "public_key": statement.public_key,
        "binding_version": statement.binding_version,
        "valid_from": statement.valid_from,
        "expires_at": statement.expires_at,
        "operation": statement.operation,
        "prior_binding_id": statement.prior_binding_id,
        "nonce": statement.nonce,
        "statement_sha256": statement.digest,
        "signature_format": statement.signature_format,
        "identity_signature": statement.signature,
        "active": statement.operation != "revoke",
        "retired_at": NOW if statement.operation == "revoke" else None,
        "created_at": NOW,
    }
    values.update(changes)
    return values


def stored_rows(repository):
    with repository._session_factory() as session:
        rows = session.execute(select(X25519IdentityBinding).order_by(X25519IdentityBinding.binding_id)).scalars().all()
        return [
            (
                row.binding_id,
                row.contract_version,
                row.subject_pubkey,
                row.algorithm,
                row.public_key,
                row.binding_version,
                row.valid_from,
                row.expires_at,
                row.operation,
                row.prior_binding_id,
                row.nonce,
                row.statement_sha256,
                row.signature_format,
                row.identity_signature,
                row.active,
                row.retired_at,
                row.created_at,
            )
            for row in rows
        ]


def active_rows(repository):
    with repository._session_factory() as session:
        rows = (
            session.execute(select(X25519IdentityBinding).where(X25519IdentityBinding.active.is_(True))).scalars().all()
        )
        return [(row.binding_id, row.public_key, row.operation) for row in rows]


def corrupt_row(repository, binding_id, **changes):
    with repository._session_factory() as session:
        session.execute(text("PRAGMA ignore_check_constraints = ON"))
        result = session.execute(
            update(X25519IdentityBinding).where(X25519IdentityBinding.binding_id == binding_id).values(**changes)
        )
        assert result.rowcount == 1
        session.execute(text("PRAGMA ignore_check_constraints = OFF"))
        session.commit()


def delete_row(repository, binding_id):
    with repository._session_factory() as session:
        result = session.execute(delete(X25519IdentityBinding).where(X25519IdentityBinding.binding_id == binding_id))
        assert result.rowcount == 1
        session.commit()


def insert_statement(repository, statement, **changes):
    with repository._session_factory() as session:
        session.execute(insert(X25519IdentityBinding), persisted_values(statement, **changes))
        session.commit()


def insert_same_key_rotation(
    repository,
    private_key,
    *,
    active=True,
    first_nonce="c0",
    rotate_nonce="c1",
):
    first = signed_statement(private_key, nonce=first_nonce * 32)
    repository.apply(first, NOW)
    corrupt_row(repository, first.binding_id, active=False, retired_at=NOW)
    rotated = signed_statement(
        private_key,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce=rotate_nonce * 32,
    )
    insert_statement(
        repository,
        rotated,
        active=active,
        retired_at=None if active else NOW,
    )
    return first, rotated


def assert_rejects_without_mutation(repository, statement):
    before = stored_rows(repository)
    with pytest.raises(BindingRegistryUnavailable):
        repository.apply(statement, NOW)
    assert stored_rows(repository) == before


def assert_snapshot_rejects_without_mutation(repository, now=NOW):
    before = stored_rows(repository)
    service = X25519IdentityBindingRegistry(repository, clock=lambda: now)
    with pytest.raises(BindingRegistryUnavailable) as caught:
        service.current_snapshot()
    assert str(caught.value) == contract.UNAVAILABLE_MESSAGE
    assert stored_rows(repository) == before


def forged_statement(
    *,
    subject=SUBJECT_A,
    public_key=KEY_A,
    version=1,
    operation="register",
    prior=None,
    nonce="aa" * 32,
):
    return BindingStatement(
        contract.STATEMENT_SCHEMA,
        subject,
        contract.ALGORITHM,
        public_key,
        version,
        NOW - timedelta(hours=1),
        NOW + timedelta(days=1),
        operation,
        prior,
        nonce,
        nonce,
        contract.SIGNATURE_FORMAT,
        "22" * 64,
    )


def test_valid_first_registration_and_canonical_digest(monkeypatch, repository):
    candidate = payload()
    expected = statement_digest(
        {key: candidate[key] for key in candidate if key not in {"digest", "signatureFormat", "signature"}}
    )
    assert candidate["digest"] == expected
    monkeypatch.setattr(contract, "PublicKeyXOnly", AcceptingPublicKey)
    service = X25519IdentityBindingRegistry(repository, clock=lambda: NOW)
    result = service.apply(encoded(candidate), authenticated_subject=SUBJECT_A)
    assert result == candidate


def test_register_and_rotate_replays_fail_closed(monkeypatch, repository):
    first = parsed(monkeypatch)
    repository.apply(first, NOW)
    with pytest.raises(BindingRegistryUnavailable):
        repository.apply(first, NOW)

    rotated = parsed(
        monkeypatch,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="33" * 32,
    )
    repository.apply(rotated, NOW)
    with pytest.raises(BindingRegistryUnavailable):
        repository.apply(rotated, NOW)


def test_authorization_subject_and_signature_mismatch_fail_closed(monkeypatch):
    monkeypatch.setattr(contract, "PublicKeyXOnly", AcceptingPublicKey)
    with pytest.raises(BindingRegistryUnavailable):
        parse_and_verify_statement(encoded(payload()), authenticated_subject=SUBJECT_B)

    class RejectingPublicKey(AcceptingPublicKey):
        def verify(self, signature, digest):
            return False

    monkeypatch.setattr(contract, "PublicKeyXOnly", RejectingPublicKey)
    with pytest.raises(BindingRegistryUnavailable):
        parse_and_verify_statement(encoded(payload()), authenticated_subject=SUBJECT_A)


def test_unknown_or_private_key_fields_and_duplicate_nonce_fail_closed(monkeypatch, repository):
    monkeypatch.setattr(contract, "PublicKeyXOnly", AcceptingPublicKey)
    candidate = payload()
    candidate["privateKey"] = "not-inspected"
    with pytest.raises(BindingRegistryUnavailable):
        parse_and_verify_statement(encoded(candidate), authenticated_subject=SUBJECT_A)

    repository.apply(parsed(monkeypatch), NOW)
    conflict = parsed(monkeypatch, subject=SUBJECT_B, public_key=KEY_B)
    with pytest.raises(BindingRegistryUnavailable):
        repository.apply(conflict, NOW)


def test_statement_boundary_rejects_duplicate_keys_and_decoded_objects(monkeypatch):
    monkeypatch.setattr(contract, "PublicKeyXOnly", AcceptingPublicKey)
    canonical = encoded(payload())
    duplicated = canonical.replace(
        f'"subject":"{SUBJECT_A}"',
        f'"subject":"{SUBJECT_B}","subject":"{SUBJECT_A}"',
    )
    with pytest.raises(BindingRegistryUnavailable):
        parse_and_verify_statement(duplicated, authenticated_subject=SUBJECT_A)
    with pytest.raises(BindingRegistryUnavailable):
        parse_and_verify_statement(payload(), authenticated_subject=SUBJECT_A)
    with pytest.raises(BindingRegistryUnavailable):
        parse_and_verify_statement(canonical + " ", authenticated_subject=SUBJECT_A)


def test_exact_rotation_stale_skipped_and_cross_subject_duplicate_key(monkeypatch, repository):
    first = parsed(monkeypatch)
    repository.apply(first, NOW)
    rotated = parsed(
        monkeypatch,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="33" * 32,
    )
    assert repository.apply(rotated, NOW) == rotated

    stale = parsed(
        monkeypatch,
        public_key="0b" + "00" * 31,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="44" * 32,
    )
    with pytest.raises(BindingRegistryUnavailable):
        repository.apply(stale, NOW)
    skipped = parsed(
        monkeypatch,
        public_key="0c" + "00" * 31,
        version=4,
        operation="rotate",
        prior=rotated.binding_id,
        nonce="55" * 32,
    )
    with pytest.raises(BindingRegistryUnavailable):
        repository.apply(skipped, NOW)
    duplicate = parsed(
        monkeypatch,
        subject=SUBJECT_B,
        public_key=KEY_B,
        nonce="66" * 32,
    )
    with pytest.raises(BindingRegistryUnavailable):
        repository.apply(duplicate, NOW)


def test_rotation_rejects_reuse_of_current_public_key(monkeypatch, repository):
    first = parsed(monkeypatch)
    repository.apply(first, NOW)
    reused = parsed(
        monkeypatch,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="aa" * 32,
    )
    with pytest.raises(BindingRegistryUnavailable):
        repository.apply(reused, NOW)


def test_concurrent_rotation_has_exactly_one_winner(monkeypatch, tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'registry.sqlite'}",
        connect_args={"check_same_thread": False},
    )
    X25519IdentityBinding.__table__.create(engine)
    repository = SqlAlchemyX25519IdentityBindingRepository(sessionmaker(bind=engine))
    first = parsed(monkeypatch)
    repository.apply(first, NOW)
    candidates = [
        parsed(
            monkeypatch,
            public_key=key,
            version=2,
            operation="rotate",
            prior=first.binding_id,
            nonce=nonce,
        )
        for key, nonce in ((KEY_B, "33" * 32), ("0b" + "00" * 31, "44" * 32))
    ]

    def attempt(candidate):
        try:
            repository.apply(candidate, NOW)
            return True
        except BindingRegistryUnavailable:
            return False

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(attempt, candidates))
    assert sorted(results) == [False, True]


def test_exact_revocation_replay_conflict_and_snapshot_exclusion(monkeypatch, repository):
    first = parsed(monkeypatch)
    repository.apply(first, NOW)
    revoked = parsed(
        monkeypatch,
        version=2,
        operation="revoke",
        prior=first.binding_id,
        nonce="77" * 32,
    )
    assert repository.apply(revoked, NOW) == revoked
    assert repository.apply(revoked, NOW) == revoked
    assert repository.current_snapshot(NOW, 10) == []

    conflict = parsed(
        monkeypatch,
        version=2,
        operation="revoke",
        prior=first.binding_id,
        nonce="88" * 32,
    )
    with pytest.raises(BindingRegistryUnavailable):
        repository.apply(conflict, NOW)


def test_revocation_replay_rejects_corrupt_predecessor_state(monkeypatch, repository):
    first = parsed(monkeypatch)
    repository.apply(first, NOW)
    revoked = parsed(
        monkeypatch,
        version=2,
        operation="revoke",
        prior=first.binding_id,
        nonce="77" * 32,
    )
    repository.apply(revoked, NOW)
    with repository._session_factory() as session:
        session.execute(
            update(X25519IdentityBinding)
            .where(X25519IdentityBinding.binding_id == first.binding_id)
            .values(active=True, retired_at=None)
        )
        session.commit()
    with pytest.raises(BindingRegistryUnavailable):
        repository.apply(revoked, NOW)


def test_write_path_revalidates_malformed_persisted_bip340_signature_without_mutation(repository):
    private_key = PrivateKey(b"\x01" * 32)
    first = signed_statement(private_key, nonce="01" * 32)
    repository.apply(first, NOW)
    corrupt_row(repository, first.binding_id, identity_signature="00" * 64)

    rotated = signed_statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="02" * 32,
    )
    revoked = signed_statement(
        private_key,
        version=2,
        operation="revoke",
        prior=first.binding_id,
        nonce="03" * 32,
    )

    assert_rejects_without_mutation(repository, rotated)
    assert_rejects_without_mutation(repository, revoked)


@pytest.mark.parametrize(
    "changes",
    [
        {"statement_sha256": "aa" * 32},
        {"nonce": "aa" * 32},
    ],
)
def test_write_path_revalidates_persisted_digest_and_canonical_core_without_mutation(repository, changes):
    private_key = PrivateKey(b"\x01" * 32)
    first = signed_statement(private_key, nonce="04" * 32)
    repository.apply(first, NOW)
    corrupt_row(repository, first.binding_id, **changes)

    rotated = signed_statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="05" * 32,
    )
    revoked = signed_statement(
        private_key,
        version=2,
        operation="revoke",
        prior=first.binding_id,
        nonce="06" * 32,
    )

    assert_rejects_without_mutation(repository, rotated)
    assert_rejects_without_mutation(repository, revoked)


def test_rotation_rejects_successor_after_chain_deadline_without_mutation(repository):
    private_key = PrivateKey(b"\x01" * 32)
    chain_deadline = NOW + timedelta(seconds=120)
    first = signed_statement(
        private_key,
        nonce="a1" * 32,
        expires_at=timestamp_text(chain_deadline),
    )
    repository.apply(first, NOW)
    rotated = signed_statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="a2" * 32,
        expires_at=timestamp_text(chain_deadline + timedelta(seconds=1)),
    )

    assert_rejects_without_mutation(repository, rotated)

    assert active_rows(repository) == [(first.binding_id, KEY_A, "register")]


def test_revocation_rejects_expired_predecessor_without_mutation(repository):
    private_key = PrivateKey(b"\x01" * 32)
    first = signed_statement(
        private_key,
        nonce="a4" * 32,
        valid_from="2026-08-24T10:00:00Z",
        expires_at="2026-08-24T11:30:00Z",
    )
    repository.apply(first, NOW - timedelta(hours=2))
    rotated = signed_statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="a5" * 32,
        valid_from="2026-08-24T11:00:00Z",
        expires_at="2026-08-24T11:30:00Z",
    )
    repository.apply(rotated, NOW - timedelta(minutes=45))

    revoked = signed_statement(
        private_key,
        public_key=KEY_B,
        version=3,
        operation="revoke",
        prior=rotated.binding_id,
        nonce="a6" * 32,
    )

    assert_rejects_without_mutation(repository, revoked)


def test_revocation_and_replay_reject_successor_after_chain_deadline_without_mutation(repository):
    private_key = PrivateKey(b"\x01" * 32)
    chain_deadline = NOW + timedelta(seconds=120)
    first = signed_statement(
        private_key,
        nonce="ac" * 32,
        expires_at=timestamp_text(chain_deadline),
    )
    repository.apply(first, NOW)
    revoked = signed_statement(
        private_key,
        version=2,
        operation="revoke",
        prior=first.binding_id,
        nonce="ad" * 32,
        expires_at=timestamp_text(chain_deadline + timedelta(seconds=1)),
    )

    assert_rejects_without_mutation(repository, revoked)

    corrupt_row(repository, first.binding_id, active=False, retired_at=NOW)
    insert_statement(repository, revoked)

    assert_rejects_without_mutation(repository, revoked)


def test_rotation_accepts_exact_chain_deadline_equality(repository):
    private_key = PrivateKey(b"\x01" * 32)
    chain_deadline = NOW + timedelta(seconds=120)
    first = signed_statement(
        private_key,
        nonce="ae" * 32,
        expires_at=timestamp_text(chain_deadline),
    )
    repository.apply(first, NOW)
    rotated = signed_statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="af" * 32,
        expires_at=timestamp_text(chain_deadline),
    )

    assert repository.apply(rotated, NOW) == rotated


def test_valid_different_key_rotation_remains_accepted(repository):
    private_key = PrivateKey(b"\x01" * 32)
    first = signed_statement(private_key, nonce="d0" * 32)
    repository.apply(first, NOW)
    rotated = signed_statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="d1" * 32,
    )

    assert repository.apply(rotated, NOW) == rotated


def test_revoke_with_exact_current_key_remains_accepted(repository):
    private_key = PrivateKey(b"\x01" * 32)
    first = signed_statement(private_key, nonce="d2" * 32)
    repository.apply(first, NOW)
    revoked = signed_statement(
        private_key,
        version=2,
        operation="revoke",
        prior=first.binding_id,
        nonce="d3" * 32,
    )

    assert repository.apply(revoked, NOW) == revoked
    assert repository.current_snapshot(NOW, 10) == []


def test_write_path_rejects_not_yet_valid_predecessor_without_mutation(repository):
    private_key = PrivateKey(b"\x01" * 32)
    predecessor = signed_statement(
        private_key,
        nonce="a7" * 32,
        valid_from="2026-08-24T12:30:00Z",
        expires_at="2026-08-25T12:00:00Z",
    )
    current = signed_statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=predecessor.binding_id,
        nonce="a8" * 32,
        valid_from="2026-08-24T11:00:00Z",
        expires_at="2026-08-25T12:00:00Z",
    )
    insert_statement(repository, predecessor, active=False, retired_at=NOW - timedelta(minutes=10))
    insert_statement(repository, current, active=True, retired_at=None)

    next_rotation = signed_statement(
        private_key,
        public_key=KEY_C,
        version=3,
        operation="rotate",
        prior=current.binding_id,
        nonce="a9" * 32,
    )
    revoked = signed_statement(
        private_key,
        public_key=KEY_B,
        version=3,
        operation="revoke",
        prior=current.binding_id,
        nonce="ab" * 32,
    )

    assert_rejects_without_mutation(repository, next_rotation)
    assert_rejects_without_mutation(repository, revoked)


@pytest.mark.parametrize("corruption", ["missing", "partial"])
def test_write_path_rejects_missing_or_partial_predecessor_without_mutation(repository, corruption):
    private_key = PrivateKey(b"\x01" * 32)
    first = signed_statement(private_key, nonce="07" * 32)
    repository.apply(first, NOW)
    rotated = signed_statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="08" * 32,
    )
    repository.apply(rotated, NOW)
    if corruption == "missing":
        delete_row(repository, first.binding_id)
    else:
        corrupt_row(repository, first.binding_id, retired_at=None)

    next_rotation = signed_statement(
        private_key,
        public_key=KEY_C,
        version=3,
        operation="rotate",
        prior=rotated.binding_id,
        nonce="09" * 32,
    )
    revoked = signed_statement(
        private_key,
        public_key=KEY_B,
        version=3,
        operation="revoke",
        prior=rotated.binding_id,
        nonce="0a" * 32,
    )

    assert_rejects_without_mutation(repository, next_rotation)
    assert_rejects_without_mutation(repository, revoked)


def test_write_path_rejects_cross_subject_predecessor_without_mutation(repository):
    private_key_a = PrivateKey(b"\x01" * 32)
    private_key_b = PrivateKey(b"\x02" * 32)
    first_a = signed_statement(private_key_a, nonce="0b" * 32)
    first_b = signed_statement(private_key_b, public_key=KEY_B, nonce="0c" * 32)
    repository.apply(first_a, NOW)
    repository.apply(first_b, NOW)
    corrupt_row(repository, first_a.binding_id, active=False, retired_at=NOW)
    cross_subject_current = signed_statement(
        private_key_a,
        public_key=KEY_C,
        version=2,
        operation="rotate",
        prior=first_b.binding_id,
        nonce="0d" * 32,
    )
    insert_statement(repository, cross_subject_current, active=True, retired_at=None)

    next_rotation = signed_statement(
        private_key_a,
        public_key=KEY_D,
        version=3,
        operation="rotate",
        prior=cross_subject_current.binding_id,
        nonce="0e" * 32,
    )
    revoked = signed_statement(
        private_key_a,
        public_key=KEY_C,
        version=3,
        operation="revoke",
        prior=cross_subject_current.binding_id,
        nonce="0f" * 32,
    )

    assert_rejects_without_mutation(repository, next_rotation)
    assert_rejects_without_mutation(repository, revoked)


def test_write_path_rejects_broken_version_linkage_without_mutation(repository):
    private_key = PrivateKey(b"\x01" * 32)
    first = signed_statement(private_key, nonce="10" * 32)
    repository.apply(first, NOW)
    corrupt_row(repository, first.binding_id, active=False, retired_at=NOW)
    broken_current = signed_statement(
        private_key,
        public_key=KEY_B,
        version=3,
        operation="rotate",
        prior=first.binding_id,
        nonce="11" * 32,
    )
    insert_statement(repository, broken_current, active=True, retired_at=None)

    next_rotation = signed_statement(
        private_key,
        public_key=KEY_C,
        version=4,
        operation="rotate",
        prior=broken_current.binding_id,
        nonce="12" * 32,
    )
    revoked = signed_statement(
        private_key,
        public_key=KEY_B,
        version=4,
        operation="revoke",
        prior=broken_current.binding_id,
        nonce="13" * 32,
    )

    assert_rejects_without_mutation(repository, next_rotation)
    assert_rejects_without_mutation(repository, revoked)


def test_valid_real_bip340_register_rotate_revoke_chain(repository):
    private_key = PrivateKey(b"\x01" * 32)
    subject = real_subject(private_key)
    service = X25519IdentityBindingRegistry(repository, clock=lambda: NOW)

    first = signed_payload(private_key, nonce="14" * 32)
    assert service.apply(encoded(first), authenticated_subject=subject) == first

    rotated = signed_payload(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first["digest"],
        nonce="15" * 32,
    )
    assert service.apply(encoded(rotated), authenticated_subject=subject) == rotated
    snapshot = service.current_snapshot()
    assert snapshot["bindings"][0]["publicKey"] == KEY_B

    revoked = signed_payload(
        private_key,
        public_key=KEY_B,
        version=3,
        operation="revoke",
        prior=rotated["digest"],
        nonce="16" * 32,
    )
    assert service.apply(encoded(revoked), authenticated_subject=subject) == revoked
    assert service.apply(encoded(revoked), authenticated_subject=subject) == revoked
    assert service.current_snapshot()["bindings"] == []


def test_valid_real_bip340_subject_equal_public_key_rejected_without_mutation(repository):
    private_key = PrivateKey((4).to_bytes(32, "big"))
    subject = real_subject(private_key)
    assert validate_x25519_public_key(subject) == subject

    service = X25519IdentityBindingRegistry(repository, clock=lambda: NOW)
    first = signed_payload(private_key, public_key=KEY_A, nonce="17" * 32)
    assert service.apply(encoded(first), authenticated_subject=subject) == first
    before_rows = stored_rows(repository)
    before_snapshot = service.current_snapshot()
    assert active_rows(repository) == [(first["digest"], KEY_A, "register")]

    adversarial = signed_payload(
        private_key,
        public_key=subject,
        version=2,
        operation="rotate",
        prior=first["digest"],
        nonce="18" * 32,
    )
    assert PublicKeyXOnly(bytes.fromhex(subject)).verify(
        bytes.fromhex(adversarial["signature"]),
        bytes.fromhex(adversarial["digest"]),
    )

    with pytest.raises(BindingRegistryUnavailable) as parsed_error:
        parse_and_verify_statement(encoded(adversarial), authenticated_subject=subject)
    assert str(parsed_error.value) == contract.UNAVAILABLE_MESSAGE

    with pytest.raises(BindingRegistryUnavailable) as service_error:
        service.apply(encoded(adversarial), authenticated_subject=subject)

    assert str(service_error.value) == contract.UNAVAILABLE_MESSAGE
    assert stored_rows(repository) == before_rows
    assert active_rows(repository) == [(first["digest"], KEY_A, "register")]
    assert service.current_snapshot() == before_snapshot


@pytest.mark.parametrize(
    "changes",
    [
        {"binding_id": "AA" * 32},
        {"subject_pubkey": "GG" * 32},
        {"public_key": "AA" * 32},
        {"nonce": "AA" * 32},
        {"statement_sha256": "aa" * 32},
        {"identity_signature": "AA" * 64},
    ],
)
def test_model_rejects_noncanonical_or_mismatched_persisted_values(monkeypatch, changes):
    engine = create_engine("sqlite://")
    X25519IdentityBinding.__table__.create(engine)
    statement = parsed(monkeypatch)
    with engine.begin() as connection, pytest.raises(IntegrityError):
        connection.execute(insert(X25519IdentityBinding), persisted_values(statement, **changes))


def test_model_requires_retirement_timestamp_for_inactive_revocation(monkeypatch, repository):
    first = parsed(monkeypatch)
    repository.apply(first, NOW)
    revoked = parsed(
        monkeypatch,
        version=2,
        operation="revoke",
        prior=first.binding_id,
        nonce="77" * 32,
    )
    with repository._session_factory() as session:
        with pytest.raises(IntegrityError):
            session.execute(
                insert(X25519IdentityBinding),
                persisted_values(revoked, active=False, retired_at=None),
            )
            session.commit()


def test_model_canonical_constraints_compile_for_postgresql():
    ddl = str(CreateTable(X25519IdentityBinding.__table__).compile(dialect=postgresql.dialect()))
    assert " REGEXP " not in ddl
    assert ddl.count(" ~ '^[0-9a-f]") == 6


def test_complete_bounded_empty_and_expired_snapshots(monkeypatch, repository):
    service = X25519IdentityBindingRegistry(repository, clock=lambda: NOW)
    empty = service.current_snapshot(maximum=0)
    assert empty["complete"] is True and empty["bindings"] == []

    first = parsed(monkeypatch)
    repository.apply(first, NOW)
    complete = service.current_snapshot(maximum=1)
    assert complete["complete"] is True
    assert complete["bindings"][0]["publicKey"] == KEY_A
    with pytest.raises(BindingRegistryUnavailable):
        service.current_snapshot(maximum=0)

    expired_service = X25519IdentityBindingRegistry(repository, clock=lambda: NOW + timedelta(days=2))
    before = stored_rows(repository)
    with pytest.raises(BindingRegistryUnavailable) as caught:
        expired_service.current_snapshot()
    assert str(caught.value) == contract.UNAVAILABLE_MESSAGE
    assert stored_rows(repository) == before


@pytest.mark.parametrize(
    "nonce,valid_from,expires_at",
    [
        ("31" * 32, "2026-08-23T10:00:00Z", "2026-08-24T11:30:00Z"),
        ("32" * 32, "2026-08-24T12:30:00Z", "2026-08-25T12:00:00Z"),
    ],
)
def test_snapshot_rejects_expired_or_future_active_row_alone_without_mutation(
    repository,
    nonce,
    valid_from,
    expires_at,
):
    private_key = PrivateKey(b"\x01" * 32)
    invalid = signed_statement(
        private_key,
        nonce=nonce,
        valid_from=valid_from,
        expires_at=expires_at,
    )
    insert_statement(repository, invalid, active=True, retired_at=None)

    assert active_rows(repository) == [(invalid.binding_id, KEY_A, "register")]
    assert_snapshot_rejects_without_mutation(repository)


@pytest.mark.parametrize(
    "nonce,valid_from,expires_at",
    [
        ("33" * 32, "2026-08-23T10:00:00Z", "2026-08-24T11:30:00Z"),
        ("34" * 32, "2026-08-24T12:30:00Z", "2026-08-25T12:00:00Z"),
    ],
)
def test_snapshot_rejects_expired_or_future_active_row_beside_valid_member_without_partial_bindings_or_mutation(
    repository,
    nonce,
    valid_from,
    expires_at,
):
    service = X25519IdentityBindingRegistry(repository, clock=lambda: NOW)
    valid = signed_statement(PrivateKey(b"\x01" * 32), nonce="35" * 32)
    repository.apply(valid, NOW)
    invalid = signed_statement(
        PrivateKey(b"\x02" * 32),
        public_key=KEY_B,
        nonce=nonce,
        valid_from=valid_from,
        expires_at=expires_at,
    )
    insert_statement(repository, invalid, active=True, retired_at=None)
    before = stored_rows(repository)

    with pytest.raises(BindingRegistryUnavailable) as caught:
        service.current_snapshot()

    assert str(caught.value) == contract.UNAVAILABLE_MESSAGE
    assert stored_rows(repository) == before


def test_snapshot_returns_valid_current_register_and_rotate_members_without_mutation(repository):
    service = X25519IdentityBindingRegistry(repository, clock=lambda: NOW)
    private_key_a = PrivateKey(b"\x01" * 32)
    private_key_b = PrivateKey(b"\x02" * 32)
    registered = signed_statement(private_key_a, nonce="36" * 32)
    repository.apply(registered, NOW)
    predecessor = signed_statement(private_key_b, public_key=KEY_B, nonce="37" * 32)
    repository.apply(predecessor, NOW)
    rotated = signed_statement(
        private_key_b,
        public_key=KEY_C,
        version=2,
        operation="rotate",
        prior=predecessor.binding_id,
        nonce="38" * 32,
    )
    repository.apply(rotated, NOW)
    before = stored_rows(repository)

    snapshot = service.current_snapshot()

    expected = sorted([registered, rotated], key=lambda statement: statement.subject)
    assert stored_rows(repository) == before
    assert [(binding["subject"], binding["version"], binding["publicKey"]) for binding in snapshot["bindings"]] == [
        (statement.subject, statement.binding_version, statement.public_key) for statement in expected
    ]


def test_snapshot_expires_at_equals_earliest_chain_expiration(repository):
    service = X25519IdentityBindingRegistry(repository, clock=lambda: NOW)
    private_key = PrivateKey(b"\x01" * 32)
    chain_deadline = NOW + timedelta(seconds=120)
    predecessor_deadline = NOW + timedelta(seconds=240)
    first = signed_statement(
        private_key,
        nonce="b1" * 32,
        expires_at=timestamp_text(predecessor_deadline),
    )
    repository.apply(first, NOW)
    rotated = signed_statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="b2" * 32,
        expires_at=timestamp_text(chain_deadline),
    )
    repository.apply(rotated, NOW)

    snapshot = service.current_snapshot()

    assert snapshot["expiresAt"] == int(chain_deadline.timestamp() * 1000)
    assert snapshot["bindings"][0]["expiresAt"] == int(rotated.expires_at.timestamp() * 1000)


def test_snapshot_never_outlives_any_predecessor(repository):
    service = X25519IdentityBindingRegistry(repository, clock=lambda: NOW)
    private_key = PrivateKey(b"\x01" * 32)
    first_deadline = NOW + timedelta(seconds=240)
    earliest_deadline = NOW + timedelta(seconds=180)
    first = signed_statement(
        private_key,
        nonce="b3" * 32,
        expires_at=timestamp_text(first_deadline),
    )
    repository.apply(first, NOW)
    second = signed_statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="b4" * 32,
        expires_at=timestamp_text(earliest_deadline),
    )
    repository.apply(second, NOW)
    third = signed_statement(
        private_key,
        public_key=KEY_C,
        version=3,
        operation="rotate",
        prior=second.binding_id,
        nonce="b5" * 32,
        expires_at=timestamp_text(earliest_deadline),
    )
    repository.apply(third, NOW)

    snapshot = service.current_snapshot()

    assert snapshot["expiresAt"] == int(earliest_deadline.timestamp() * 1000)


def test_valid_chain_remains_readable_within_common_interval(repository):
    private_key = PrivateKey(b"\x01" * 32)
    predecessor_deadline = NOW + timedelta(seconds=240)
    chain_deadline = NOW + timedelta(seconds=180)
    first = signed_statement(
        private_key,
        nonce="c2" * 32,
        expires_at=timestamp_text(predecessor_deadline),
    )
    repository.apply(first, NOW)
    rotated = signed_statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="c3" * 32,
        expires_at=timestamp_text(chain_deadline),
    )
    repository.apply(rotated, NOW)

    immediate = X25519IdentityBindingRegistry(repository, clock=lambda: NOW).current_snapshot()
    later = X25519IdentityBindingRegistry(
        repository,
        clock=lambda: NOW + timedelta(seconds=120),
    ).current_snapshot()

    assert immediate["bindings"][0]["publicKey"] == KEY_B
    assert later["bindings"][0]["publicKey"] == KEY_B
    assert immediate["expiresAt"] == int(chain_deadline.timestamp() * 1000)
    assert later["expiresAt"] == int(chain_deadline.timestamp() * 1000)


def test_snapshot_rejects_persisted_successor_after_chain_deadline_without_mutation(repository):
    private_key = PrivateKey(b"\x01" * 32)
    chain_deadline = NOW + timedelta(seconds=120)
    first = signed_statement(
        private_key,
        nonce="cd" * 32,
        expires_at=timestamp_text(chain_deadline),
    )
    repository.apply(first, NOW)
    corrupt_row(repository, first.binding_id, active=False, retired_at=NOW)
    rotated = signed_statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="ce" * 32,
        expires_at=timestamp_text(chain_deadline + timedelta(seconds=1)),
    )
    insert_statement(repository, rotated, active=True, retired_at=None)

    assert_snapshot_rejects_without_mutation(repository)


@pytest.mark.parametrize("deadline_state", ["unavailable", "malformed", "expired"])
def test_snapshot_rejects_unavailable_malformed_or_expired_chain_deadline(monkeypatch, deadline_state):
    statement = parsed(monkeypatch, nonce="b6" * 32)

    class DeadlineRepository:
        def apply(self, statement, now):
            raise AssertionError

        def current_snapshot(self, now, maximum):
            if deadline_state == "unavailable":
                return [statement]
            if deadline_state == "malformed":
                return [SnapshotBinding(statement, "2026-08-24T12:05:00Z")]
            return [SnapshotBinding(statement, NOW - timedelta(seconds=1))]

    service = X25519IdentityBindingRegistry(DeadlineRepository(), clock=lambda: NOW)

    with pytest.raises(BindingRegistryUnavailable) as caught:
        service.current_snapshot()
    assert str(caught.value) == contract.UNAVAILABLE_MESSAGE


def test_injected_internal_clock_with_microseconds_is_truncated(monkeypatch, repository):
    monkeypatch.setattr(contract, "PublicKeyXOnly", AcceptingPublicKey)
    service = X25519IdentityBindingRegistry(
        repository,
        clock=lambda: NOW + timedelta(microseconds=987654),
    )
    candidate = payload(nonce="b7" * 32)

    assert service.apply(encoded(candidate), authenticated_subject=SUBJECT_A) == candidate
    snapshot = service.current_snapshot()

    assert snapshot["issuedAt"] == int(NOW.timestamp() * 1000)
    assert snapshot["bindings"][0]["publicKey"] == KEY_A
    assert stored_rows(repository)[0][-1].microsecond == 0


def test_default_service_clock_works_for_apply_and_snapshot(monkeypatch, repository):
    monkeypatch.setattr(contract, "PublicKeyXOnly", AcceptingPublicKey)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    candidate = payload(
        nonce="b8" * 32,
        valid_from=timestamp_text(now - timedelta(minutes=1)),
        expires_at=timestamp_text(now + timedelta(days=1)),
    )
    service = X25519IdentityBindingRegistry(repository)

    assert service.apply(encoded(candidate), authenticated_subject=SUBJECT_A) == candidate
    snapshot = service.current_snapshot()

    assert snapshot["bindings"][0]["publicKey"] == KEY_A


@pytest.mark.parametrize("field_name", ["valid_from", "expires_at"])
def test_external_timestamps_with_fractional_seconds_remain_rejected(monkeypatch, field_name):
    monkeypatch.setattr(contract, "PublicKeyXOnly", AcceptingPublicKey)
    values = {field_name: "2026-08-24T11:00:00.123Z"}
    if field_name == "expires_at":
        values[field_name] = "2026-08-25T12:00:00.123Z"

    with pytest.raises(BindingRegistryUnavailable):
        parse_and_verify_statement(encoded(payload(**values)), authenticated_subject=SUBJECT_A)


def test_operation_window_must_be_current_and_expiry_releases_active_key(monkeypatch, repository):
    future = parsed(monkeypatch)
    with pytest.raises(BindingRegistryUnavailable):
        repository.apply(future, NOW - timedelta(days=1))

    repository.apply(future, NOW)
    replacement = parsed(
        monkeypatch,
        subject=SUBJECT_B,
        public_key=KEY_A,
        nonce="99" * 32,
        valid_from="2026-08-26T11:00:00Z",
        expires_at="2026-08-27T12:00:00Z",
    )
    assert repository.apply(replacement, NOW + timedelta(days=2)) == replacement


def test_malformed_persisted_signature_fails_snapshot_closed(monkeypatch, repository):
    first = parsed(monkeypatch)
    repository.apply(first, NOW)
    with repository._session_factory() as session:
        session.execute(
            update(X25519IdentityBinding)
            .where(X25519IdentityBinding.binding_id == first.binding_id)
            .values(identity_signature="00" * 64)
        )
        session.commit()
    monkeypatch.undo()
    service = X25519IdentityBindingRegistry(repository, clock=lambda: NOW)
    with pytest.raises(BindingRegistryUnavailable):
        service.current_snapshot()


def test_snapshot_bounds_active_population_before_chain_validation(monkeypatch, repository):
    first = parsed(
        monkeypatch,
        subject=SUBJECT_A,
        public_key=KEY_A,
        nonce="f0" * 32,
    )
    second = parsed(
        monkeypatch,
        subject=SUBJECT_B,
        public_key=KEY_B,
        nonce="f1" * 32,
    )
    repository.apply(first, NOW)
    repository.apply(second, NOW)
    before = stored_rows(repository)
    calls = []

    def fail_if_called(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("chain validation must not run for oversized population")

    monkeypatch.setattr(storage, "_valid_authority_chain", fail_if_called)

    with pytest.raises(BindingRegistryUnavailable):
        repository.current_snapshot(NOW, 1)

    assert calls == []
    assert stored_rows(repository) == before


def test_snapshot_rejects_missing_predecessor_without_mutation(repository):
    private_key = PrivateKey(b"\x01" * 32)
    first = signed_statement(private_key, nonce="20" * 32)
    repository.apply(first, NOW)
    rotated = signed_statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="21" * 32,
    )
    repository.apply(rotated, NOW)
    delete_row(repository, first.binding_id)

    assert_snapshot_rejects_without_mutation(repository)


def test_snapshot_rejects_partial_predecessor_without_mutation(repository):
    private_key = PrivateKey(b"\x01" * 32)
    first = signed_statement(private_key, nonce="22" * 32)
    repository.apply(first, NOW)
    rotated = signed_statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="23" * 32,
    )
    repository.apply(rotated, NOW)
    corrupt_row(repository, first.binding_id, retired_at=None)

    assert_snapshot_rejects_without_mutation(repository)


def test_snapshot_rejects_cross_subject_predecessor_without_mutation(repository):
    private_key_a = PrivateKey(b"\x01" * 32)
    private_key_b = PrivateKey(b"\x02" * 32)
    first_b = signed_statement(private_key_b, public_key=KEY_A, nonce="24" * 32)
    repository.apply(first_b, NOW)
    corrupt_row(repository, first_b.binding_id, active=False, retired_at=NOW)
    cross_subject_current = signed_statement(
        private_key_a,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first_b.binding_id,
        nonce="25" * 32,
    )
    insert_statement(repository, cross_subject_current, active=True, retired_at=None)

    assert_snapshot_rejects_without_mutation(repository)


def test_snapshot_rejects_cyclic_predecessor_chain_without_mutation(monkeypatch, repository):
    monkeypatch.setattr(contract, "PublicKeyXOnly", AcceptingPublicKey)
    monkeypatch.setattr(contract, "statement_digest", lambda core: core["nonce"])
    cycle_v2 = forged_statement(
        version=2,
        operation="rotate",
        prior="03" * 32,
        nonce="02" * 32,
    )
    cycle_v3 = forged_statement(
        public_key=KEY_B,
        version=3,
        operation="rotate",
        prior=cycle_v2.binding_id,
        nonce="03" * 32,
    )
    insert_statement(repository, cycle_v2, active=False, retired_at=NOW)
    insert_statement(repository, cycle_v3, active=True, retired_at=None)

    assert_snapshot_rejects_without_mutation(repository)


def test_snapshot_rejects_skipped_or_broken_version_without_mutation(repository):
    private_key = PrivateKey(b"\x01" * 32)
    first = signed_statement(private_key, nonce="26" * 32)
    repository.apply(first, NOW)
    corrupt_row(repository, first.binding_id, active=False, retired_at=NOW)
    broken_current = signed_statement(
        private_key,
        public_key=KEY_B,
        version=3,
        operation="rotate",
        prior=first.binding_id,
        nonce="27" * 32,
    )
    insert_statement(repository, broken_current, active=True, retired_at=None)

    assert_snapshot_rejects_without_mutation(repository)


@pytest.mark.parametrize(
    "target,changes",
    [
        ("predecessor", {"statement_sha256": "aa" * 32}),
        ("current", {"prior_binding_id": "ab" * 32}),
    ],
)
def test_snapshot_rejects_digest_or_predecessor_mismatch_without_mutation(repository, target, changes):
    private_key = PrivateKey(b"\x01" * 32)
    first = signed_statement(private_key, nonce="28" * 32)
    repository.apply(first, NOW)
    rotated = signed_statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="29" * 32,
    )
    repository.apply(rotated, NOW)
    corrupt_row(repository, first.binding_id if target == "predecessor" else rotated.binding_id, **changes)

    assert_snapshot_rejects_without_mutation(repository)


def test_snapshot_rejects_expired_predecessor_without_mutation(repository):
    private_key = PrivateKey(b"\x01" * 32)
    first = signed_statement(
        private_key,
        nonce="2a" * 32,
        valid_from="2026-08-23T10:00:00Z",
        expires_at="2026-08-24T11:30:00Z",
    )
    repository.apply(first, NOW - timedelta(hours=2))
    corrupt_row(repository, first.binding_id, active=False, retired_at=NOW - timedelta(minutes=45))
    rotated = signed_statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="2b" * 32,
        valid_from="2026-08-24T11:00:00Z",
        expires_at="2026-08-25T12:00:00Z",
    )
    insert_statement(repository, rotated, active=True, retired_at=None)

    assert_snapshot_rejects_without_mutation(repository)


def test_snapshot_rejects_validly_signed_rotate_row_with_invalid_chain(repository):
    private_key = PrivateKey(b"\x01" * 32)
    rotated = signed_statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior="bb" * 32,
        nonce="2c" * 32,
    )
    insert_statement(repository, rotated, active=True, retired_at=None)

    assert_snapshot_rejects_without_mutation(repository)


def test_persisted_real_bip340_same_key_rotation_rejected_by_snapshot(repository):
    private_key = PrivateKey(b"\x01" * 32)
    insert_same_key_rotation(repository, private_key, first_nonce="c4", rotate_nonce="c5")

    assert_snapshot_rejects_without_mutation(repository)


def test_persisted_same_key_rotation_cannot_authorize_later_rotation_or_revocation(repository):
    private_key = PrivateKey(b"\x01" * 32)
    _, same_key = insert_same_key_rotation(
        repository,
        private_key,
        first_nonce="c6",
        rotate_nonce="c7",
    )
    next_rotation = signed_statement(
        private_key,
        public_key=KEY_B,
        version=3,
        operation="rotate",
        prior=same_key.binding_id,
        nonce="c8" * 32,
    )
    revoked = signed_statement(
        private_key,
        version=3,
        operation="revoke",
        prior=same_key.binding_id,
        nonce="c9" * 32,
    )

    assert_rejects_without_mutation(repository, next_rotation)
    assert_rejects_without_mutation(repository, revoked)


def test_persisted_same_key_rotation_cannot_authorize_revocation_replay(repository):
    private_key = PrivateKey(b"\x01" * 32)
    _, same_key = insert_same_key_rotation(
        repository,
        private_key,
        active=False,
        first_nonce="ca",
        rotate_nonce="cb",
    )
    revoked = signed_statement(
        private_key,
        version=3,
        operation="revoke",
        prior=same_key.binding_id,
        nonce="cc" * 32,
    )
    insert_statement(repository, revoked)

    assert_rejects_without_mutation(repository, revoked)


def test_active_revoke_row_alone_fails_snapshot_generically_without_mutation(repository):
    private_key = PrivateKey(b"\x01" * 32)
    first = signed_statement(private_key, nonce="e0" * 32)
    repository.apply(first, NOW)
    revoked = signed_statement(
        private_key,
        version=2,
        operation="revoke",
        prior=first.binding_id,
        nonce="e1" * 32,
    )
    repository.apply(revoked, NOW)
    corrupt_row(repository, revoked.binding_id, active=True, retired_at=None)

    assert active_rows(repository) == [(revoked.binding_id, KEY_A, "revoke")]
    assert_snapshot_rejects_without_mutation(repository)


def test_active_revoke_row_blocks_valid_member_without_partial_snapshot(repository):
    service = X25519IdentityBindingRegistry(repository, clock=lambda: NOW)
    private_key_a = PrivateKey(b"\x01" * 32)
    private_key_b = PrivateKey(b"\x02" * 32)
    first = signed_statement(private_key_a, nonce="e2" * 32)
    repository.apply(first, NOW)
    revoked = signed_statement(
        private_key_a,
        version=2,
        operation="revoke",
        prior=first.binding_id,
        nonce="e3" * 32,
    )
    repository.apply(revoked, NOW)
    corrupt_row(repository, revoked.binding_id, active=True, retired_at=None)
    valid = signed_statement(private_key_b, public_key=KEY_B, nonce="e4" * 32)
    repository.apply(valid, NOW)
    before = stored_rows(repository)

    with pytest.raises(BindingRegistryUnavailable) as caught:
        service.current_snapshot()

    assert str(caught.value) == contract.UNAVAILABLE_MESSAGE
    assert stored_rows(repository) == before


def test_inactive_revoke_history_is_ignored_while_valid_current_bindings_remain_readable(repository):
    service = X25519IdentityBindingRegistry(repository, clock=lambda: NOW)
    private_key_a = PrivateKey(b"\x01" * 32)
    private_key_b = PrivateKey(b"\x02" * 32)
    first = signed_statement(private_key_a, nonce="e5" * 32)
    repository.apply(first, NOW)
    revoked = signed_statement(
        private_key_a,
        version=2,
        operation="revoke",
        prior=first.binding_id,
        nonce="e6" * 32,
    )
    repository.apply(revoked, NOW)
    valid = signed_statement(private_key_b, public_key=KEY_B, nonce="e7" * 32)
    repository.apply(valid, NOW)
    before = stored_rows(repository)

    snapshot = service.current_snapshot()

    assert stored_rows(repository) == before
    assert snapshot["bindings"] == [
        {
            "snapshotId": snapshot["snapshotId"],
            "subject": valid.subject,
            "algorithm": contract.ALGORITHM,
            "version": 1,
            "publicKey": KEY_B,
            "validFrom": int(valid.valid_from.timestamp() * 1000),
            "expiresAt": int(valid.expires_at.timestamp() * 1000),
            "revoked": False,
        }
    ]


def test_corrupt_member_fails_whole_snapshot_generically_without_partial_bindings(repository):
    service = X25519IdentityBindingRegistry(repository, clock=lambda: NOW)
    private_key_a = PrivateKey(b"\x01" * 32)
    private_key_b = PrivateKey(b"\x02" * 32)
    valid = signed_statement(private_key_a, public_key=KEY_A, nonce="2d" * 32)
    repository.apply(valid, NOW)
    invalid = signed_statement(
        private_key_b,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior="bc" * 32,
        nonce="2e" * 32,
    )
    insert_statement(repository, invalid, active=True, retired_at=None)
    before = stored_rows(repository)

    with pytest.raises(BindingRegistryUnavailable) as caught:
        service.current_snapshot()

    assert str(caught.value) == contract.UNAVAILABLE_MESSAGE
    assert stored_rows(repository) == before


def test_snapshot_returns_valid_real_bip340_rotation_chain_without_mutation(repository):
    service = X25519IdentityBindingRegistry(repository, clock=lambda: NOW)
    private_key = PrivateKey(b"\x01" * 32)
    first = signed_statement(private_key, nonce="2f" * 32)
    repository.apply(first, NOW)
    rotated = signed_statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="30" * 32,
    )
    repository.apply(rotated, NOW)
    before = stored_rows(repository)

    snapshot = service.current_snapshot()

    assert snapshot["bindings"] == [
        {
            "snapshotId": snapshot["snapshotId"],
            "subject": rotated.subject,
            "algorithm": contract.ALGORITHM,
            "version": 2,
            "publicKey": KEY_B,
            "validFrom": int(rotated.valid_from.timestamp() * 1000),
            "expiresAt": int(rotated.expires_at.timestamp() * 1000),
            "revoked": False,
        }
    ]
    assert stored_rows(repository) == before


def test_transaction_failures_are_generic_and_entitlement_is_not_a_registry_input(monkeypatch):
    class FailedRepository:
        def apply(self, statement, now):
            raise RuntimeError("detail")

        def current_snapshot(self, now, maximum):
            raise RuntimeError("detail")

    service = X25519IdentityBindingRegistry(FailedRepository(), clock=lambda: NOW)
    with pytest.raises(BindingRegistryUnavailable) as caught:
        service.current_snapshot()
    assert str(caught.value) == contract.UNAVAILABLE_MESSAGE
    monkeypatch.setattr(contract, "PublicKeyXOnly", AcceptingPublicKey)
    with pytest.raises(BindingRegistryUnavailable) as caught:
        service.apply(encoded(payload()), authenticated_subject=SUBJECT_A)
    assert str(caught.value) == contract.UNAVAILABLE_MESSAGE
    assert "entitlement" not in X25519IdentityBinding.__table__.columns


def test_sqlalchemy_transaction_open_failure_is_fail_closed(monkeypatch):
    class BrokenTransaction:
        def __enter__(self):
            raise RuntimeError("database detail")

        def __exit__(self, *args):
            return False

    repository = SqlAlchemyX25519IdentityBindingRepository(lambda: BrokenTransaction())
    statement = parsed(monkeypatch)
    with pytest.raises(BindingRegistryUnavailable):
        repository.apply(statement, NOW)
    with pytest.raises(BindingRegistryUnavailable):
        repository.current_snapshot(NOW, 1)


@pytest.mark.parametrize(
    "key",
    ["AA" * 32, "00" * 32, "01" + "00" * 31, "09" + "00" * 30 + "80", "f6" + "ff" * 30 + "7f"],
)
def test_noncanonical_and_prohibited_public_values(key):
    with pytest.raises(ValueError):
        validate_x25519_public_key(key)
