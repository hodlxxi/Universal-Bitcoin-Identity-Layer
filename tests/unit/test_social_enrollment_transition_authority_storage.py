from __future__ import annotations

import ast
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.services import social_enrollment_transition_authority as contract
from app.services import social_enrollment_transition_authority_storage as storage
from app.services import social_messaging_device_admission_contract as admission
from app.services import social_messaging_device_ed25519_association_lifecycle as lifecycle
from app.services.social_device_challenge_store import DeviceAdmissionChallengeV1
from app.services.social_device_verification_statement import AuthenticatedSocialDeviceVerificationStatementV1

ROOT = Path(__file__).parents[2]
VECTORS = json.loads(
    (ROOT / "tests/fixtures/social_enrollment_transition_authority_effect_identity_v1.json").read_bytes()
)
LIFECYCLE = json.loads(
    (ROOT / "tests/fixtures/social_messaging_device_ed25519_association_lifecycle_v1.json").read_bytes()
)
SOURCE = ROOT / "app/services/social_enrollment_transition_authority_storage.py"
ERROR = "^social enrollment transition authority storage unavailable$"
REAL_CHALLENGE_STORE = storage.SqlAlchemyDeviceChallengeStore


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def statement(facts: dict[str, object]) -> AuthenticatedSocialDeviceVerificationStatementV1:
    result = object.__new__(AuthenticatedSocialDeviceVerificationStatementV1)
    for name, item in facts.items():
        object.__setattr__(result, name, item)
    return result


class FakeChallengeStore:
    record = None

    def __init__(self, _session):
        pass

    def read_for_update(self, _challenge_id):
        if self.record is None:
            raise ValueError
        return self.record


class FakeCurrentAuthority:
    final = None
    fail = False

    def __init__(self, _session, **_kwargs):
        pass

    def _lock_non_ed25519_authority(self, context, *, observed_at):
        if self.fail:
            raise ValueError
        return SimpleNamespace(context=context, observed_at=observed_at)

    def _finalize_non_ed25519_authority(self, _locked):
        if self.fail or self.final is None:
            raise ValueError
        return self.final


class FakeEd25519Store:
    evidence = None

    def __init__(self, _session):
        pass

    def lock_lifecycle(self, _subject, _device_id):
        if self.evidence is None:
            raise ValueError
        return self.evidence


@pytest.fixture(autouse=True)
def composed_owners(monkeypatch):
    monkeypatch.setattr(storage, "SqlAlchemyDeviceChallengeStore", FakeChallengeStore)
    monkeypatch.setattr(storage, "SqlAlchemyTransactionBoundAdmissionAuthority", FakeCurrentAuthority)
    monkeypatch.setattr(storage, "SqlAlchemyEd25519AssociationStore", FakeEd25519Store)
    FakeChallengeStore.record = None
    FakeCurrentAuthority.final = None
    FakeCurrentAuthority.fail = False
    FakeEd25519Store.evidence = None


def configured(name: str, *, state: str = "issued"):
    vector = VECTORS["vectors"][name]
    value = admission.parse_verification_input_v1(vector["inputWire"])
    enrollment = json.loads(value.challenge_wire)
    FakeChallengeStore.record = DeviceAdmissionChallengeV1(
        context=value.context,
        challenge_wire=value.challenge_wire,
        actual_request_wire=None,
        routing_request_wire=None,
        operation="enrollment-activate",
        issued_at=enrollment["issuedAt"],
        expires_at=enrollment["expiresAt"],
        state=state,
    )
    FakeCurrentAuthority.final = SimpleNamespace(
        locked_deadline_ms=vector["lockedDeadlineMs"] + 1_000,
        full_proof_id=value.context.full_proof_id,
        approver_full_proof_id=value.context.approver_full_proof_id,
    )
    FakeEd25519Store.evidence = lifecycle.AssociationLifecycleV1(
        tuple(lifecycle.parse_association_event_v1(LIFECYCLE["eventWires"][item]) for item in vector["priorEvents"])
    )
    adapter = storage.SqlAlchemyTransactionBoundEnrollmentTransitionAuthority(
        object(),
        device_issuance_id="11" * 32,
        device_client_id="device-client",
        oauth_issuer="https://identity.example",
        approver_oauth_session_id="22" * 32,
        approver_client_id="approver-client",
    )
    return adapter, value, statement(vector["statementFacts"]), vector


def denied(callable_) -> None:
    with pytest.raises(storage.SocialEnrollmentTransitionAuthorityStorageUnavailable, match=ERROR) as failure:
        callable_()
    assert failure.value.__cause__ is failure.value.__context__ is None


@pytest.mark.parametrize(
    ("name", "transition_kind"),
    (("initial", "initial"), ("rotation", "rotate"), ("reenrollment", "reenroll")),
)
def test_locked_initial_rotation_and_reenrollment_return_only_typed_pre_effect_authority(
    name,
    transition_kind,
):
    adapter, value, authenticated, vector = configured(name)
    result = adapter.lock_transition_authority(
        value,
        authenticated,
        observed_at=vector["observedAt"],
    )
    assert type(result) is contract.EnrollmentTransitionAuthorityV1
    assert result.transition_kind == transition_kind
    assert result.proposed_association_id == value.context.association_id
    assert result.locked_deadline_ms == vector["lockedDeadlineMs"]
    assert contract.prepared_enrollment_effect_v1(result).operation == "enrollment-activate"
    assert storage.FINAL_ADMISSION == "denied"


def test_proposed_successor_is_not_required_to_be_current():
    adapter, value, authenticated, vector = configured("rotation")
    snapshot = lifecycle.association_snapshot_v1(FakeEd25519Store.evidence)
    assert snapshot.current.association_id == value.context.predecessor_association_id
    assert snapshot.current.association_id != value.context.association_id
    result = adapter.lock_transition_authority(value, authenticated, observed_at=vector["observedAt"])
    assert result.proposed_association_id == value.context.association_id
    assert result.pre_effect_association_id == snapshot.current.association_id


@pytest.mark.parametrize("state", ("consumed", "expired", "invalidated", "cancelled"))
def test_exact_issued_nonterminal_challenge_is_required(state):
    adapter, value, authenticated, vector = configured("initial", state=state)
    denied(lambda: adapter.lock_transition_authority(value, authenticated, observed_at=vector["observedAt"]))


def test_missing_mismatched_and_exactly_expired_challenge_are_denied():
    adapter, value, authenticated, vector = configured("initial")
    FakeChallengeStore.record = None
    denied(lambda: adapter.lock_transition_authority(value, authenticated, observed_at=vector["observedAt"]))

    adapter, value, authenticated, vector = configured("initial")
    configured("rotation")
    mismatched = FakeChallengeStore.record
    FakeChallengeStore.record = mismatched
    denied(lambda: adapter.lock_transition_authority(value, authenticated, observed_at=vector["observedAt"]))

    adapter, value, authenticated, _vector = configured("initial")
    denied(
        lambda: adapter.lock_transition_authority(
            value,
            authenticated,
            observed_at=FakeChallengeStore.record.expires_at,
        )
    )


def test_authenticated_statement_exact_type_and_bindings_are_required():
    adapter, value, authenticated, vector = configured("initial")
    denied(lambda: adapter.lock_transition_authority(value, object(), observed_at=vector["observedAt"]))

    adapter, value, _authenticated, vector = configured("initial")
    facts = dict(vector["statementFacts"], attempt_id="33" * 32)
    denied(
        lambda: adapter.lock_transition_authority(
            value,
            statement(facts),
            observed_at=vector["observedAt"],
        )
    )

    adapter, value, _authenticated, vector = configured("initial")
    facts = dict(vector["statementFacts"], expires_at=vector["observedAt"])
    denied(
        lambda: adapter.lock_transition_authority(
            value,
            statement(facts),
            observed_at=vector["observedAt"],
        )
    )


def test_non_ed25519_authority_failure_and_full_identity_mismatch_are_denied():
    adapter, value, authenticated, vector = configured("initial")
    FakeCurrentAuthority.fail = True
    denied(lambda: adapter.lock_transition_authority(value, authenticated, observed_at=vector["observedAt"]))

    adapter, value, authenticated, vector = configured("initial")
    FakeCurrentAuthority.final.full_proof_id = "hodlxxi-full-entitlement-v1-sha256:" + "44" * 32
    denied(lambda: adapter.lock_transition_authority(value, authenticated, observed_at=vector["observedAt"]))


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("predecessorAssociationId", "55" * 32),
        ("associationVersion", 9),
        ("authorityEpoch", 9),
    ),
)
def test_stale_predecessor_wrong_version_and_wrong_epoch_are_denied(field, replacement):
    adapter, value, authenticated, vector = configured("rotation")
    input_fields = json.loads(value.wire)
    context_fields = json.loads(value.context.wire)
    context_fields[field] = replacement
    input_fields["context"] = canonical(context_fields)
    changed = admission.parse_verification_input_v1(canonical(input_fields))
    facts = dict(
        vector["statementFacts"],
        context_digest=admission.verification_context_digest_v1(changed.context.wire),
        input_digest=admission.verification_input_digest_v1(changed.wire),
    )
    FakeChallengeStore.record = DeviceAdmissionChallengeV1(
        changed.context,
        changed.challenge_wire,
        None,
        None,
        "enrollment-activate",
        FakeChallengeStore.record.issued_at,
        FakeChallengeStore.record.expires_at,
        "issued",
    )
    FakeCurrentAuthority.final.full_proof_id = changed.context.full_proof_id
    FakeCurrentAuthority.final.approver_full_proof_id = changed.context.approver_full_proof_id
    denied(lambda: adapter.lock_transition_authority(changed, statement(facts), observed_at=vector["observedAt"]))


def test_sqlite_is_never_an_authority_backend(monkeypatch):
    monkeypatch.setattr(storage, "SqlAlchemyDeviceChallengeStore", REAL_CHALLENGE_STORE)
    engine = create_engine("sqlite:///:memory:")
    factory = sessionmaker(engine)
    try:
        with factory.begin() as session:
            denied(
                lambda: storage.SqlAlchemyTransactionBoundEnrollmentTransitionAuthority(
                    session,
                    device_issuance_id="11" * 32,
                    device_client_id="device-client",
                    oauth_issuer="https://identity.example",
                    approver_oauth_session_id="22" * 32,
                    approver_client_id="approver-client",
                )
            )
    finally:
        engine.dispose()


def test_source_is_read_only_dormant_and_has_explicit_time():
    source = SOURCE.read_text(encoding="ascii")
    ast.parse(source)
    assert storage.RUNTIME_ENABLED is False
    assert storage.CHALLENGE_CONSUMPTION == "not_implemented"
    assert storage.EFFECT_EXECUTION == "not_implemented"
    assert storage.RECEIPT_ISSUANCE == "not_implemented"
    assert storage.FINAL_ADMISSION == "denied"
    assert source.index("read_for_update") < source.index("_lock_non_ed25519_authority")
    assert source.index("_lock_non_ed25519_authority") < source.index("lock_lifecycle")
    for forbidden in (
        "datetime.now(",
        "time.time(",
        "NOW()",
        ".commit(",
        ".rollback(",
        ".close(",
        "sessionmaker(",
        "create_engine(",
        "DATABASE_URL",
        "redis",
        "AdmissionReceiptV1(",
        ".establish_initial(",
        ".rotate(",
        ".reenroll(",
        ".revoke(",
    ):
        assert forbidden not in source
