"""Offline contract tests for the dormant current-handle candidate check."""

from __future__ import annotations

import inspect
import json
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services import social_messaging_active_alias_namespace_storage as active_namespace
from app.services import social_messaging_current_handle_candidate as candidate
from app.services import social_messaging_device_admission_contract as admission
from app.services import social_messaging_recipient_routing_storage as routing_storage
from app.services.social_messaging_device_contract import MessagingDeviceBinding

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/social_device_admission_v1.json"
ALIAS_SECRET = bytes(range(32))
DENIED = candidate.SocialMessagingCurrentHandleCandidateUnavailable
ERROR = "^social messaging current handle candidate unavailable$"


class Result:
    def __init__(self, scalar=None):
        self.scalar = scalar

    def scalar_one(self):
        return self.scalar


class Session:
    def __init__(self, parsed: admission.VerificationInputV1, observed_at: int):
        self.transaction = SimpleNamespace(is_active=True)
        self.nested = None
        self.database_transaction = SimpleNamespace(is_active=True)
        self.database_nested = None
        self.is_active = True
        self.new, self.dirty, self.deleted = set(), set(), set()
        self.driver = SimpleNamespace(autocommit=False)
        self.events = []
        self.namespace_values = [namespace()]
        request = admission._parse_request(parsed.actual_request_wire)
        self.owner = routing_storage._RecipientHandleOwnerV1(
            device_handle=request["recipientHandle"],
            viewer_subject="02" * 32,
            recipient_subject=parsed.context.subject,
            alias_version=1,
            device_id=parsed.context.device_id,
            binding_id=parsed.context.binding_id,
            binding_version=parsed.context.binding_version,
        )
        instant = datetime.fromtimestamp(observed_at / 1000, timezone.utc)
        self.binding = MessagingDeviceBinding(
            subject=parsed.context.subject,
            device_id=parsed.context.device_id,
            binding_id=parsed.context.binding_id,
            public_key="03" * 32,
            binding_version=parsed.context.binding_version,
            valid_from=instant - timedelta(seconds=1),
            expires_at=instant + timedelta(seconds=60),
            operation="register" if parsed.context.binding_version == 1 else "rotate",
            prior_binding_id=None if parsed.context.binding_version == 1 else "04" * 32,
            request_id="05" * 32,
            active=True,
        )
        self.authority_values = [authority_for(parsed.context, observed_at)]
        self.bound_connection = SimpleNamespace(
            closed=False,
            invalidated=False,
            in_transaction=self.in_transaction,
            get_transaction=lambda: self.database_transaction,
            get_nested_transaction=lambda: self.database_nested,
            connection=SimpleNamespace(dbapi_connection=self.driver),
            execute=self.execute,
        )

    def get_transaction(self):
        return self.transaction

    def get_nested_transaction(self):
        return self.nested

    def in_transaction(self):
        return self.transaction is not None

    def get_bind(self):
        return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

    def connection(self):
        return self.bound_connection

    def execute(self, statement, _parameters=None):
        if str(statement) == "SHOW transaction_isolation":
            return Result("read committed")
        raise AssertionError(str(statement))


class Authority:
    def __init__(self, session, **_kwargs):
        self.session = session

    def lock_current_authority(self, context, *, observed_at):
        self.session.events.append("current-authority")
        assert context.challenge_kind == "device-request-v1"
        assert type(observed_at) is int
        values = self.session.authority_values
        return values.pop(0) if len(values) > 1 else values[0]


class Namespace:
    def __init__(self, session, **_kwargs):
        self.session = session

    def lock_configured_active_namespace(self):
        self.session.events.append("active-namespace")
        values = self.session.namespace_values
        return values.pop(0) if len(values) > 1 else values[0]


class History:
    def __init__(self, session):
        self.session = session

    def lock_historical_handle_owner(self, requested_handle):
        self.session.events.append("historical-owner")
        if self.session.owner is not None:
            assert requested_handle == self.session.owner.device_handle
        return self.session.owner


class Bindings:
    def __init__(self, session):
        self.session = session

    def binding_for_id(self, binding_id):
        self.session.events.append("current-binding")
        if self.session.binding is not None:
            assert binding_id == self.session.binding.binding_id
        return self.session.binding


def vector(name="recipientSelfRead"):
    return json.loads(FIXTURE.read_text(encoding="ascii"))["vectors"][name]


def parsed_input(name="recipientSelfRead"):
    value = vector(name)
    return admission.parse_verification_input_v1(value["inputWire"]), value["now"]


def namespace(version=1):
    return active_namespace.LockedActiveAliasNamespaceV1(
        alias_version=version,
        secret_commitment=active_namespace.active_alias_namespace_secret_commitment(
            alias_secret=ALIAS_SECRET,
            alias_version=version,
        ),
        lifecycle_state=active_namespace.ACTIVE_NAMESPACE_STATE,
    )


def authority_for(context, observed_at, *, deadline_delta=60_000):
    return admission.CurrentAdmissionAuthorityV1(
        context_digest=admission.verification_context_digest_v1(context.wire),
        authority_epoch=context.authority_epoch,
        locked_deadline_ms=observed_at + deadline_delta,
        full_proof_id=context.full_proof_id,
        approver_full_proof_id=None,
    )


@pytest.fixture(autouse=True)
def synthetic_adapters(monkeypatch):
    monkeypatch.setattr(
        candidate.current_authority,
        "SqlAlchemyTransactionBoundAdmissionAuthority",
        Authority,
    )
    monkeypatch.setattr(
        candidate.active_namespace,
        "SqlAlchemyTransactionBoundActiveAliasNamespaceReader",
        Namespace,
    )
    monkeypatch.setattr(
        candidate.routing_storage,
        "SqlAlchemyRecipientRoutingRepository",
        History,
    )
    monkeypatch.setattr(
        candidate,
        "SqlAlchemyTransactionBoundSocialMessagingDeviceStorage",
        Bindings,
    )


def checker(session):
    return candidate.SqlAlchemyTransactionBoundCurrentHandleCandidate(
        session,
        device_issuance_id="11" * 32,
        device_client_id="social-viewer-v1",
        oauth_issuer="https://identity.example",
        configured_alias_secret=ALIAS_SECRET,
        configured_alias_version=1,
    )


def test_exact_self_read_request_is_compared_in_lock_order_but_grants_nothing():
    parsed, now = parsed_input()
    session = Session(parsed, now)
    value = checker(session)
    result = value.check_recipient_self_read_candidate(parsed.wire, observed_at=now)

    assert result.requested_handle == session.owner.device_handle
    assert result.alias_version == 1
    assert result.context_digest == admission.verification_context_digest_v1(parsed.context.wire)
    assert result.comparison == "exact_current_candidate_match"
    assert result.authorization == "not_granted"
    assert result.recipient_self_read == "not_granted"
    assert result.ciphertext == "not_returned"
    assert session.events == [
        "current-authority",
        "active-namespace",
        "historical-owner",
        "active-namespace",
        "current-binding",
        "current-authority",
        "active-namespace",
    ]
    with pytest.raises(FrozenInstanceError):
        result.authorization = "granted"
    assert ALIAS_SECRET not in value.__dict__.values()


def test_only_strict_wire_is_input_and_detached_authority_is_not_accepted():
    signature = inspect.signature(
        candidate.SqlAlchemyTransactionBoundCurrentHandleCandidate.check_recipient_self_read_candidate
    )
    assert tuple(signature.parameters) == ("self", "verification_input_wire", "observed_at")
    assert not {"authority", "subject", "device_id", "binding_id", "binding_version", "handle"}.intersection(
        signature.parameters
    )

    parsed, now = parsed_input()
    value = checker(Session(parsed, now))
    detached = authority_for(parsed.context, now)
    with pytest.raises(TypeError):
        value.check_recipient_self_read_candidate(parsed.wire, observed_at=now, authority=detached)


@pytest.mark.parametrize(
    "mutation",
    (
        "unknown-owner",
        "old-alias-version",
        "wrong-recipient",
        "wrong-device",
        "wrong-binding",
        "wrong-binding-version",
        "inactive-binding",
        "expired-binding",
        "rotated-namespace-after-owner",
        "changed-authority-after-owner",
    ),
)
def test_ambiguity_revocation_rotation_and_every_exact_mismatch_share_one_failure(mutation):
    parsed, now = parsed_input()
    session = Session(parsed, now)
    if mutation == "unknown-owner":
        session.owner = None
    elif mutation == "old-alias-version":
        session.owner = replace(session.owner, alias_version=2)
    elif mutation == "wrong-recipient":
        session.owner = replace(session.owner, recipient_subject="09" * 32)
    elif mutation == "wrong-device":
        session.owner = replace(session.owner, device_id="09" * 32)
    elif mutation == "wrong-binding":
        session.owner = replace(session.owner, binding_id="09" * 32)
    elif mutation == "wrong-binding-version":
        session.owner = replace(session.owner, binding_version=session.owner.binding_version + 1)
    elif mutation == "inactive-binding":
        session.binding = replace(session.binding, active=False)
    elif mutation == "expired-binding":
        instant = datetime.fromtimestamp(now / 1000, timezone.utc)
        session.binding = replace(session.binding, expires_at=instant)
    elif mutation == "rotated-namespace-after-owner":
        session.namespace_values = [namespace(1), namespace(2)]
    else:
        session.authority_values = [
            authority_for(parsed.context, now),
            authority_for(parsed.context, now, deadline_delta=59_000),
        ]

    with pytest.raises(DENIED, match=ERROR) as failure:
        checker(session).check_recipient_self_read_candidate(parsed.wire, observed_at=now)
    assert failure.value.__cause__ is failure.value.__context__ is None


@pytest.mark.parametrize(
    "wire,observed",
    (
        ("{}", 1),
        (None, 1),
        (vector("ciphertextSubmit")["inputWire"], vector("ciphertextSubmit")["now"]),
        (vector()["inputWire"], True),
    ),
)
def test_noncanonical_non_self_read_and_invalid_time_inputs_share_one_failure(wire, observed):
    parsed, now = parsed_input()
    with pytest.raises(DENIED, match=ERROR) as failure:
        checker(Session(parsed, now)).check_recipient_self_read_candidate(wire, observed_at=observed)
    assert failure.value.__cause__ is failure.value.__context__ is None


def test_source_is_dormant_has_no_handle_derivation_or_effect_surface():
    source = (ROOT / "app/services/social_messaging_current_handle_candidate.py").read_text(encoding="utf-8")
    for forbidden in (
        "derive_recipient_device_handle(",
        "create_engine(",
        "sessionmaker(",
        ".commit(",
        ".rollback(",
        ".close(",
        "requests.",
        "socket.",
        "ciphertext =",
        'authorization = "granted"',
    ):
        assert forbidden not in source
    assert candidate.RUNTIME_ENABLED is False
    assert candidate.AUTHORIZATION == candidate.RECIPIENT_SELF_READ == "not_granted"
    assert candidate.CIPHERTEXT == "not_returned"
