import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

import app.services.social_messaging_recipient_routing as routing
from app.services.privacy_safe_full_directory import derive_privacy_directory_alias
from app.services.social_messaging_device_contract import MessagingDeviceBinding
from app.services.social_messaging_recipient_routing import (
    DECISION_SCHEMA,
    REQUEST_SCHEMA,
    RecipientMessagingRoutingUnavailable,
    RecipientRoutingDecision,
    RecipientRoutingRequest,
    SocialMessagingRecipientRoutingGateV1,
    VerifiedBindingAuthorization,
    VerifiedCurrentFullEntitlement,
    canonical_routing_decision_bytes,
    canonical_routing_request_bytes,
    canonical_routing_snapshot_bytes,
    derive_recipient_device_handle,
    parse_recipient_routing_request,
)

NOW = datetime(2026, 9, 5, 20, 0, 0, tzinfo=timezone.utc)
NOW_MS = int(NOW.timestamp() * 1000)
VIEWER_A = "01" * 32
VIEWER_B = "02" * 32
RECIPIENT = "03" * 32
OTHER_RECIPIENT = "04" * 32
ALIAS_SECRET = bytes(range(32))
MESSAGE_ID = "m_" + "AQ" + "A" * 41
ENVELOPE_DIGEST = "hodlxxi-social-message-envelope-v1-sha256:" + "ab" * 32
ERROR = "recipient messaging routing unavailable"


def _hex(number):
    return f"{number:064x}"


def make_binding(index=1, *, subject=RECIPIENT, version=1, expires_at=None):
    return MessagingDeviceBinding(
        subject=subject,
        device_id=_hex(100 + index),
        binding_id=_hex(200 + index),
        public_key=_hex(300 + index),
        binding_version=version,
        valid_from=NOW - timedelta(seconds=1),
        expires_at=expires_at or NOW + timedelta(seconds=600),
        operation="register" if version == 1 else "rotate",
        prior_binding_id=None if version == 1 else _hex(800 + index),
        request_id=_hex(400 + index),
        active=True,
    )


def proof_id(binding):
    digest = hashlib.sha256((binding.subject + binding.binding_id).encode("ascii")).hexdigest()
    return "hodlxxi-binding-authorization-v1-sha256:" + digest


class BindingVerifier:
    def __init__(self, mutate=None, error=None):
        self.mutate = mutate
        self.error = error
        self.calls = []

    def verify(self, binding, *, now):
        self.calls.append((binding, now))
        if self.error:
            raise self.error
        evidence = VerifiedBindingAuthorization(
            proof_id=proof_id(binding),
            subject=binding.subject,
            device_id=binding.device_id,
            binding_id=binding.binding_id,
            binding_version=binding.binding_version,
            public_key=binding.public_key,
            valid_from=binding.valid_from,
            expires_at=binding.expires_at,
            evidence_valid_from=NOW - timedelta(seconds=2),
            evidence_expires_at=NOW + timedelta(seconds=400),
        )
        return self.mutate(evidence) if self.mutate else evidence


class FullVerifier:
    def __init__(self, mutate=None, error=None):
        self.mutate = mutate
        self.error = error

    def verify(self, subject, *, now):
        if self.error:
            raise self.error
        digest = hashlib.sha256(subject.encode("ascii")).hexdigest()
        evidence = VerifiedCurrentFullEntitlement(
            proof_id="hodlxxi-full-entitlement-v1-sha256:" + digest,
            subject=subject,
            valid_from=NOW - timedelta(seconds=2),
            expires_at=NOW + timedelta(seconds=400),
        )
        return self.mutate(evidence) if self.mutate else evidence


class BindingProvider:
    def __init__(self, values, error=None):
        self.values = list(values)
        self.error = error

    def current_for_subject(self, subject, *, now, maximum):
        if self.error:
            raise self.error
        return list(self.values)


class Repository:
    def __init__(self):
        self.snapshots = {}
        self.owners = {}
        self.decisions = {}

    def retain_snapshot(self, snapshot):
        identity = (
            snapshot.viewer_subject,
            snapshot.recipient_subject,
        )
        for route in snapshot.routes:
            owner = identity + (route.device_id, route.binding_id, route.binding_version)
            if route.device_handle in self.owners and self.owners[route.device_handle] != owner:
                raise RuntimeError("ambiguous")
        existing = self.snapshots.get(snapshot.recipient_package_snapshot_id)
        if existing is not None and existing != snapshot:
            raise RuntimeError("conflicting snapshot")
        self.snapshots[snapshot.recipient_package_snapshot_id] = snapshot
        for route in snapshot.routes:
            self.owners[route.device_handle] = identity + (
                route.device_id,
                route.binding_id,
                route.binding_version,
            )
        return snapshot

    def read_snapshot(self, snapshot_id):
        return self.snapshots.get(snapshot_id)

    def record_decision(self, decision):
        existing = self.decisions.get(decision.message_id)
        if existing is not None:
            if existing.envelope_digest != decision.envelope_digest or existing != decision:
                raise RuntimeError("message conflict")
            return existing
        self.decisions[decision.message_id] = decision
        return decision


def make_package(bindings, *, viewer=VIEWER_A, recipient=RECIPIENT, alias_version=1, lifetime=300_000):
    devices = []
    for item in bindings:
        devices.append(
            {
                "deviceHandle": derive_recipient_device_handle(
                    viewer=viewer,
                    target=recipient,
                    binding_id=item.binding_id,
                    alias_secret=ALIAS_SECRET,
                    alias_version=alias_version,
                ),
                "algorithm": "x25519-v1",
                "version": item.binding_version,
                "publicKey": item.public_key,
                "validFrom": int(item.valid_from.timestamp() * 1000),
                "expiresAt": int(item.expires_at.timestamp() * 1000),
            }
        )
    devices.sort(key=lambda value: value["deviceHandle"])
    evidence = {
        "schema": "hodlxxi.social_messaging_recipient_package.v1",
        "version": 1,
        "source": "hodlxxi-ubid",
        "alias": derive_privacy_directory_alias(
            viewer=viewer,
            target=recipient,
            alias_secret=ALIAS_SECRET,
            alias_version=alias_version,
        ),
        "complete": True,
        "issuedAt": NOW_MS,
        "expiresAt": NOW_MS + lifetime,
        "devices": devices,
    }
    canonical = json.dumps(evidence, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return {
        **evidence,
        "snapshotId": "sha256:" + hashlib.sha256(canonical.encode("ascii")).hexdigest(),
    }


def make_gate(
    bindings,
    *,
    repository=None,
    binding_verifier=None,
    full_verifier=None,
    alias_version=1,
    now=NOW,
):
    repository = repository or Repository()
    gate = SocialMessagingRecipientRoutingGateV1(
        repository=repository,
        binding_provider=BindingProvider(bindings),
        binding_authorization_verifier=binding_verifier or BindingVerifier(),
        full_entitlement_verifier=full_verifier or FullVerifier(),
        alias_secret=ALIAS_SECRET,
        alias_version=alias_version,
        clock=lambda: now,
    )
    return gate, repository


def request_for(package, *, handles=None, message_id=MESSAGE_ID, digest=ENVELOPE_DIGEST):
    value = RecipientRoutingRequest(
        schema=REQUEST_SCHEMA,
        version=1,
        message_id=message_id,
        envelope_digest=digest,
        recipient_package_snapshot_id=package["snapshotId"],
        recipient_device_handles=tuple(
            handles
            if handles is not None
            else [item["deviceHandle"] for item in package["devices"]]
        ),
    )
    return canonical_routing_request_bytes(value).decode("ascii")


def retain(bindings=None, **kwargs):
    bindings = [make_binding()] if bindings is None else bindings
    gate, repository = make_gate(bindings, **kwargs)
    package = make_package(bindings, alias_version=kwargs.get("alias_version", 1))
    snapshot = gate.retain_recipient_package(
        viewer_subject=VIEWER_A,
        recipient_subject=RECIPIENT,
        recipient_package=package,
    )
    return gate, repository, package, snapshot


def assert_generic(call):
    with pytest.raises(RecipientMessagingRoutingUnavailable) as caught:
        call()
    assert str(caught.value) == ERROR


def test_exact_current_device_handle_compatibility_vectors_and_separation():
    values = (
        (VIEWER_A, 1, "d_BuBy9pJy3oI4xa_nKYetNg"),
        (VIEWER_B, 1, "d_TPlSBVPGPIJAKUUWUCCdqw"),
        (VIEWER_A, 2, "d_vZ19udOpQREnO1v2hzNDGw"),
    )
    for viewer, alias_version, expected in values:
        assert derive_recipient_device_handle(
            viewer=viewer,
            target=RECIPIENT,
            binding_id="21" * 32,
            alias_secret=ALIAS_SECRET,
            alias_version=alias_version,
        ) == expected
    assert len({item[2] for item in values}) == 3


@pytest.mark.parametrize("count", (1, 16))
def test_complete_one_and_sixteen_device_routing_is_sorted_and_private(count):
    bindings = list(reversed([make_binding(index) for index in range(1, count + 1)]))
    gate, _, package, snapshot = retain(bindings)
    decision = gate.resolve(request_for(package), authenticated_viewer_subject=VIEWER_A)

    handles = tuple(item.device_handle for item in decision.routes)
    assert decision.schema == DECISION_SCHEMA
    assert decision.complete is True
    assert len(decision.routes) == count
    assert handles == tuple(sorted(handles))
    snapshot_bytes = canonical_routing_snapshot_bytes(snapshot)
    decision_bytes = canonical_routing_decision_bytes(decision)
    for forbidden in (b"publicKey", b"alias\"", b"private", b"credential", b"ciphertext"):
        assert forbidden not in snapshot_bytes
        assert forbidden not in decision_bytes


def test_canonical_request_and_decision_bytes_are_deterministic():
    gate, _, package, _ = retain()
    payload = request_for(package)
    parsed = parse_recipient_routing_request(payload)
    first = gate.resolve(payload, authenticated_viewer_subject=VIEWER_A)
    second = gate.resolve(payload, authenticated_viewer_subject=VIEWER_A)
    assert payload.encode("ascii") == canonical_routing_request_bytes(parsed)
    assert canonical_routing_decision_bytes(first) == canonical_routing_decision_bytes(second)


@pytest.mark.parametrize(
    "payload",
    (
        "{}",
        "not-json",
        "{\"schema\":\"x\",\"schema\":\"y\"}",
        "{\"é\":1}",
        "[]",
    ),
)
def test_malformed_duplicate_or_non_ascii_json_fails_generically(payload):
    assert_generic(lambda: parse_recipient_routing_request(payload))


def test_noncanonical_json_unknown_fields_and_oversize_fail():
    _, _, package, _ = retain()
    canonical = request_for(package)
    assert_generic(lambda: parse_recipient_routing_request(canonical + " "))
    decoded = json.loads(canonical)
    decoded["viewerSubject"] = VIEWER_A
    assert_generic(
        lambda: parse_recipient_routing_request(
            json.dumps(decoded, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        )
    )
    assert_generic(lambda: parse_recipient_routing_request("x" * 2_049))


@pytest.mark.parametrize(
    "field,value",
    (
        ("messageId", "m_" + "A" * 42 + "B"),
        ("envelopeDigest", "hodlxxi-social-message-envelope-v1-sha256:" + "AB" * 32),
        ("recipientPackageSnapshotId", "sha256:" + "AB" * 32),
    ),
)
def test_malformed_identifiers_fail(field, value):
    _, _, package, _ = retain()
    decoded = json.loads(request_for(package))
    decoded[field] = value
    payload = json.dumps(decoded, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    assert_generic(lambda: parse_recipient_routing_request(payload))


@pytest.mark.parametrize("mode", ("missing", "extra", "subset", "duplicate"))
def test_request_must_equal_complete_registered_handle_set(mode):
    bindings = [make_binding(1), make_binding(2)]
    gate, _, package, _ = retain(bindings)
    handles = [item["deviceHandle"] for item in package["devices"]]
    if mode == "missing":
        values = ["d_" + "A" * 22]
    elif mode == "extra":
        values = sorted(handles + ["d_" + "A" * 22])
    elif mode == "subset":
        values = handles[:1]
    else:
        values = [handles[0], handles[0]]
    assert_generic(
        lambda: gate.resolve(
            request_for(package, handles=values), authenticated_viewer_subject=VIEWER_A
        )
    )


def test_conflicting_handle_ownership_and_derived_handle_collision_fail(monkeypatch):
    bindings = [make_binding(1), make_binding(2)]
    gate, repository = make_gate(bindings)
    package = make_package(bindings)
    first_handle = package["devices"][0]["deviceHandle"]
    repository.owners[first_handle] = ("conflict",)
    assert_generic(
        lambda: gate.retain_recipient_package(
            viewer_subject=VIEWER_A,
            recipient_subject=RECIPIENT,
            recipient_package=package,
        )
    )

    gate, _ = make_gate(bindings)
    monkeypatch.setattr(
        routing,
        "derive_recipient_device_handle",
        lambda **_kwargs: "d_" + "A" * 22,
    )
    assert_generic(
        lambda: gate.retain_recipient_package(
            viewer_subject=VIEWER_A,
            recipient_subject=RECIPIENT,
            recipient_package=package,
        )
    )


@pytest.mark.parametrize("duplicate", ("device", "binding"))
def test_duplicate_device_or_binding_id_fails(duplicate):
    first = make_binding(1)
    second = make_binding(2)
    if duplicate == "device":
        second = replace(second, device_id=first.device_id)
    else:
        second = replace(second, binding_id=first.binding_id)
    package = make_package([first, second])
    gate, _ = make_gate([first, second])
    assert_generic(
        lambda: gate.retain_recipient_package(
            viewer_subject=VIEWER_A,
            recipient_subject=RECIPIENT,
            recipient_package=package,
        )
    )


def test_snapshot_digest_mismatch_and_expiry_fail():
    bindings = [make_binding()]
    gate, _ = make_gate(bindings)
    package = make_package(bindings)
    package["snapshotId"] = "sha256:" + "00" * 32
    assert_generic(
        lambda: gate.retain_recipient_package(
            viewer_subject=VIEWER_A,
            recipient_subject=RECIPIENT,
            recipient_package=package,
        )
    )
    expired_gate, _ = make_gate(bindings, now=NOW + timedelta(seconds=301))
    package = make_package(bindings)
    assert_generic(
        lambda: expired_gate.retain_recipient_package(
            viewer_subject=VIEWER_A,
            recipient_subject=RECIPIENT,
            recipient_package=package,
        )
    )


def test_retained_alias_version_is_part_of_the_authoritative_mapping():
    gate, repository, package, snapshot = retain()
    repository.snapshots[package["snapshotId"]] = replace(snapshot, alias_version=2)

    assert_generic(
        lambda: gate.resolve(
            request_for(package),
            authenticated_viewer_subject=VIEWER_A,
        )
    )


def test_full_and_binding_evidence_bound_snapshot_deadline():
    binding = make_binding()
    package = make_package([binding])
    short_binding = BindingVerifier(
        mutate=lambda value: replace(
            value, evidence_expires_at=NOW + timedelta(seconds=299)
        )
    )
    gate, _ = make_gate([binding], binding_verifier=short_binding)
    assert_generic(
        lambda: gate.retain_recipient_package(
            viewer_subject=VIEWER_A,
            recipient_subject=RECIPIENT,
            recipient_package=package,
        )
    )
    short_full = FullVerifier(
        mutate=lambda value: replace(value, expires_at=NOW + timedelta(seconds=299))
    )
    gate, _ = make_gate([binding], full_verifier=short_full)
    assert_generic(
        lambda: gate.retain_recipient_package(
            viewer_subject=VIEWER_A,
            recipient_subject=RECIPIENT,
            recipient_package=package,
        )
    )


def test_viewer_and_recipient_mismatch_fail():
    gate, _, package, _ = retain()
    assert_generic(
        lambda: gate.resolve(request_for(package), authenticated_viewer_subject=VIEWER_B)
    )
    wrong = make_binding(subject=OTHER_RECIPIENT)
    package = make_package([wrong], recipient=RECIPIENT)
    gate, _ = make_gate([wrong])
    assert_generic(
        lambda: gate.retain_recipient_package(
            viewer_subject=VIEWER_A,
            recipient_subject=RECIPIENT,
            recipient_package=package,
        )
    )


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: replace(value, subject=OTHER_RECIPIENT),
        lambda value: replace(value, device_id=_hex(999)),
        lambda value: replace(value, binding_id=_hex(999)),
        lambda value: replace(value, binding_version=2),
        lambda value: replace(value, public_key=_hex(999)),
        lambda value: replace(value, valid_from=NOW - timedelta(seconds=3)),
        lambda value: replace(value, expires_at=NOW + timedelta(seconds=601)),
        lambda value: replace(value, proof_id="invalid"),
    ),
)
def test_exact_authorization_evidence_mismatch_fails(mutation):
    binding = make_binding()
    gate, _ = make_gate([binding], binding_verifier=BindingVerifier(mutate=mutation))
    package = make_package([binding])
    assert_generic(
        lambda: gate.retain_recipient_package(
            viewer_subject=VIEWER_A,
            recipient_subject=RECIPIENT,
            recipient_package=package,
        )
    )


@pytest.mark.parametrize("untrusted", (True, {"authorized": True}, make_binding()))
def test_oauth_only_binding_or_untyped_authorization_cannot_be_routable(untrusted):
    binding = make_binding()

    class OAuthOnly:
        def verify(self, _binding, *, now):
            return untrusted

    gate, _ = make_gate([binding], binding_verifier=OAuthOnly())
    package = make_package([binding])
    assert_generic(
        lambda: gate.retain_recipient_package(
            viewer_subject=VIEWER_A,
            recipient_subject=RECIPIENT,
            recipient_package=package,
        )
    )


def test_duplicate_authorization_evidence_fails():
    bindings = [make_binding(1), make_binding(2)]

    class DuplicateProof(BindingVerifier):
        def verify(self, binding, *, now):
            return replace(super().verify(binding, now=now), proof_id="hodlxxi-binding-authorization-v1-sha256:" + "11" * 32)

    gate, _ = make_gate(bindings, binding_verifier=DuplicateProof())
    package = make_package(bindings)
    assert_generic(
        lambda: gate.retain_recipient_package(
            viewer_subject=VIEWER_A,
            recipient_subject=RECIPIENT,
            recipient_package=package,
        )
    )


def test_rotation_revocation_and_stale_exact_binding_fail_before_decision():
    gate, _, package, snapshot = retain()
    old = make_binding()
    rotated = replace(
        old,
        binding_id=_hex(901),
        binding_version=2,
        public_key=_hex(902),
        operation="rotate",
        prior_binding_id=old.binding_id,
    )
    gate._binding_provider.values = [rotated]
    assert_generic(
        lambda: gate.resolve(request_for(package), authenticated_viewer_subject=VIEWER_A)
    )
    gate._binding_provider.values = []
    assert_generic(
        lambda: gate.resolve(request_for(package), authenticated_viewer_subject=VIEWER_A)
    )
    gate._binding_provider.values = [replace(old, active=False, operation="revoke")]
    assert_generic(
        lambda: gate.resolve(request_for(package), authenticated_viewer_subject=VIEWER_A)
    )
    assert snapshot.routes[0].binding_id == old.binding_id


def test_same_message_and_digest_is_idempotent_but_changed_digest_conflicts():
    gate, _, package, _ = retain()
    payload = request_for(package)
    first = gate.resolve(payload, authenticated_viewer_subject=VIEWER_A)
    assert gate.resolve(payload, authenticated_viewer_subject=VIEWER_A) == first
    changed = request_for(
        package,
        digest="hodlxxi-social-message-envelope-v1-sha256:" + "cd" * 32,
    )
    assert_generic(lambda: gate.resolve(changed, authenticated_viewer_subject=VIEWER_A))


def test_exact_snapshot_retention_is_idempotent():
    bindings = [make_binding()]
    gate, _ = make_gate(bindings)
    package = make_package(bindings)
    first = gate.retain_recipient_package(
        viewer_subject=VIEWER_A,
        recipient_subject=RECIPIENT,
        recipient_package=package,
    )
    second = gate.retain_recipient_package(
        viewer_subject=VIEWER_A,
        recipient_subject=RECIPIENT,
        recipient_package=package,
    )
    assert second == first


@pytest.mark.parametrize("dependency", ("repository", "binding", "full"))
def test_dependency_failures_have_exactly_the_same_generic_error(dependency):
    binding = make_binding()
    repository = Repository()
    binding_verifier = BindingVerifier()
    full_verifier = FullVerifier()
    if dependency == "repository":
        repository.retain_snapshot = lambda _snapshot: (_ for _ in ()).throw(RuntimeError("db"))
    elif dependency == "binding":
        binding_verifier.error = RuntimeError("secret binding error")
    else:
        full_verifier.error = RuntimeError("secret full error")
    gate, _ = make_gate(
        [binding],
        repository=repository,
        binding_verifier=binding_verifier,
        full_verifier=full_verifier,
    )
    package = make_package([binding])
    assert_generic(
        lambda: gate.retain_recipient_package(
            viewer_subject=VIEWER_A,
            recipient_subject=RECIPIENT,
            recipient_package=package,
        )
    )


def test_missing_or_ambiguous_repository_snapshot_fails_without_oracle():
    gate, repository, package, _ = retain()
    repository.snapshots.clear()
    assert_generic(
        lambda: gate.resolve(request_for(package), authenticated_viewer_subject=VIEWER_A)
    )
    repository.read_snapshot = lambda _snapshot_id: ["ambiguous", "records"]
    assert_generic(
        lambda: gate.resolve(request_for(package), authenticated_viewer_subject=VIEWER_A)
    )


def test_snapshot_and_decision_are_frozen_and_exclude_outward_secrets():
    gate, _, package, snapshot = retain()
    decision = gate.resolve(request_for(package), authenticated_viewer_subject=VIEWER_A)
    with pytest.raises(Exception):
        snapshot.viewer_subject = VIEWER_B
    with pytest.raises(Exception):
        decision.routes = ()
    internal = canonical_routing_decision_bytes(decision).decode("ascii")
    for forbidden in (
        package["alias"],
        package["devices"][0]["publicKey"],
        "privateKey",
        "messageKey",
        "bearer",
        "session",
    ):
        assert forbidden not in internal


def test_source_module_has_no_runtime_or_database_framework_imports():
    source = routing.__file__
    text = open(source, encoding="utf-8").read()
    for forbidden in (
        "sqlalchemy",
        "flask",
        "blueprint",
        "app.models",
        "app.config",
        "oauth",
        "requests",
    ):
        assert forbidden not in text.lower()
