"""Accepted mobile proof -> current package -> exact routing boundary, offline."""

import hashlib
import json
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.services import social_messaging_mobile_authorization as mobile
from app.services.privacy_safe_full_directory import derive_privacy_directory_alias
from app.services.recipient_device_resolver import RecipientDeviceResolverV1
from app.services.social_messaging_device_binding_authorization import _binding_from_record
from app.services.social_messaging_mobile_routing import (
    EVIDENCE_SCHEMA,
    PROOF_ID_PREFIX,
    AcceptedMobileBindingAuthorizationVerifier,
    AcceptedMobileBindingEvidence,
    MobileBindingEvidenceState,
)
from app.services.social_messaging_recipient_routing import (
    RecipientMessagingRoutingUnavailable,
    SocialMessagingRecipientRoutingGateV1,
    canonical_routing_request_bytes,
    canonical_routing_snapshot_bytes,
    parse_recipient_routing_request,
)
from tests.unit.test_recipient_device_resolver import decision
from tests.unit.test_social_messaging_device_binding_authorization_intent import current_full
from tests.unit.test_social_messaging_mobile_authorization import (
    FIRST,
    REVISION,
    SUBJECT,
    VECTORS,
    event_for,
    source_for,
    submission_for,
)
from tests.unit.test_social_messaging_recipient_routing import ALIAS_SECRET, VIEWER_A, BindingProvider, Repository

NOW = datetime.fromtimestamp(FIRST["now"], timezone.utc)
ERROR = "^recipient messaging routing unavailable$"


def record_for(entry=FIRST, method=mobile.QR):
    source = source_for(entry, method)
    candidate = mobile.parse_authorization(source, subject=SUBJECT, expected_method=method, now=entry["now"])
    context = mobile.parse_json(source)["context"]
    qr = method == mobile.QR
    return AcceptedMobileBindingEvidence(
        context["pairingId"] if qr else context["challenge"],
        method,
        SUBJECT,
        context["desktopContext"] if qr else context["loginContext"],
        mobile._second(context["createdAt"]) if qr else candidate.semantic.issued_at,
        mobile._second(context["expiresAt"]) if qr else candidate.semantic.expires_at,
        REVISION if qr else None,
        context["secretCommitment"] if qr else None,
        source,
        event_for(entry) if qr else submission_for(entry),
        mobile.canonical(
            dict(
                schema="hodlxxi.social_mobile_authorization_acceptance.v1",
                version=1,
                authorizationDigest=candidate.digest,
                bindingId=candidate.semantic.binding_id,
                subject=SUBJECT,
                requestId=candidate.semantic.request_id,
            )
        ),
        candidate.semantic.request_id,
        candidate.digest,
        candidate.semantic.binding_id,
        entry["now"],
    )


def binding_for(record):
    candidate = mobile.parse_authorization(
        record.source, subject=record.subject, expected_method=record.method, now=record.accepted_at
    )
    return _binding_from_record(mobile.parse_json(candidate.semantic.binding_record), record.binding_id)


class EvidenceReader:
    def __init__(self, record):
        self.value = MobileBindingEvidenceState(EVIDENCE_SCHEMA, 1, record.binding_id, True, False, (record,))
        self.calls = 0

    def accepted_for_binding(self, binding_id, *, maximum):
        self.calls += 1
        assert binding_id == self.value.binding_id and maximum == 2
        return self.value


class Full:
    def __init__(self):
        self.denied = None
        self.calls = []

    def verify(self, subject, *, now):
        self.calls.append(subject)
        if subject == self.denied:
            raise ValueError
        return current_full(subject, now=NOW)


class DeviceProvider(BindingProvider):
    def apply(self, *args, **kwargs):
        raise AssertionError("read-only package producer")


def package_for(binding, now=NOW):
    """Real existing package producer, with a complete synthetic authority input."""
    now_ms = int(now.timestamp() * 1000)
    end = now_ms + 120_000
    evidence = dict(
        complete=True,
        issuedAt=now_ms,
        expiresAt=end,
        entitlements=[
            dict(subject=s, status="full", validFrom=now_ms, expiresAt=end, revoked=False)
            for s in sorted((VIEWER_A, SUBJECT))
        ],
    )
    snapshot = "sha256:" + hashlib.sha256(mobile.canonical(evidence).encode("ascii")).hexdigest()
    population = dict(
        evidence,
        schema="hodlxxi.full_entitlement_snapshot.v1",
        version=1,
        source="hodlxxi-crt",
        snapshotId=snapshot,
        entitlements=[dict(row, snapshotId=snapshot) for row in evidence["entitlements"]],
    )
    alias = derive_privacy_directory_alias(viewer=VIEWER_A, target=SUBJECT, alias_secret=ALIAS_SECRET, alias_version=1)
    resolver = RecipientDeviceResolverV1(
        current_entitlement_resolver=decision,
        full_population_provider=lambda: population,
        device_repository=DeviceProvider([binding]),
        alias_secret=ALIAS_SECRET,
        clock=lambda: now,
    )
    return resolver.resolve(viewer_subject=VIEWER_A, recipient_alias=alias)


def boundary(record=None, enabled=True):
    record = record or record_for()
    reader = EvidenceReader(record)
    binding = binding_for(record)
    provider, repository, full = BindingProvider([binding]), Repository(), Full()
    clock = [NOW]
    gate = SocialMessagingRecipientRoutingGateV1(
        repository=repository,
        binding_provider=provider,
        binding_authorization_verifier=AcceptedMobileBindingAuthorizationVerifier(reader, enabled=True),
        full_entitlement_verifier=full,
        alias_secret=ALIAS_SECRET,
        clock=lambda: clock[0],
        mobile_authorization_enabled=enabled,
    )
    return gate, reader, provider, repository, full, clock


@pytest.mark.parametrize("entry", VECTORS["entries"], ids=lambda entry: entry["operation"])
@pytest.mark.parametrize("method", [mobile.LEGACY, mobile.QR])
def test_real_method_signatures_exact_accepted_binding_and_post_command_expiry(entry, method):
    record = record_for(entry, method)
    if entry["operation"] == "revoke":
        # Revoke's record cannot become active recipient authorization.
        from app.services.social_messaging_mobile_authorization_storage import _binding

        candidate = mobile.parse_authorization(record.source, subject=SUBJECT, expected_method=method, now=entry["now"])
        binding = _binding(candidate)
    else:
        binding = binding_for(record)
    verifier = AcceptedMobileBindingAuthorizationVerifier(EvidenceReader(record), enabled=True)
    now = datetime.fromtimestamp(entry["now"] + 301, timezone.utc)
    if entry["operation"] == "revoke":
        with pytest.raises(RecipientMessagingRoutingUnavailable, match=ERROR):
            verifier.verify(binding, now=now)
        return
    result = verifier.verify(binding, now=now)
    assert result.proof_id == PROOF_ID_PREFIX + entry[method]["digest"]
    assert result.evidence_valid_from == datetime.fromtimestamp(record.accepted_at, timezone.utc)
    assert result.evidence_expires_at == binding.expires_at
    assert result.binding_id == entry["bindingId"]


def test_disabled_verifier_never_reads_authority():
    record = record_for()
    reader = EvidenceReader(record)
    with pytest.raises(RecipientMessagingRoutingUnavailable, match=ERROR):
        AcceptedMobileBindingAuthorizationVerifier(reader).verify(binding_for(record), now=NOW)
    assert reader.calls == 0


@pytest.mark.parametrize("value", [None, 1, "true", {}, []])
def test_flags_require_boolean(value):
    with pytest.raises(ValueError):
        AcceptedMobileBindingAuthorizationVerifier(EvidenceReader(record_for()), enabled=value)
    with pytest.raises(ValueError):
        boundary(enabled=value)


@pytest.mark.parametrize(
    "change",
    [
        dict(complete=False),
        dict(truncated=True),
        dict(version=True),
        dict(schema="wrong"),
        dict(binding_id="aa" * 32),
        dict(records=()),
        dict(records=[]),
        dict(records=(True,)),
    ],
)
def test_incomplete_or_untyped_evidence_is_not_acceptance(change):
    record = record_for()
    reader = EvidenceReader(record)
    reader.value = replace(reader.value, **change)
    with pytest.raises(RecipientMessagingRoutingUnavailable, match=ERROR):
        AcceptedMobileBindingAuthorizationVerifier(reader, enabled=True).verify(binding_for(record), now=NOW)


@pytest.mark.parametrize("method", [mobile.LEGACY, mobile.QR])
@pytest.mark.parametrize(
    "field,value",
    [
        ("method", mobile.NOSTR),
        ("subject", VIEWER_A),
        ("operation_id", "aa" * 32),
        ("context_id", "aa" * 32),
        ("request_id", "aa" * 32),
        ("authorization_digest", "aa" * 32),
        ("binding_id", "aa" * 32),
        ("accepted_at", FIRST["now"] + 301),
        ("accepted_at", True),
        ("created_at", -1),
        ("expires_at", FIRST["now"]),
        ("proof_source", "{}"),
        ("result_source", "{}"),
        ("source", "{}"),
        ("secret_commitment", "aa" * 32),
    ],
)
def test_substituted_or_unaccepted_evidence_fails_closed(method, field, value):
    original = record_for(method=method)
    reader = EvidenceReader(replace(original, **{field: value}))
    with pytest.raises(RecipientMessagingRoutingUnavailable, match=ERROR):
        AcceptedMobileBindingAuthorizationVerifier(reader, enabled=True).verify(binding_for(original), now=NOW)


@pytest.mark.parametrize(
    "change",
    [
        dict(subject=VIEWER_A),
        dict(device_id="aa" * 32),
        dict(binding_id="aa" * 32),
        dict(public_key="0a" + "00" * 31),
        dict(binding_version=True),
        dict(active=False),
        dict(request_id="aa" * 32),
        dict(prior_binding_id="aa" * 32),
        dict(expires_at=NOW),
        dict(valid_from=NOW + timedelta(seconds=1)),
    ],
)
def test_exact_current_binding_required(change):
    record = record_for()
    with pytest.raises(RecipientMessagingRoutingUnavailable, match=ERROR):
        AcceptedMobileBindingAuthorizationVerifier(EvidenceReader(record), enabled=True).verify(
            replace(binding_for(record), **change), now=NOW
        )


def test_duplicate_and_mapping_evidence_denied():
    record = record_for()
    reader = EvidenceReader(record)
    for value in (asdict(reader.value), replace(reader.value, records=(record, record))):
        reader.value = value
        with pytest.raises(RecipientMessagingRoutingUnavailable, match=ERROR):
            AcceptedMobileBindingAuthorizationVerifier(reader, enabled=True).verify(binding_for(record), now=NOW)


def test_clock_and_acceptance_deadlines():
    record = record_for()
    binding = binding_for(record)
    verifier = AcceptedMobileBindingAuthorizationVerifier(EvidenceReader(record), enabled=True)
    for now in (NOW - timedelta(seconds=1), NOW.replace(tzinfo=None), NOW.replace(microsecond=1), binding.expires_at):
        with pytest.raises(RecipientMessagingRoutingUnavailable, match=ERROR):
            verifier.verify(binding, now=now)


def test_gate_requires_explicit_mobile_opt_in():
    gate, _, provider, repository, _, _ = boundary(enabled=False)
    with pytest.raises(RecipientMessagingRoutingUnavailable, match=ERROR):
        gate.retain_recipient_package(
            viewer_subject=VIEWER_A, recipient_subject=SUBJECT, recipient_package=package_for(provider.values[0])
        )
    assert not repository.snapshots


def test_fixed_social_wire_and_real_package_producer_feed_existing_gate():
    fixture = json.loads((Path(__file__).parents[1] / "fixtures/social_messaging_phase3_routing_v1.json").read_text())
    gate, _, provider, repository, full, _ = boundary()
    package = package_for(provider.values[0])
    assert package == fixture["recipientPackage"]
    snapshot = gate.retain_recipient_package(
        viewer_subject=VIEWER_A, recipient_subject=SUBJECT, recipient_package=package
    )
    request = parse_recipient_routing_request(fixture["routingRequest"])
    assert canonical_routing_request_bytes(request).decode("ascii") == fixture["routingRequest"]
    assert request.envelope_digest == fixture["envelopeDigest"]
    assert request.recipient_device_handles == tuple(d["deviceHandle"] for d in package["devices"])
    assert request.recipient_package_snapshot_id == package["snapshotId"]
    assert snapshot.routes[0].authorization_proof_id == PROOF_ID_PREFIX + FIRST[mobile.QR]["digest"]
    snapshot_wire = canonical_routing_snapshot_bytes(snapshot).decode("ascii")
    assert provider.values[0].public_key not in snapshot_wire and package["alias"] not in snapshot_wire
    result = gate.resolve(fixture["routingRequest"], authenticated_viewer_subject=VIEWER_A)
    assert gate.resolve(fixture["routingRequest"], authenticated_viewer_subject=VIEWER_A) == result
    assert len(repository.decisions) == 1
    assert full.calls == [VIEWER_A, SUBJECT] * 3
    changed = replace(request, envelope_digest="hodlxxi-social-message-envelope-v1-sha256:" + "aa" * 32)
    with pytest.raises(RecipientMessagingRoutingUnavailable, match=ERROR):
        gate.resolve(canonical_routing_request_bytes(changed).decode("ascii"), authenticated_viewer_subject=VIEWER_A)


@pytest.mark.parametrize(
    "failure",
    [
        "missing",
        "revoked",
        "rotated",
        "duplicate",
        "sender-full",
        "recipient-full",
        "expired",
        "different-viewer",
        "lost-acceptance",
    ],
)
def test_current_authority_rechecked_after_snapshot(failure):
    fixture = json.loads((Path(__file__).parents[1] / "fixtures/social_messaging_phase3_routing_v1.json").read_text())
    gate, reader, provider, repository, full, clock = boundary()
    gate.retain_recipient_package(
        viewer_subject=VIEWER_A, recipient_subject=SUBJECT, recipient_package=package_for(provider.values[0])
    )
    if failure == "missing":
        provider.values = []
    elif failure == "revoked":
        provider.values = [replace(provider.values[0], active=False)]
    elif failure == "rotated":
        provider.values = [binding_for(record_for(VECTORS["entries"][1]))]
    elif failure == "duplicate":
        provider.values *= 2
    elif failure == "sender-full":
        full.denied = VIEWER_A
    elif failure == "recipient-full":
        full.denied = SUBJECT
    elif failure == "expired":
        clock[0] += timedelta(seconds=120)
    elif failure == "lost-acceptance":
        reader.value = replace(reader.value, records=())
    viewer = SUBJECT if failure == "different-viewer" else VIEWER_A
    with pytest.raises(RecipientMessagingRoutingUnavailable, match=ERROR):
        gate.resolve(fixture["routingRequest"], authenticated_viewer_subject=viewer)
    assert not repository.decisions


def test_fixed_fixture_identity():
    path = Path(__file__).parents[1] / "fixtures/social_messaging_phase3_routing_v1.json"
    assert (
        hashlib.sha256(path.read_bytes()).hexdigest()
        == "90f7c3726a9dfcfa655630626d53d65b410e5e330456d5114d04982a53da2f1c"
    )


@pytest.mark.parametrize("method", [mobile.LEGACY, mobile.QR])
def test_signature_corruption_is_reverified(method):
    original = record_for(method=method)
    proof = mobile.parse_json(original.proof_source)
    field = "signature" if method == mobile.LEGACY else "sig"
    proof[field] = ("A" if method == mobile.LEGACY else "0") + proof[field][1:]
    reader = EvidenceReader(replace(original, proof_source=mobile.canonical(proof)))
    with pytest.raises(RecipientMessagingRoutingUnavailable, match=ERROR):
        AcceptedMobileBindingAuthorizationVerifier(reader, enabled=True).verify(binding_for(original), now=NOW)


def test_package_before_committed_acceptance_is_ineligible():
    record = replace(record_for(), accepted_at=FIRST["now"] + 1)
    gate, _, provider, repository, _, clock = boundary(record)
    clock[0] += timedelta(seconds=2)
    with pytest.raises(RecipientMessagingRoutingUnavailable, match=ERROR):
        gate.retain_recipient_package(
            viewer_subject=VIEWER_A, recipient_subject=SUBJECT, recipient_package=package_for(provider.values[0])
        )
    assert not repository.snapshots
