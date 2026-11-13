from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest

from app.services import social_admission_session_binding as contract
from app.services.social_messaging_device_admission_contract import parse_verification_context_v1

FIXTURES = Path(__file__).parents[1] / "fixtures"
ROOT = Path(__file__).parents[2]
FIXTURE_BYTES = (FIXTURES / "social_admission_session_binding_v1.json").read_bytes()
VECTORS = json.loads(FIXTURE_BYTES)
ERROR = "^social admission session binding unavailable$"


def canonical(value: dict[str, object]) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def vector(name: str) -> dict[str, str]:
    return VECTORS["vectors"][name]


def test_fixture_and_existing_cross_contract_fixture_bytes_are_fixed_and_public_only():
    assert hashlib.sha256(FIXTURE_BYTES).hexdigest() == (
        "da98cfc67294a39fd45ed0a3488d6c21bf8f3ca755111a61b1fb92d5fe46ed09"
    )
    expected_existing = {
        "social_device_admission_v1.json": "09722ca9ab230a7bbc73b2228dfed5e80cdd2c2bb44a32e8571bdcf246ca4324",
        "social_session_issuance_v1.json": "474bdfa4d3c300da0e78e5cde9a2b8dd263ee1e68227bb3a5000687d2ce230f3",
        "social_messaging_device_ed25519_association_lifecycle_v1.json": (
            "4851690baa82ffef85d6badd7469e43ae5468d7d3eeec93bf67999be6f2def23"
        ),
    }
    for filename, expected in expected_existing.items():
        assert hashlib.sha256((FIXTURES / filename).read_bytes()).hexdigest() == expected

    lowered = FIXTURE_BYTES.lower()
    for forbidden in (b"vieweraccesstoken", b"access_token", b"bearer", b"secret", b"credential"):
        assert forbidden not in lowered


def test_every_fixed_vector_has_its_exact_canonical_preimage_and_independent_sha256():
    assert VECTORS["schema"] == "hodlxxi.social_admission_session_binding_vectors.v1"
    assert VECTORS["version"] == 1
    assert VECTORS["sessionBindingDomain"] == contract.SESSION_BINDING_DOMAIN
    assert VECTORS["approverSessionBindingDomain"] == contract.APPROVER_SESSION_BINDING_DOMAIN

    approver_names = ("approverSessionBinding", "differentApproverSession")
    device_names = (
        "normalSocialDeviceSessionBinding",
        "differentSubject",
        "differentDevice",
        "differentX25519Binding",
        "differentOAuthSessionGeneration",
        "differentClient",
        "replacementSocialIssuance",
    )
    for name in device_names:
        value = vector(name)
        parsed = contract.parse_session_binding_preimage_v1(value["preimage"])
        expected = hashlib.sha256(
            contract.SESSION_BINDING_DOMAIN.encode("ascii") + b"\0" + value["preimage"].encode("ascii")
        ).hexdigest()
        assert parsed.preimage == value["preimage"]
        assert expected == value["sha256"]
        assert contract.derive_session_binding_v1(value["preimage"]) == expected

    for name in approver_names:
        value = vector(name)
        parsed = contract.parse_approver_session_binding_preimage_v1(value["preimage"])
        expected = hashlib.sha256(
            contract.APPROVER_SESSION_BINDING_DOMAIN.encode("ascii") + b"\0" + value["preimage"].encode("ascii")
        ).hexdigest()
        assert parsed.preimage == value["preimage"]
        assert expected == value["sha256"]
        assert contract.derive_approver_session_binding_v1(value["preimage"]) == expected


def test_constructors_reproduce_exact_fixed_canonical_bytes():
    device = json.loads(vector("normalSocialDeviceSessionBinding")["preimage"])
    assert contract.canonical_session_binding_preimage_v1_bytes(
        subject=device["subject"],
        device_id=device["deviceId"],
        x25519_binding_id=device["x25519BindingId"],
        social_session_issuance_id=device["socialSessionIssuanceId"],
        social_session_token_id=device["socialSessionTokenId"],
        parent_oauth_token_id=device["parentOAuthTokenId"],
        parent_oauth_session_id=device["parentOAuthSessionId"],
        parent_oauth_browser_generation_id=device["parentOAuthBrowserGenerationId"],
        client_id=device["clientId"],
    ) == vector("normalSocialDeviceSessionBinding")["preimage"].encode("ascii")

    approver = json.loads(vector("approverSessionBinding")["preimage"])
    assert contract.canonical_approver_session_binding_preimage_v1_bytes(
        subject=approver["subject"],
        oauth_token_id=approver["oauthTokenId"],
        oauth_session_id=approver["oauthSessionId"],
        oauth_browser_generation_id=approver["oauthBrowserGenerationId"],
        client_id=approver["clientId"],
    ) == vector("approverSessionBinding")["preimage"].encode("ascii")


@pytest.mark.parametrize(
    "field,replacement",
    (
        ("subject", "31" * 32),
        ("deviceId", "32" * 32),
        ("x25519BindingId", "33" * 32),
        ("socialSessionIssuanceId", "34" * 32),
        ("socialSessionTokenId", "35" * 16),
        ("parentOAuthTokenId", "36" * 16),
        ("parentOAuthSessionId", "37" * 32),
        ("parentOAuthBrowserGenerationId", "38" * 32),
        ("clientId", "social-viewer-v2"),
    ),
)
def test_every_device_authority_dimension_changes_session_binding(field, replacement):
    normal = vector("normalSocialDeviceSessionBinding")
    changed = canonical({**json.loads(normal["preimage"]), field: replacement})
    assert contract.derive_session_binding_v1(changed) != normal["sha256"]


@pytest.mark.parametrize(
    "field,replacement",
    (
        ("subject", "41" * 32),
        ("oauthTokenId", "42" * 16),
        ("oauthSessionId", "43" * 32),
        ("oauthBrowserGenerationId", "44" * 32),
        ("clientId", "social-viewer-v2"),
    ),
)
def test_every_approver_authority_dimension_changes_approver_binding(field, replacement):
    normal = vector("approverSessionBinding")
    changed = canonical({**json.loads(normal["preimage"]), field: replacement})
    assert contract.derive_approver_session_binding_v1(changed) != normal["sha256"]


def test_device_and_approver_roles_are_domain_separated_and_cannot_substitute():
    role = vector("deviceApproverRoleSeparation")
    assert role["devicePreimage"] == vector("normalSocialDeviceSessionBinding")["preimage"]
    assert role["approverPreimage"] == vector("approverSessionBinding")["preimage"]
    assert role["deviceSha256"] == contract.derive_session_binding_v1(role["devicePreimage"])
    assert role["approverSha256"] == contract.derive_approver_session_binding_v1(role["approverPreimage"])
    assert contract.SESSION_BINDING_DOMAIN != contract.APPROVER_SESSION_BINDING_DOMAIN
    assert role["deviceSha256"] != role["approverSha256"]
    with pytest.raises(contract.SocialAdmissionSessionBindingUnavailable, match=ERROR):
        contract.require_session_binding_match_v1(role["devicePreimage"], role["approverSha256"])
    with pytest.raises(contract.SocialAdmissionSessionBindingUnavailable, match=ERROR):
        contract.require_approver_session_binding_match_v1(role["approverPreimage"], role["deviceSha256"])


def test_comparison_is_exact_and_separate_from_current_authority_validity():
    device = vector("normalSocialDeviceSessionBinding")
    approver = vector("approverSessionBinding")
    assert contract.require_session_binding_match_v1(device["preimage"], device["sha256"]) == device["sha256"]
    assert (
        contract.require_approver_session_binding_match_v1(approver["preimage"], approver["sha256"])
        == approver["sha256"]
    )
    for presented in ("0" * 64, "A" * 64, b"0" * 64, True, None):
        with pytest.raises(contract.SocialAdmissionSessionBindingUnavailable, match=ERROR):
            contract.require_session_binding_match_v1(device["preimage"], presented)


def test_device_preimage_rejects_noncanonical_malformed_and_authority_state_inputs():
    wire = vector("normalSocialDeviceSessionBinding")["preimage"]
    value = json.loads(wire)
    missing = dict(value)
    del missing["subject"]
    candidates = (
        None,
        wire.encode("ascii"),
        "{}",
        canonical(missing),
        canonical({**value, "unknown": "value"}),
        wire[:-1] + ',"version":1}',
        json.dumps(value, ensure_ascii=True, sort_keys=True),
        canonical({**value, "version": True}),
        canonical({**value, "schema": "other"}),
        canonical({**value, "subject": "A" * 64}),
        canonical({**value, "socialSessionTokenId": "a" * 64}),
        canonical({**value, "clientId": " social-viewer-v1"}),
        canonical({**value, "clientId": "social-viewer-\N{LATIN SMALL LETTER E WITH ACUTE}"}),
        canonical({**value, "active": True}),
    )
    for candidate in candidates:
        with pytest.raises(contract.SocialAdmissionSessionBindingUnavailable, match=ERROR):
            contract.parse_session_binding_preimage_v1(candidate)


def test_approver_preimage_rejects_noncanonical_malformed_and_extra_proof_identity():
    wire = vector("approverSessionBinding")["preimage"]
    value = json.loads(wire)
    missing = dict(value)
    del missing["oauthSessionId"]
    candidates = (
        None,
        wire.encode("ascii"),
        canonical(missing),
        canonical({**value, "approverFullProofId": "hodlxxi-full-entitlement-v1-sha256:" + "a" * 64}),
        wire[:-1] + ',"version":1}',
        json.dumps(value, ensure_ascii=True, sort_keys=True),
        canonical({**value, "version": False}),
        canonical({**value, "oauthTokenId": "A" * 32}),
        canonical({**value, "oauthSessionId": "a" * 63}),
        canonical({**value, "clientId": "social viewer"}),
    )
    for candidate in candidates:
        with pytest.raises(contract.SocialAdmissionSessionBindingUnavailable, match=ERROR):
            contract.parse_approver_session_binding_preimage_v1(candidate)


def test_derived_bindings_fit_the_unchanged_frozen_verification_context():
    admission = json.loads((FIXTURES / "social_device_admission_v1.json").read_bytes())
    enrollment = json.loads(admission["vectors"]["enrollmentV2"]["contextWire"])
    device = vector("normalSocialDeviceSessionBinding")
    approver = vector("approverSessionBinding")
    context = parse_verification_context_v1(
        canonical(
            {
                **enrollment,
                "sessionBinding": device["sha256"],
                "approverSessionBinding": approver["sha256"],
            }
        )
    )
    assert contract.require_session_binding_match_v1(device["preimage"], context.session_binding) == device["sha256"]
    assert (
        contract.require_approver_session_binding_match_v1(approver["preimage"], context.approver_session_binding)
        == approver["sha256"]
    )
    assert context.approver_full_proof_id == enrollment["approverFullProofId"]
    assert "approverFullProofId" not in json.loads(approver["preimage"])


def test_durable_contracts_expose_every_non_secret_derivation_input_separately():
    def declared_fields(path: Path, class_name: str) -> set[str]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        declaration = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
        return {
            target.id
            for statement in declaration.body
            if isinstance(statement, ast.Assign)
            for target in statement.targets
            if isinstance(target, ast.Name)
        }

    issuance_columns = declared_fields(ROOT / "app/services/social_session_issuance.py", "SocialSessionIssuance")
    oauth_columns = declared_fields(ROOT / "app/models.py", "OAuthSessionGeneration")
    assert {
        "issuance_id",
        "token_id",
        "parent_token_id",
        "client_id",
        "subject",
        "binding_id",
        "device_id",
    } <= issuance_columns
    assert {
        "token_id",
        "browser_generation_id",
        "session_id",
        "client_id",
        "subject",
    } <= oauth_columns
    assert "access_token" not in issuance_columns
    assert "access_token" not in oauth_columns
