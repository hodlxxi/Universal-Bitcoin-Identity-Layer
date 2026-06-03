"""NIP-59 dependency provenance checklist contract.

P30 adds review gates for future exact dependency selection without selecting
a version, generating a lockfile, enabling crypto, or enabling send.
"""

import json
from pathlib import Path

DOC = Path("docs/ops/NIP59_DEPENDENCY_PROVENANCE_CHECKLIST.md")
CHECKLIST = Path("frontend/nip59/dependency-provenance-checklist.json")
SKELETON = Path("frontend/nip59/dependency-skeleton.json")
BUILDER_TEMPLATE = Path("frontend/nip59/package.builder.template.json")
ROOT_PACKAGE = Path("package.json")
BUNDLE = Path("app/static/js/nip59_client_bundle.js")


def test_provenance_doc_requires_review_before_version_selection():
    text = DOC.read_text(encoding="utf-8")

    assert "does not select a version" in text
    assert "exact package version" in text
    assert "package license" in text
    assert "tarball integrity or lockfile integrity" in text
    assert "transitive cryptographic dependencies" in text
    assert "secp256k1/Schnorr implementation path" in text
    assert "SHA-256/event-hash implementation path" in text


def test_machine_readable_checklist_is_checklist_only():
    payload = json.loads(CHECKLIST.read_text(encoding="utf-8"))

    assert payload["status"] == "checklist-only"
    assert payload["candidatePackage"] == "nostr-tools"
    assert payload["versionSelected"] is False
    assert payload["lockfileGenerated"] is False
    assert payload["productionInstallAllowed"] is False
    assert payload["cryptoImplemented"] is False
    assert payload["sendEnabled"] is False
    assert payload["postEnabled"] is False
    assert payload["relayPublishing"] is False


def test_checklist_contains_required_crypto_review_fields():
    payload = json.loads(CHECKLIST.read_text(encoding="utf-8"))
    fields = set(payload["requiredReviewFields"])

    assert "exact package version" in fields
    assert "tarball or lockfile integrity" in fields
    assert "direct dependencies" in fields
    assert "transitive cryptographic dependencies" in fields
    assert "secp256k1/Schnorr implementation path" in fields
    assert "SHA-256/event-hash implementation path" in fields
    assert "NIP-44 implementation path" in fields
    assert "NIP-59 support assumptions" in fields


def test_dependency_skeleton_references_provenance_checklist():
    payload = json.loads(SKELETON.read_text(encoding="utf-8"))

    assert payload["dependencyProvenanceChecklist"] == "frontend/nip59/dependency-provenance-checklist.json"
    assert payload["provenanceReviewRequiredBeforeVersionPin"] is True
    assert payload["versionSelectionStatus"] in {
        "pending",
        "candidate-observed-not-pinned",
    }
    assert payload["exactVersionSelected"] is False
    assert payload["realCryptoImplemented"] is False
    assert payload["sendEnabled"] is False


def test_builder_template_still_has_placeholder_not_exact_version():
    payload = json.loads(BUILDER_TEMPLATE.read_text(encoding="utf-8"))

    assert payload["dependencies"]["nostr-tools"] == "PIN_EXACT_VERSION_IN_BUILDER_PR"


def test_root_package_and_bundle_remain_production_safe():
    root = json.loads(ROOT_PACKAGE.read_text(encoding="utf-8"))
    bundle = BUNDLE.read_text(encoding="utf-8")

    assert root["dependencies"] == {}
    assert root["devDependencies"] == {}
    assert not Path("package-lock.json").exists()
    assert not Path("frontend/nip59/package-lock.json").exists()
    assert 'status: "skeleton"' in bundle
    assert "cryptoReady: false" in bundle
    assert "canFinalizeGiftWrap: false" in bundle
    assert "fetch(" not in bundle
