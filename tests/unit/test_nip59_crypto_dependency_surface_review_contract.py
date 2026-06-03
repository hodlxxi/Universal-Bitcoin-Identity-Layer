"""NIP-59 crypto dependency surface review contract.

P32 records the direct dependency surface and blocks lockfile/build work until
nostr-wasm is reviewed. It does not enable crypto or delivery.
"""

import json
from pathlib import Path

DOC = Path("docs/ops/NIP59_CRYPTO_DEPENDENCY_SURFACE_REVIEW.md")
REVIEW = Path("frontend/nip59/crypto-dependency-surface-review.json")
SKELETON = Path("frontend/nip59/dependency-skeleton.json")
ROOT_PACKAGE = Path("package.json")
BUNDLE = Path("app/static/js/nip59_client_bundle.js")


def test_review_record_does_not_approve_crypto_or_delivery():
    payload = json.loads(REVIEW.read_text(encoding="utf-8"))

    assert payload["status"] == "review-record-only"
    assert payload["candidatePackage"] == "nostr-tools"
    assert payload["candidateVersion"] == "2.23.5"
    assert payload["candidateApprovedForCrypto"] is False
    assert payload["lockfileGenerated"] is False
    assert payload["productionInstallAllowed"] is False
    assert payload["cryptoImplemented"] is False
    assert payload["sendEnabled"] is False
    assert payload["postEnabled"] is False
    assert payload["relayPublishing"] is False


def test_dependency_surface_records_expected_packages():
    payload = json.loads(REVIEW.read_text(encoding="utf-8"))
    packages = {item["name"]: item for item in payload["dependencySurface"]}

    assert packages["@noble/ciphers"]["version"] == "2.1.1"
    assert packages["@noble/curves"]["version"] == "2.0.1"
    assert packages["@noble/hashes"]["version"] == "2.0.1"
    assert packages["@scure/base"]["version"] == "2.0.0"
    assert packages["@scure/bip32"]["version"] == "2.0.1"
    assert packages["@scure/bip39"]["version"] == "2.0.1"
    assert packages["nostr-wasm"]["version"] == "0.1.0"


def test_nostr_wasm_is_marked_as_blocker():
    payload = json.loads(REVIEW.read_text(encoding="utf-8"))
    packages = {item["name"]: item for item in payload["dependencySurface"]}
    nostr_wasm = packages["nostr-wasm"]

    assert nostr_wasm["repositoryPresent"] is False
    assert nostr_wasm["homepagePresent"] is False
    assert nostr_wasm["reviewStatus"] == "pending-blocker"
    assert "nostr-wasm role in browser bundle is not reviewed" in payload["blockers"]


def test_doc_explains_no_build_before_nostr_wasm_review():
    text = DOC.read_text(encoding="utf-8")

    assert "does not approve the candidate for production browser crypto" in text
    assert "`nostr-wasm@0.1.0` is a blocker" in text
    assert "no repository URL" in text
    assert "no homepage URL" in text
    assert "Before any lockfile/build PR" in text


def test_skeleton_tracks_review_without_approving_crypto():
    payload = json.loads(SKELETON.read_text(encoding="utf-8"))

    assert payload["cryptoDependencySurfaceReview"] == "frontend/nip59/crypto-dependency-surface-review.json"
    assert payload["nostrWasmReviewStatus"] in {
        "pending-blocker",
        "avoidable-if-wasm-export-not-imported-unproven",
    }
    assert payload["candidateApprovedForCrypto"] is False
    assert payload["versionSelectionStatus"] == "candidate-observed-not-approved"
    assert payload["exactVersionSelected"] is False
    assert payload["realCryptoImplemented"] is False
    assert payload["sendEnabled"] is False


def test_root_package_and_static_bundle_remain_safe():
    root = json.loads(ROOT_PACKAGE.read_text(encoding="utf-8"))
    bundle = BUNDLE.read_text(encoding="utf-8")

    assert root["dependencies"] == {}
    assert root["devDependencies"] == {}
    assert not Path("package-lock.json").exists()
    assert not Path("frontend/nip59/package-lock.json").exists()
    assert 'status: "skeleton"' in bundle
    assert "cryptoReady: false" in bundle
    assert "canFinalizeGiftWrap: false" in bundle
    assert "canPostEnvelope: false" in bundle
    assert "finalizeEvent" not in bundle
    assert "fetch(" not in bundle
