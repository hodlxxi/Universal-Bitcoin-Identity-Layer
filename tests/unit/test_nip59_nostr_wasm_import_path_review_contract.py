"""NIP-59 nostr-wasm import path review contract.

P33 records evidence that nostr-wasm is tied to the explicit wasm export path
and requires future bundle proof before crypto can be enabled.
"""

import json
from pathlib import Path

DOC = Path("docs/ops/NIP59_NOSTR_WASM_IMPORT_PATH_REVIEW.md")
REVIEW = Path("frontend/nip59/nostr-wasm-import-path-review.json")
SKELETON = Path("frontend/nip59/dependency-skeleton.json")
ROOT_PACKAGE = Path("package.json")
BUNDLE = Path("app/static/js/nip59_client_bundle.js")


def test_import_path_review_records_wasm_path_without_approval():
    payload = json.loads(REVIEW.read_text(encoding="utf-8"))

    assert payload["status"] == "review-record-only"
    assert payload["candidatePackage"] == "nostr-tools"
    assert payload["candidateVersion"] == "2.23.5"
    assert payload["wasmPackage"] == "nostr-wasm"
    assert payload["wasmVersion"] == "0.1.0"
    assert payload["candidateApprovedForCrypto"] is False
    assert payload["productionInstallAllowed"] is False
    assert payload["lockfileGenerated"] is False
    assert payload["bundleGenerated"] is False
    assert payload["cryptoImplemented"] is False
    assert payload["sendEnabled"] is False


def test_import_path_review_records_explicit_wasm_export():
    payload = json.loads(REVIEW.read_text(encoding="utf-8"))
    observations = payload["observations"]

    assert observations["nostrToolsInstallsNostrWasm"] is True
    assert observations["nostrToolsHasExplicitWasmExport"] is True
    assert observations["explicitWasmExport"] == "./wasm"
    assert observations["wasmExportImportPath"] == "@nostr/tools/wasm"
    assert observations["wasmExportImportsNostrWasm"] is True
    assert observations["defaultBundleAvoidanceLikelyButUnproven"] is True


def test_review_requires_future_bundle_proof():
    payload = json.loads(REVIEW.read_text(encoding="utf-8"))

    required = set(payload["requiredFutureProofs"])
    assert "prove final browser bundle does not import @nostr/tools/wasm" in required
    assert "prove final browser bundle does not include nostr-wasm" in required
    assert "prove final browser bundle does not include WebAssembly code from nostr-wasm" in required


def test_doc_explains_no_wasm_import_policy():
    text = DOC.read_text(encoding="utf-8")

    assert "does not approve `nostr-tools` for production browser crypto" in text
    assert "do not import `@nostr/tools/wasm`" in text
    assert "do not import `nostr-wasm`" in text
    assert "not yet proven by a bundler artifact" in text


def test_skeleton_tracks_import_path_review_without_approval():
    payload = json.loads(SKELETON.read_text(encoding="utf-8"))

    assert payload["nostrWasmImportPathReview"] == "frontend/nip59/nostr-wasm-import-path-review.json"
    assert payload["nostrWasmReviewStatus"] == "avoidable-if-wasm-export-not-imported-unproven"
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
    assert "@nostr/tools/wasm" not in bundle
    assert "nostr-wasm" not in bundle
    assert "WebAssembly" not in bundle
    assert "fetch(" not in bundle
