"""NIP-59 builder import policy contract.

P34 forbids the wasm import path before any real builder/bundle work starts.
It does not install dependencies, build a bundle, enable crypto, or enable send.
"""

import json
from pathlib import Path

DOC = Path("docs/ops/NIP59_BUILDER_IMPORT_POLICY.md")
POLICY = Path("frontend/nip59/import-policy.json")
SKELETON = Path("frontend/nip59/dependency-skeleton.json")
ROOT_PACKAGE = Path("package.json")
BUNDLE = Path("app/static/js/nip59_client_bundle.js")


def test_import_policy_is_policy_only_and_does_not_enable_runtime():
    payload = json.loads(POLICY.read_text(encoding="utf-8"))

    assert payload["status"] == "policy-only"
    assert payload["candidatePackage"] == "nostr-tools"
    assert payload["candidateVersion"] == "2.23.5"
    assert payload["productionInstallAllowed"] is False
    assert payload["lockfileGenerated"] is False
    assert payload["bundleGenerated"] is False
    assert payload["cryptoImplemented"] is False
    assert payload["sendEnabled"] is False
    assert payload["postEnabled"] is False
    assert payload["relayPublishing"] is False
    assert payload["candidateApprovedForCrypto"] is False


def test_import_policy_forbids_wasm_paths_and_identifiers():
    payload = json.loads(POLICY.read_text(encoding="utf-8"))

    assert "@nostr/tools/wasm" in payload["forbiddenImports"]
    assert "nostr-wasm" in payload["forbiddenImports"]
    assert "initNostrWasm" in payload["forbiddenIdentifiers"]
    assert "setNostrWasm" in payload["forbiddenIdentifiers"]
    assert "NostrWasm" in payload["forbiddenIdentifiers"]
    assert "WebAssembly" in payload["forbiddenIdentifiers"]


def test_doc_explains_forbidden_wasm_policy():
    text = DOC.read_text(encoding="utf-8")

    assert "must avoid the explicit wasm path" in text
    assert "`@nostr/tools/wasm`" in text
    assert "`nostr-wasm`" in text
    assert "`WebAssembly`" in text
    assert "does not approve `nostr-tools` for production browser crypto" in text


def test_skeleton_tracks_import_policy_without_approving_crypto():
    payload = json.loads(SKELETON.read_text(encoding="utf-8"))

    assert payload["builderImportPolicy"] == "frontend/nip59/import-policy.json"
    assert payload["forbidWasmImports"] is True
    assert payload["candidateApprovedForCrypto"] is False
    assert payload["versionSelectionStatus"] == "candidate-observed-not-approved"
    assert payload["exactVersionSelected"] is False
    assert payload["realCryptoImplemented"] is False
    assert payload["sendEnabled"] is False
    assert payload["postEnabled"] is False
    assert payload["relayPublishing"] is False


def test_static_bundle_remains_skeleton_and_contains_no_wasm_path():
    bundle = BUNDLE.read_text(encoding="utf-8")

    assert 'status: "skeleton"' in bundle
    assert "cryptoReady: false" in bundle
    assert "canFinalizeGiftWrap: false" in bundle
    assert "canPostEnvelope: false" in bundle
    assert "@nostr/tools/wasm" not in bundle
    assert "nostr-wasm" not in bundle
    assert "initNostrWasm" not in bundle
    assert "setNostrWasm" not in bundle
    assert "WebAssembly" not in bundle
    assert "fetch(" not in bundle


def test_root_package_remains_zero_dependency_and_no_lockfile_exists():
    root = json.loads(ROOT_PACKAGE.read_text(encoding="utf-8"))

    assert root["dependencies"] == {}
    assert root["devDependencies"] == {}
    assert not Path("package-lock.json").exists()
    assert not Path("frontend/nip59/package-lock.json").exists()
    assert not Path("pnpm-lock.yaml").exists()
    assert not Path("yarn.lock").exists()
