"""NIP-59 import policy scanner contract.

P35 adds a source scanner that enforces the P34 import policy without
installing dependencies, building a bundle, enabling crypto, or enabling send.
"""

import json
from pathlib import Path

import scripts.verify_nip59_import_policy as scanner

DOC = Path("docs/ops/NIP59_IMPORT_POLICY_SCANNER.md")
POLICY = Path("frontend/nip59/import-policy.json")
SKELETON = Path("frontend/nip59/dependency-skeleton.json")
SCANNER = Path("scripts/verify_nip59_import_policy.py")
ROOT_PACKAGE = Path("package.json")
BUNDLE = Path("app/static/js/nip59_client_bundle.js")


def test_scanner_script_exists_and_policy_is_still_runtime_disabled():
    assert SCANNER.exists()

    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    assert policy["status"] == "policy-only"
    assert policy["bundleGenerated"] is False
    assert policy["cryptoImplemented"] is False
    assert policy["sendEnabled"] is False
    assert policy["candidateApprovedForCrypto"] is False


def test_scanner_passes_current_repo_sources():
    assert scanner.main() == 0


def test_scanner_detects_forbidden_terms_in_source_file(tmp_path):
    bad = tmp_path / "bad.js"
    bad.write_text("import { verifyEvent } from '@nostr/tools/wasm';\n", encoding="utf-8")

    policy = scanner.load_policy()
    forbidden_terms = list(policy["forbiddenImports"]) + list(policy["forbiddenIdentifiers"])

    violations = scanner.scan_file(bad, forbidden_terms)
    assert violations
    assert "@nostr/tools/wasm" in violations[0]


def test_scanner_detects_forbidden_webassembly_identifier(tmp_path):
    bad = tmp_path / "bad.js"
    bad.write_text("const runtime = WebAssembly;\n", encoding="utf-8")

    policy = scanner.load_policy()
    forbidden_terms = list(policy["forbiddenImports"]) + list(policy["forbiddenIdentifiers"])

    violations = scanner.scan_file(bad, forbidden_terms)
    assert violations
    assert "WebAssembly" in violations[0]


def test_doc_explains_scanner_scope_and_no_runtime_changes():
    text = DOC.read_text(encoding="utf-8")

    assert "enforces the NIP-59 builder import policy" in text
    assert "`@nostr/tools/wasm`" in text
    assert "`nostr-wasm`" in text
    assert "does not scan docs, tests, JSON policy records" in text
    assert "install npm" in text
    assert "build a bundle" in text


def test_skeleton_tracks_scanner_without_approving_crypto():
    payload = json.loads(SKELETON.read_text(encoding="utf-8"))

    assert payload["builderImportPolicyScanner"] == "scripts/verify_nip59_import_policy.py"
    assert payload["importPolicyScannerRequiredBeforeBundle"] is True
    assert payload["forbidWasmImports"] is True
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
