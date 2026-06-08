"""NIP-59 builder source placeholder contract.

P36 creates a future browser-client source location under import-policy scanner
control without installing dependencies, building a bundle, enabling crypto, or
enabling send.
"""

import json
from pathlib import Path

import scripts.verify_nip59_import_policy as scanner

DOC = Path("docs/ops/NIP59_BUILDER_SOURCE_PLACEHOLDER.md")
PLACEHOLDER = Path("frontend/nip59/src/client_placeholder.js")
SKELETON = Path("frontend/nip59/dependency-skeleton.json")
ROOT_PACKAGE = Path("package.json")
BUNDLE = Path("app/static/js/nip59_client_bundle.js")


def assert_live_bundle_is_safe_no_send(text: str) -> None:
    assert 'status: "skeleton"' in text or 'status: "generated-experiment-no-send"' in text
    assert "fetch(" not in text
    assert "/api/messages/nip17/envelopes" not in text
    assert "WebAssembly" not in text
    assert "nostr-wasm" not in text


def test_placeholder_source_exists_and_is_non_crypto():
    text = PLACEHOLDER.read_text(encoding="utf-8")

    assert 'status: "placeholder"' in text
    assert "canFinalizeGiftWrap: false" in text
    assert "dependencies: []" in text


def test_placeholder_does_not_import_forbidden_or_real_crypto_terms():
    text = PLACEHOLDER.read_text(encoding="utf-8")

    assert "nostr-tools" not in text
    assert "@nostr/tools/wasm" not in text
    assert "nostr-wasm" not in text
    assert "initNostrWasm" not in text
    assert "setNostrWasm" not in text
    assert "WebAssembly" not in text
    assert "finalizeEvent" not in text
    assert "fetch(" not in text


def test_import_policy_scanner_scans_placeholder_source():
    files = list(scanner.iter_source_files(scanner.DEFAULT_SCAN_PATHS))
    relative = {str(path.relative_to(scanner.ROOT)) for path in files}

    assert "frontend/nip59/src/client_placeholder.js" in relative
    assert scanner.main() == 0


def test_skeleton_tracks_builder_source_placeholder_without_approval():
    payload = json.loads(SKELETON.read_text(encoding="utf-8"))

    assert payload["builderSourceRoot"] == "frontend/nip59/src"
    assert payload["builderSourcePlaceholder"] == "frontend/nip59/src/client_placeholder.js"
    assert payload["builderSourceUnderImportPolicyScanner"] is True
    assert payload["candidateApprovedForCrypto"] is False
    assert payload["exactVersionSelected"] is False
    assert payload["realCryptoImplemented"] is False
    assert payload["sendEnabled"] is False
    assert payload["postEnabled"] is False
    assert payload["relayPublishing"] is False


def test_doc_explains_placeholder_safety():
    text = DOC.read_text(encoding="utf-8")

    assert "intentionally non-cryptographic" in text
    assert "`frontend/nip59/src/client_placeholder.js`" in text
    assert "import-policy scanner" in text
    assert "does not:" in text
    assert "enable send" in text


def test_root_package_and_static_bundle_remain_safe():
    root = json.loads(ROOT_PACKAGE.read_text(encoding="utf-8"))
    bundle = BUNDLE.read_text(encoding="utf-8")

    assert root["dependencies"] == {}
    assert root["devDependencies"] == {}
    assert not Path("package-lock.json").exists()
    assert not Path("frontend/nip59/package-lock.json").exists()
    assert_live_bundle_is_safe_no_send(bundle)
    assert "canFinalizeGiftWrap: false" in bundle
