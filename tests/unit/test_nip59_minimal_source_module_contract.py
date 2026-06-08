"""NIP-59 minimal source module contract.

P44 introduces a real source module, but does not build a bundle, replace the
static bundle, enable send, enable intake, or enable relay publishing.
"""

import json
from pathlib import Path

SOURCE = Path("frontend/nip59/src/client.js")
DOC = Path("docs/ops/NIP59_MINIMAL_SOURCE_MODULE.md")
SKELETON = Path("frontend/nip59/dependency-skeleton.json")
ROOT_PACKAGE = Path("package.json")
STATIC_BUNDLE = Path("app/static/js/nip59_client_bundle.js")


FORBIDDEN_SOURCE_TERMS = [
    "@nostr/tools/wasm",
    "nostr-wasm",
    "initNostrWasm",
    "setNostrWasm",
    "NostrWasm",
    "WebAssembly",
    "fetch(",
    "XMLHttpRequest",
    "/api/messages/nip17/envelopes",
    "Relay",
    "SimplePool",
]


def test_source_module_exists_and_uses_normal_nostr_tools_import_only():
    text = SOURCE.read_text(encoding="utf-8")

    assert 'from "nostr-tools"' in text or 'from "nostr-tools/pure"' in text
    assert "finalizeEvent" in text
    assert "generateSecretKey" in text
    assert "getPublicKey" in text
    assert "verifyEvent" in text
    assert "nip44" in text

    for term in FORBIDDEN_SOURCE_TERMS:
        assert term not in text


def test_source_module_is_no_send_no_post_no_relay():
    text = SOURCE.read_text(encoding="utf-8")

    assert 'status: "minimal-source-no-send"' in text
    assert "networkPost: false" in text
    assert "relayPublishing: false" in text
    assert "plaintextPost: false" in text
    assert "sendEnabled: false" in text
    assert "postEnabled: false" in text
    assert "createLocalProbeEvent" in text
    assert "assertNoSendAvailable" in text


def test_doc_explains_source_module_boundary():
    text = DOC.read_text(encoding="utf-8")

    assert "first real NIP-59 browser-client source module" in text
    assert "does not replace the production static bundle" in text
    assert "normal `nostr-tools` only" in text
    assert "`@nostr/tools/wasm`" in text
    assert "`nostr-wasm`" in text
    assert "sendEnabled=false" in text


def test_skeleton_tracks_minimal_source_without_runtime_enablement():
    payload = json.loads(SKELETON.read_text(encoding="utf-8"))

    assert payload["minimalSourceModule"] == "frontend/nip59/src/client.js"
    assert payload["minimalSourceModuleDoc"] == "docs/ops/NIP59_MINIMAL_SOURCE_MODULE.md"
    assert payload["minimalSourceModuleStatus"] == "source-only-no-send"
    assert payload["normalNostrToolsImportRequired"] is True
    assert payload["wasmImportAllowed"] is False
    assert payload["sourceNetworkPostAllowed"] is False
    assert payload["sourceRelayPublishingAllowed"] is False
    assert payload["candidateApprovedForCrypto"] is False
    assert payload["exactVersionSelected"] is False
    assert payload["productionInstallAllowed"] is False
    assert payload["realCryptoImplemented"] is False
    assert payload["sendEnabled"] is False
    assert payload["postEnabled"] is False
    assert payload["relayPublishing"] is False
    assert payload["nextAllowedPhase"] in {
        "generated-bundle-experiment-no-send",
        "reviewed-generated-bundle-no-send",
        "live-static-bundle-rollout-no-send",
    }


def test_static_bundle_remains_skeleton_and_root_package_zero_dependency():
    root = json.loads(ROOT_PACKAGE.read_text(encoding="utf-8"))
    bundle = STATIC_BUNDLE.read_text(encoding="utf-8")

    assert root["dependencies"] == {}
    assert root["devDependencies"] == {}
    assert not Path("package-lock.json").exists()
    assert not Path("frontend/nip59/package-lock.json").exists()
    assert not Path("node_modules").exists()

    assert 'status: "skeleton"' in bundle
    assert "cryptoReady: false" in bundle
    assert "canFinalizeGiftWrap: false" in bundle
    assert "canPostEnvelope: false" in bundle
