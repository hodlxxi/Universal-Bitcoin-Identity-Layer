"""NIP-59 nostr-tools candidate evidence contract.

P31 records observed external npm metadata without selecting, installing,
pinning, building, or enabling browser crypto.
"""

import json
from pathlib import Path

DOC = Path("docs/ops/NIP59_NOSTR_TOOLS_CANDIDATE_EVIDENCE.md")
EVIDENCE = Path("frontend/nip59/nostr-tools-candidate-evidence.json")
SKELETON = Path("frontend/nip59/dependency-skeleton.json")
BUILDER_TEMPLATE = Path("frontend/nip59/package.builder.template.json")
ROOT_PACKAGE = Path("package.json")
BUNDLE = Path("app/static/js/nip59_client_bundle.js")


def assert_live_bundle_is_safe_no_send(text: str) -> None:
    assert 'status: "skeleton"' in text or 'status: "generated-experiment-no-send"' in text
    assert "fetch(" not in text
    assert "/api/messages/nip17/envelopes" not in text
    assert "WebAssembly" not in text
    assert "nostr-wasm" not in text


def test_candidate_evidence_records_observed_metadata_without_selection():
    payload = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    assert payload["status"] == "candidate-observed-not-pinned"
    assert payload["candidatePackage"] == "nostr-tools"
    assert payload["candidateVersion"] == "2.23.5"
    assert payload["versionSelected"] is False
    assert payload["exactVersionPinned"] is False
    assert payload["lockfileGenerated"] is False
    assert payload["productionInstallAllowed"] is False
    assert payload["cryptoImplemented"] is False
    assert payload["sendEnabled"] is False
    assert payload["postEnabled"] is False
    assert payload["relayPublishing"] is False


def test_candidate_evidence_records_integrity_and_direct_deps():
    payload = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    assert payload["license"] == "Unlicense"
    assert payload["repository"]["url"] == "git+https://github.com/nbd-wtf/nostr-tools.git"
    assert payload["dist"]["tarball"].endswith("/nostr-tools-2.23.5.tgz")
    assert payload["dist"]["integrity"].startswith("sha512-")

    deps = payload["directDependencies"]
    assert deps["@noble/ciphers"] == "2.1.1"
    assert deps["@noble/curves"] == "2.0.1"
    assert deps["@noble/hashes"] == "2.0.1"
    assert deps["@scure/base"] == "2.0.0"
    assert deps["@scure/bip32"] == "2.0.1"
    assert deps["@scure/bip39"] == "2.0.1"
    assert deps["nostr-wasm"] == "0.1.0"


def test_doc_says_candidate_is_not_yet_approved():
    text = DOC.read_text(encoding="utf-8")

    assert "does not select or pin" in text
    assert "not yet approved for production browser crypto" in text
    assert "Production still must not run `npm install`" in text
    assert "`nostr-wasm` role review" in text


def test_skeleton_tracks_candidate_without_enabling_crypto():
    payload = json.loads(SKELETON.read_text(encoding="utf-8"))

    assert payload["candidateEvidence"] == "frontend/nip59/nostr-tools-candidate-evidence.json"
    assert payload["candidateVersionObserved"] == "2.23.5"
    assert payload["versionSelectionStatus"] in {
        "candidate-observed-not-pinned",
        "candidate-observed-not-approved",
    }
    assert payload["exactVersionSelected"] is False
    assert payload["realCryptoImplemented"] is False
    assert payload["sendEnabled"] is False
    assert payload["postEnabled"] is False
    assert payload["relayPublishing"] is False


def test_builder_template_still_has_placeholder_not_real_version():
    payload = json.loads(BUILDER_TEMPLATE.read_text(encoding="utf-8"))

    assert payload["dependencies"]["nostr-tools"] == "PIN_EXACT_VERSION_IN_BUILDER_PR"


def test_root_package_and_bundle_remain_safe():
    root = json.loads(ROOT_PACKAGE.read_text(encoding="utf-8"))
    bundle = BUNDLE.read_text(encoding="utf-8")

    assert root["dependencies"] == {}
    assert root["devDependencies"] == {}
    assert not Path("package-lock.json").exists()
    assert not Path("frontend/nip59/package-lock.json").exists()
    assert_live_bundle_is_safe_no_send(bundle)
    assert "canFinalizeGiftWrap: false" in bundle
    # P47 live bundle may include reviewed narrow-import nostr-tools code.
    # P47 live generated no-send bundle may include local finalizeEvent probe code.
    assert "fetch(" not in bundle
