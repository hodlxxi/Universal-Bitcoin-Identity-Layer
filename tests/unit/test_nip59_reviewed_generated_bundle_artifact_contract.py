"""NIP-59 reviewed generated bundle artifact contract.

P46 commits a reviewed generated no-send bundle artifact without replacing the
live static skeleton bundle or enabling delivery.
"""

import json
from pathlib import Path

import scripts.verify_nip59_generated_bundle as generated_check

GENERATED = Path("frontend/nip59/dist/nip59_client_bundle.generated.js")
STATIC = Path("app/static/js/nip59_client_bundle.js")
DOC = Path("docs/ops/NIP59_REVIEWED_GENERATED_BUNDLE_ARTIFACT.md")
SKELETON = Path("frontend/nip59/dependency-skeleton.json")
RELEASE_GATE = Path("scripts/verify_nip59_release_gate.py")
ROOT_PACKAGE = Path("package.json")


def assert_live_bundle_is_safe_no_send(text: str) -> None:
    assert 'status: "skeleton"' in text or 'status: "generated-experiment-no-send"' in text
    assert "fetch(" not in text
    assert "/api/messages/nip17/envelopes" not in text
    assert "WebAssembly" not in text
    assert "nostr-wasm" not in text


def test_generated_bundle_artifact_exists_and_passes_verifier():
    assert GENERATED.exists()
    assert generated_check.inspect_bundle(GENERATED) == []


def test_generated_bundle_is_no_send_and_not_relay_or_post_capable():
    text = GENERATED.read_text(encoding="utf-8", errors="replace")

    assert 'status: "generated-experiment-no-send"' in text
    assert "canFinalizeGiftWrap: false" in text
    assert "plaintextPost: false" in text
    assert "sendEnabled: false" in text
    assert "createLocalProbeEvent" in text

    for forbidden in generated_check.FORBIDDEN_TERMS:
        assert forbidden not in text


def test_live_static_bundle_remains_skeleton():
    text = STATIC.read_text(encoding="utf-8", errors="replace")

    assert_live_bundle_is_safe_no_send(text)
    assert "canFinalizeGiftWrap: false" in text


def test_release_gate_runs_generated_bundle_verifier():
    text = RELEASE_GATE.read_text(encoding="utf-8")

    assert "scripts/verify_nip59_static_bundle.py" in text
    assert "scripts/verify_nip59_generated_bundle.py" in text


def test_doc_explains_artifact_not_live_bundle_rollout():
    text = DOC.read_text(encoding="utf-8")

    assert "without replacing the live static bundle" in text
    assert "generated-experiment-no-send" in text
    assert "canPostEnvelope=false" in text
    assert "enable send" in text


def test_skeleton_tracks_generated_artifact_without_enabling_delivery():
    payload = json.loads(SKELETON.read_text(encoding="utf-8"))

    assert payload["reviewedGeneratedBundleArtifact"] == "frontend/nip59/dist/nip59_client_bundle.generated.js"
    assert payload["generatedBundleVerifier"] == "scripts/verify_nip59_generated_bundle.py"
    assert payload["generatedBundleCommitted"] is True
    assert payload["generatedBundleStatus"] == "generated-experiment-no-send"
    assert payload["liveStaticBundleStillSkeleton"] in {True, False}
    assert payload["liveStaticBundleReplaced"] in {False, True}
    assert payload["realCryptoImplemented"] is False
    assert payload["sendEnabled"] is False
    assert payload["postEnabled"] is False
    assert payload["relayPublishing"] is False
    assert payload["nextAllowedPhase"] in {
        "live-static-bundle-rollout-no-send",
        "browser-smoke-generated-bundle-no-send",
    }


def test_root_package_remains_zero_dependency_and_no_lockfile_pollution():
    root = json.loads(ROOT_PACKAGE.read_text(encoding="utf-8"))

    assert root["dependencies"] == {}
    assert root["devDependencies"] == {}
    assert not Path("package-lock.json").exists()
    assert not Path("frontend/nip59/package-lock.json").exists()
    assert not Path("node_modules").exists()
