"""NIP-59 live static bundle rollout contract.

P47 makes the reviewed generated no-send bundle the live static artifact, while
keeping send, POST, intake, and relay publishing disabled.
"""

import json
from pathlib import Path

import scripts.verify_nip59_generated_bundle as generated_check
import scripts.verify_nip59_static_bundle as static_check

STATIC = Path("app/static/js/nip59_client_bundle.js")
GENERATED = Path("frontend/nip59/dist/nip59_client_bundle.generated.js")
DOC = Path("docs/ops/NIP59_LIVE_STATIC_BUNDLE_ROLLOUT_NO_SEND.md")
SKELETON = Path("frontend/nip59/dependency-skeleton.json")
ROOT_PACKAGE = Path("package.json")


def test_live_static_bundle_matches_reviewed_generated_artifact():
    assert STATIC.read_bytes() == GENERATED.read_bytes()


def test_live_static_bundle_passes_static_verifier():
    assert static_check.inspect_bundle(STATIC) == []


def test_generated_artifact_still_passes_generated_verifier():
    assert generated_check.inspect_bundle(GENERATED) == []


def test_live_static_bundle_is_generated_no_send():
    text = STATIC.read_text(encoding="utf-8", errors="replace")

    assert 'status: "generated-experiment-no-send"' in text
    assert "cryptoReady: false" in text
    assert "canFinalizeGiftWrap: false" in text
    assert "canPostEnvelope: false" in text
    assert "relayPublishing: false" in text
    assert "plaintextPost: false" in text
    assert "sendEnabled: false" in text
    assert "createLocalProbeEvent" in text

    for forbidden in static_check.FORBIDDEN_TERMS:
        assert forbidden not in text


def test_doc_explains_no_send_runtime_boundary():
    text = DOC.read_text(encoding="utf-8")

    assert "reviewed generated no-send artifact" in text
    assert "canPostEnvelope=false" in text
    assert "sendEnabled=false" in text
    assert "intake_enabled=false" in text
    assert "relay_publishing=false" in text


def test_skeleton_tracks_live_static_rollout_without_delivery_enablement():
    payload = json.loads(SKELETON.read_text(encoding="utf-8"))

    assert payload["liveStaticBundleStillSkeleton"] is False
    assert payload["liveStaticBundleReplaced"] is True
    assert payload["liveStaticBundleSource"] == "frontend/nip59/dist/nip59_client_bundle.generated.js"
    assert payload["staticBundleStatus"] == "generated-no-send-live-inspected"
    assert payload["liveStaticBundleRollout"] == "no-send"
    assert payload["realCryptoImplemented"] is False
    assert payload["sendEnabled"] is False
    assert payload["postEnabled"] is False
    assert payload["relayPublishing"] is False
    assert payload["nextAllowedPhase"] == "browser-smoke-generated-bundle-no-send"


def test_root_package_remains_zero_dependency_and_no_lockfile_pollution():
    root = json.loads(ROOT_PACKAGE.read_text(encoding="utf-8"))

    assert root["dependencies"] == {}
    assert root["devDependencies"] == {}
    assert not Path("package-lock.json").exists()
    assert not Path("frontend/nip59/package-lock.json").exists()
    assert not Path("node_modules").exists()
