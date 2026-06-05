"""NIP-59 pre-build readiness checkpoint contract.

P40 records that the safety ladder is complete before the first controlled
build experiment. It still does not approve npm, lockfiles, bundle replacement,
browser crypto, send, intake, or relay publishing.
"""

import json
from pathlib import Path

DOC = Path("docs/ops/NIP59_PRE_BUILD_READINESS_CHECKPOINT.md")
CHECKPOINT = Path("frontend/nip59/pre-build-readiness-checkpoint.json")
SKELETON = Path("frontend/nip59/dependency-skeleton.json")
ROOT_PACKAGE = Path("package.json")
BUNDLE = Path("app/static/js/nip59_client_bundle.js")


def test_checkpoint_records_pre_build_safety_complete_without_crypto_approval():
    payload = json.loads(CHECKPOINT.read_text(encoding="utf-8"))

    assert payload["status"] == "pre-build-safety-complete"
    assert payload["checkpointPhase"] == "before-first-controlled-build-experiment"
    assert payload["candidatePackage"] == "nostr-tools"
    assert payload["candidateVersionObserved"] == "2.23.5"
    assert payload["candidateApprovedForCrypto"] is False
    assert payload["exactVersionSelected"] is False
    assert payload["productionInstallAllowed"] is False
    assert payload["productionNpmRequired"] is False
    assert payload["rootPackageMutationAllowed"] is False
    assert payload["lockfileGenerated"] is False
    assert payload["bundleGenerated"] is False
    assert payload["cryptoImplemented"] is False
    assert payload["sendEnabled"] is False
    assert payload["postEnabled"] is False
    assert payload["relayPublishing"] is False
    assert payload["intakeEnabled"] is False


def test_checkpoint_lists_existing_release_gate_protection():
    payload = json.loads(CHECKPOINT.read_text(encoding="utf-8"))

    protected = set(payload["protectedBy"])
    assert "scripts/verify_nip59_builder_safety.py" in protected
    assert "scripts/verify_nip59_import_policy.py" in protected
    assert "scripts/verify_nip59_static_bundle.py" in protected
    assert "scripts/verify_nip59_release_gate.py" in protected
    assert "scripts/release_gate_smoke_check.sh" in protected


def test_checkpoint_forbids_production_install_and_wasm_send_paths():
    payload = json.loads(CHECKPOINT.read_text(encoding="utf-8"))

    forbidden = set(payload["forbiddenBeforeNextApproval"])
    assert "npm install on production" in forbidden
    assert "committing node_modules" in forbidden
    assert "importing @nostr/tools/wasm" in forbidden
    assert "importing nostr-wasm" in forbidden
    assert "using WebAssembly" in forbidden
    assert "setting cryptoReady true" in forbidden
    assert "enabling send" in forbidden
    assert "posting to /api/messages/nip17/envelopes" in forbidden


def test_checkpoint_allows_only_non_production_build_experiment_next():
    payload = json.loads(CHECKPOINT.read_text(encoding="utf-8"))

    assert payload["nextAllowedPhase"] == "controlled-build-experiment-outside-production"
    required = set(payload["nextAllowedPhaseRequires"])
    assert "Mac or non-production builder host" in required
    assert "reviewed package-lock.json generated outside production" in required
    assert "bundle inspection proving forbidden terms absent" in required
    assert "NIP-59 release gate passing before commit" in required


def test_doc_explains_checkpoint_boundary():
    text = DOC.read_text(encoding="utf-8")

    assert "does not approve browser crypto" in text
    assert "Production npm is not required" in text
    assert "run `npm install` on production" in text
    assert "controlled build experiment outside production" in text
    assert "NIP-59 release gate passes before commit" in text


def test_skeleton_tracks_pre_build_checkpoint_without_approval():
    payload = json.loads(SKELETON.read_text(encoding="utf-8"))

    assert payload["preBuildReadinessCheckpoint"] == "frontend/nip59/pre-build-readiness-checkpoint.json"
    assert payload["preBuildSafetyLadderComplete"] is True
    assert payload["nextAllowedPhase"] == "controlled-build-experiment-outside-production"
    assert payload["candidateApprovedForCrypto"] is False
    assert payload["exactVersionSelected"] is False
    assert payload["productionInstallAllowed"] is False
    assert payload["productionNpmRequired"] is False
    assert payload["rootPackageMutationAllowed"] is False
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
