"""NIP-59 narrow import bundle evidence contract.

P45 records that top-level nostr-tools import is unsafe for the browser bundle,
while reviewed narrow imports produced a generated no-send bundle without
forbidden network/relay/wasm surface in the Mac experiment.
"""

import json
from pathlib import Path

SOURCE = Path("frontend/nip59/src/client.js")
DOC = Path("docs/ops/NIP59_NARROW_IMPORT_BUNDLE_EVIDENCE.md")
EVIDENCE = Path("frontend/nip59/narrow-import-bundle-evidence.json")
SKELETON = Path("frontend/nip59/dependency-skeleton.json")
ROOT_PACKAGE = Path("package.json")
STATIC_BUNDLE = Path("app/static/js/nip59_client_bundle.js")


def test_source_uses_narrow_imports_not_top_level_nostr_tools():
    text = SOURCE.read_text(encoding="utf-8")

    assert 'from "nostr-tools/pure"' in text
    assert 'from "nostr-tools/nip44"' in text
    assert 'from "nostr-tools";' not in text
    assert "@nostr/tools/wasm" not in text
    assert "nostr-wasm" not in text
    assert "WebAssembly" not in text
    assert "fetch(" not in text
    assert "/api/messages/nip17/envelopes" not in text


def test_evidence_records_top_level_import_rejected_and_narrow_import_passed():
    payload = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    assert payload["status"] == "narrow-import-bundle-experiment-passed"
    assert payload["sourceImportBefore"] == "nostr-tools"
    assert payload["sourceImportAfter"] == ["nostr-tools/pure", "nostr-tools/nip44"]

    top = payload["topLevelImportResult"]
    assert top["bundleBytes"] == 210664
    assert top["forbiddenSurfaceObserved"] is True
    assert "fetch(" in top["observedForbiddenSurface"]

    narrow = payload["narrowImportResult"]
    assert narrow["bundleBytes"] == 118978
    assert narrow["forbiddenHardTermsObserved"] is False
    assert narrow["relaySurfaceTermsObserved"] is False
    assert narrow["directSourceForbiddenHardTermsObserved"] is False


def test_evidence_records_no_send_smoke_result():
    payload = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    smoke = payload["smokeResult"]
    assert smoke["status"] == "generated-experiment-no-send"
    assert smoke["cryptoReady"] is False
    assert smoke["cryptoReadyCandidate"] is True
    assert smoke["canFinalizeLocalProbe"] is True
    assert smoke["canFinalizeGiftWrap"] is False
    assert smoke["canPostEnvelope"] is False
    assert smoke["relayPublishing"] is False
    assert smoke["plaintextPost"] is False
    assert smoke["sendEnabled"] is False
    assert smoke["probeEventVerified"] is True
    assert smoke["probeNetworkPost"] is False


def test_doc_explains_decision_and_boundary():
    text = DOC.read_text(encoding="utf-8")

    assert "top-level `nostr-tools` import is not acceptable" in text
    assert "`nostr-tools/pure`" in text
    assert "`nostr-tools/nip44`" in text
    assert "Forbidden hard terms after narrow import: none observed" in text
    assert "It does not commit:" in text
    assert "generated browser bundle" in text
    assert "sendEnabled=false" in text


def test_skeleton_tracks_narrow_import_bundle_evidence_without_runtime_enablement():
    payload = json.loads(SKELETON.read_text(encoding="utf-8"))

    assert payload["minimalSourceImportMode"] == "narrow-imports"
    assert payload["topLevelNostrToolsImportAllowed"] is False
    assert payload["allowedNostrToolsImports"] == ["nostr-tools/pure", "nostr-tools/nip44"]
    assert payload["narrowImportBundleEvidence"] == "frontend/nip59/narrow-import-bundle-evidence.json"
    assert payload["narrowImportBundleEvidenceDoc"] == "docs/ops/NIP59_NARROW_IMPORT_BUNDLE_EVIDENCE.md"
    assert payload["generatedBundleExperimentCompletedOutsideProduction"] is True
    assert payload["generatedBundleHardForbiddenTermsObserved"] is False
    assert payload["generatedBundleRelaySurfaceObserved"] is False
    assert payload["generatedBundleCommitted"] in {False, True}
    assert payload["realCryptoImplemented"] is False
    assert payload["sendEnabled"] is False
    assert payload["nextAllowedPhase"] in {
        "reviewed-generated-bundle-no-send",
        "live-static-bundle-rollout-no-send",
    }


def test_root_package_and_static_bundle_remain_unchanged():
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
