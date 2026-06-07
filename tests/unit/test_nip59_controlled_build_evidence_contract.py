"""NIP-59 controlled build evidence contract.

P43 records P42 evidence from a non-production Mac build experiment. It does
not commit the lockfile, node_modules, generated bundle, browser crypto, send,
intake, or relay publishing.
"""

import json
from pathlib import Path

DOC = Path("docs/ops/NIP59_CONTROLLED_BUILD_EVIDENCE.md")
EVIDENCE = Path("frontend/nip59/controlled-build-evidence.json")
SKELETON = Path("frontend/nip59/dependency-skeleton.json")
ROOT_PACKAGE = Path("package.json")
BUNDLE = Path("app/static/js/nip59_client_bundle.js")


def test_evidence_records_mac_experiment_without_production_install():
    payload = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    assert payload["status"] == "evidence-recorded"
    assert payload["experimentHost"] == "hodls-MacBook.local"
    assert payload["candidatePackage"] == "nostr-tools"
    assert payload["candidateVersion"] == "2.23.5"
    assert payload["lockfileGeneratedOutsideProduction"] is True
    assert payload["nodeModulesGeneratedOutsideProduction"] is True
    assert payload["productionPollutionObserved"] is False
    assert payload["productionInstallAllowed"] is False
    assert payload["productionNpmRequired"] is False
    assert payload["rootPackageMutationAllowed"] is False


def test_evidence_records_safe_import_and_local_probe():
    payload = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    safe = payload["safeImportCheck"]
    assert safe["importPath"] == "nostr-tools"
    assert safe["finalizeEvent"] is True
    assert safe["verifyEvent"] is True
    assert safe["generateSecretKey"] is True
    assert safe["getPublicKey"] is True
    assert safe["nip44"] is True

    probe = payload["localProbe"]
    assert probe["status"] == "local-probe-only"
    assert probe["cryptoReadyCandidate"] is True
    assert probe["networkPost"] is False
    assert probe["relayPublishing"] is False
    assert probe["eventVerified"] is True
    assert probe["plaintextPost"] is False


def test_evidence_records_wasm_risk_without_approval():
    payload = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    risk = payload["wasmRiskObserved"]
    assert risk["nostrWasmDependencyPresent"] is True
    assert risk["nostrToolsExportsWasmPath"] is True
    assert risk["nostrWasmContainsWebAssemblyReferences"] is True
    assert "Do not import @nostr/tools/wasm" in risk["decision"]

    assert "nostr-wasm@0.1.0" in payload["dependencyTreeObserved"]
    assert "package-lock.json" in payload["notCommittedFromExperiment"]
    assert "node_modules" in payload["notCommittedFromExperiment"]
    assert "generated browser bundle" in payload["notCommittedFromExperiment"]


def test_doc_explains_boundary_and_next_step():
    text = DOC.read_text(encoding="utf-8")

    assert "executed outside production on the MacBook" in text
    assert "eventVerified=true" in text
    assert "networkPost=false" in text
    assert "nostr-wasm@0.1.0" in text
    assert "must not import `@nostr/tools/wasm` or `nostr-wasm`" in text
    assert "Prepare a minimal reviewed NIP-59 source module" in text


def test_skeleton_tracks_evidence_without_enabling_crypto_or_send():
    payload = json.loads(SKELETON.read_text(encoding="utf-8"))

    assert payload["controlledBuildEvidence"] == "frontend/nip59/controlled-build-evidence.json"
    assert payload["controlledBuildEvidenceDoc"] == "docs/ops/NIP59_CONTROLLED_BUILD_EVIDENCE.md"
    assert payload["controlledBuildExperimentCompletedOutsideProduction"] is True
    assert payload["normalNostrToolsImportSurfaceObserved"] is True
    assert payload["nostrWasmRiskObserved"] is True
    assert payload["candidateApprovedForCrypto"] is False
    assert payload["exactVersionSelected"] is False
    assert payload["productionInstallAllowed"] is False
    assert payload["realCryptoImplemented"] is False
    assert payload["sendEnabled"] is False
    assert payload["nextAllowedPhase"] in {
        "minimal-source-module-no-send",
        "generated-bundle-experiment-no-send",
    }


def test_root_package_and_bundle_remain_safe():
    root = json.loads(ROOT_PACKAGE.read_text(encoding="utf-8"))
    bundle = BUNDLE.read_text(encoding="utf-8")

    assert root["dependencies"] == {}
    assert root["devDependencies"] == {}
    assert not Path("package-lock.json").exists()
    assert not Path("frontend/nip59/package-lock.json").exists()
    assert not Path("node_modules").exists()
    assert 'status: "skeleton"' in bundle
    assert "cryptoReady: false" in bundle
    assert "canFinalizeGiftWrap: false" in bundle
    assert "canPostEnvelope: false" in bundle
