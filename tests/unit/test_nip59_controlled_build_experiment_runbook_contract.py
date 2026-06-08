"""NIP-59 controlled build experiment runbook contract.

P41 documents the next non-production build experiment. It does not run npm,
generate a lockfile, build a bundle, approve crypto, or enable send.
"""

import json
from pathlib import Path

DOC = Path("docs/ops/NIP59_CONTROLLED_BUILD_EXPERIMENT_RUNBOOK.md")
PLAN = Path("frontend/nip59/controlled-build-experiment-plan.json")
SKELETON = Path("frontend/nip59/dependency-skeleton.json")
ROOT_PACKAGE = Path("package.json")
BUNDLE = Path("app/static/js/nip59_client_bundle.js")


def test_plan_is_plan_only_and_forbids_production_execution():
    payload = json.loads(PLAN.read_text(encoding="utf-8"))

    assert payload["status"] == "plan-only"
    assert payload["phase"] == "controlled-build-experiment-outside-production"
    assert payload["productionExecutionAllowed"] is False
    assert payload["productionInstallAllowed"] is False
    assert payload["productionNpmRequired"] is False
    assert payload["rootPackageMutationAllowed"] is False
    assert payload["candidateApprovedForCrypto"] is False
    assert payload["exactVersionSelected"] is False
    assert payload["lockfileGenerated"] is False
    assert payload["bundleGenerated"] is False
    assert payload["cryptoImplemented"] is False
    assert payload["sendEnabled"] is False
    assert payload["postEnabled"] is False
    assert payload["relayPublishing"] is False


def test_plan_allows_only_non_production_hosts():
    payload = json.loads(PLAN.read_text(encoding="utf-8"))

    assert "MacBook or other non-production builder host" in payload["allowedHosts"]
    assert "temporary non-production build workspace" in payload["allowedHosts"]
    assert "production /srv/ubid" in payload["forbiddenHosts"]
    assert "staging /srv/ubid-staging" in payload["forbiddenHosts"]


def test_plan_lists_evidence_and_forbidden_artifacts():
    payload = json.loads(PLAN.read_text(encoding="utf-8"))

    assert "package-lock.json generated outside production" in payload["allowedArtifactsToCapture"]
    assert "generated bundle inspection output" in payload["allowedArtifactsToCapture"]
    assert "package-lock.json" in payload["forbiddenArtifactsToCommitInThisPhase"]
    assert "node_modules" in payload["forbiddenArtifactsToCommitInThisPhase"]
    assert "generated browser bundle" in payload["forbiddenArtifactsToCommitInThisPhase"]
    assert "send-enabled client code" in payload["forbiddenArtifactsToCommitInThisPhase"]


def test_plan_requires_pollution_checks_and_release_gates():
    payload = json.loads(PLAN.read_text(encoding="utf-8"))

    assert "no node_modules under repository" in payload["requiredPollutionChecks"]
    assert "no package-lock.json under repository" in payload["requiredPollutionChecks"]
    assert "root package.json remains zero-dependency" in payload["requiredPollutionChecks"]
    assert "bash scripts/release_gate_smoke_check.sh" in payload["requiredCommandsBeforeCommit"]
    assert "python scripts/verify_nip59_release_gate.py" in payload["requiredCommandsBeforeCommit"]


def test_doc_explains_non_production_boundary():
    text = DOC.read_text(encoding="utf-8")

    assert "controlled build experiment outside production" in text
    assert "does not approve production npm" in text
    assert "Do not run this experiment inside:" in text
    assert "production `/srv/ubid`" in text
    assert "staging `/srv/ubid-staging`" in text
    assert "The actual build experiment must be executed later outside production" in text


def test_skeleton_tracks_plan_without_approval():
    payload = json.loads(SKELETON.read_text(encoding="utf-8"))

    assert payload["controlledBuildExperimentPlan"] == "frontend/nip59/controlled-build-experiment-plan.json"
    assert payload["controlledBuildExperimentRunbook"] == "docs/ops/NIP59_CONTROLLED_BUILD_EXPERIMENT_RUNBOOK.md"
    assert payload["nextAllowedPhase"] in {
        "controlled-build-experiment-outside-production",
        "minimal-source-module-no-send",
        "generated-bundle-experiment-no-send",
        "reviewed-generated-bundle-no-send",
    }
    assert payload["productionInstallAllowed"] is False
    assert payload["productionNpmRequired"] is False
    assert payload["rootPackageMutationAllowed"] is False
    assert payload["candidateApprovedForCrypto"] is False
    assert payload["exactVersionSelected"] is False
    assert payload["realCryptoImplemented"] is False
    assert payload["sendEnabled"] is False


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
