"""NIP-59 builder-safe dependency skeleton contract.

P27 introduces a real dependency plan without installing npm dependencies on
production, adding a lockfile, enabling crypto, or enabling send.
"""

import json
import subprocess
import sys
from pathlib import Path

DOC = Path("docs/ops/NIP59_BUILDER_SAFE_DEPENDENCY_SKELETON.md")
SKELETON = Path("frontend/nip59/dependency-skeleton.json")
PACKAGE = Path("package.json")
VERIFY = Path("scripts/verify_nip59_builder_safety.py")


def test_builder_safe_dependency_doc_forbids_production_npm_mutation():
    text = DOC.read_text(encoding="utf-8")

    assert "Do not install npm" in text
    assert "production runtime host" in text
    assert "`npm install`" in text
    assert "`npm update`" in text
    assert "ad-hoc bundle download from CDN" in text


def test_dependency_skeleton_names_candidate_without_enabling_crypto():
    payload = json.loads(SKELETON.read_text(encoding="utf-8"))

    assert payload["status"] == "builder-plan-only"
    assert payload["productionInstallAllowed"] is False
    assert payload["lockfileRequiredBeforeCrypto"] is True
    assert payload["realCryptoImplemented"] is False
    assert payload["sendEnabled"] is False
    assert payload["postEnabled"] is False
    assert payload["relayPublishing"] is False

    candidate_names = [item["name"] for item in payload["candidateDependencies"]]
    assert "nostr-tools" in candidate_names


def test_root_package_remains_zero_dependency_in_p27():
    payload = json.loads(PACKAGE.read_text(encoding="utf-8"))

    assert payload["dependencies"] == {}
    assert payload["devDependencies"] == {}
    assert not Path("package-lock.json").exists()
    assert not Path("pnpm-lock.yaml").exists()
    assert not Path("yarn.lock").exists()


def test_builder_safety_verifier_passes():
    result = subprocess.run(
        [sys.executable, str(VERIFY)],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0
    assert "ok: NIP-59 builder safety invariants hold" in result.stdout


def test_builder_skeleton_still_requires_send_disabled():
    text = DOC.read_text(encoding="utf-8")

    assert "`cryptoReady` remains false" in text
    assert "`canFinalizeGiftWrap` remains false" in text
    assert "`canPostEnvelope` remains false" in text
    assert "`Send sealed envelope` remains disabled" in text
    assert "production `NIP17_MESSAGES_ENABLED` remains absent or false" in text
