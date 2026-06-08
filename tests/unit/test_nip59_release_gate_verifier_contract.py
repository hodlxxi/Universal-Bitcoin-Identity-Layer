"""NIP-59 release gate verifier contract.

P38 adds one release-gate entrypoint for current NIP-59 safety verifiers.
It does not install dependencies, build a bundle, enable crypto, or enable send.
"""

import json
from pathlib import Path

import scripts.verify_nip59_release_gate as release_gate

DOC = Path("docs/ops/NIP59_RELEASE_GATE_VERIFIER.md")
SCRIPT = Path("scripts/verify_nip59_release_gate.py")
SKELETON = Path("frontend/nip59/dependency-skeleton.json")
ROOT_PACKAGE = Path("package.json")
BUNDLE = Path("app/static/js/nip59_client_bundle.js")


def assert_live_bundle_is_safe_no_send(text: str) -> None:
    assert 'status: "skeleton"' in text or 'status: "generated-experiment-no-send"' in text
    assert "fetch(" not in text
    assert "/api/messages/nip17/envelopes" not in text
    assert "WebAssembly" not in text
    assert "nostr-wasm" not in text


def test_release_gate_script_exists_and_lists_expected_checks():
    assert SCRIPT.exists()

    assert release_gate.CHECKS == [
        "scripts/verify_nip59_builder_safety.py",
        "scripts/verify_nip59_import_policy.py",
        "scripts/verify_nip59_static_bundle.py",
        "scripts/verify_nip59_generated_bundle.py",
    ]


def test_release_gate_passes_current_repo():
    assert release_gate.main() == 0


def test_doc_explains_release_gate_scope():
    text = DOC.read_text(encoding="utf-8")

    assert "runs all current NIP-59 safety checks through one command" in text
    assert "verify_nip59_builder_safety.py" in text
    assert "verify_nip59_import_policy.py" in text
    assert "verify_nip59_static_bundle.py" in text
    assert "install npm" in text
    assert "build a bundle" in text


def test_skeleton_tracks_release_gate_without_approval():
    payload = json.loads(SKELETON.read_text(encoding="utf-8"))

    assert payload["nip59ReleaseGate"] == "scripts/verify_nip59_release_gate.py"
    assert payload["nip59ReleaseGateRequiredBeforeCrypto"] is True
    assert payload["candidateApprovedForCrypto"] is False
    assert payload["exactVersionSelected"] is False
    assert payload["realCryptoImplemented"] is False
    assert payload["sendEnabled"] is False
    assert payload["postEnabled"] is False
    assert payload["relayPublishing"] is False


def test_root_package_and_bundle_remain_safe():
    root = json.loads(ROOT_PACKAGE.read_text(encoding="utf-8"))
    bundle = BUNDLE.read_text(encoding="utf-8")

    assert root["dependencies"] == {}
    assert root["devDependencies"] == {}
    assert not Path("package-lock.json").exists()
    assert not Path("frontend/nip59/package-lock.json").exists()
    assert_live_bundle_is_safe_no_send(bundle)
    assert "canFinalizeGiftWrap: false" in bundle
