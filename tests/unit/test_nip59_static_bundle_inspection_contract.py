"""NIP-59 static bundle inspection contract.

P37 verifies the committed static bundle remains skeleton-only and contains no
wasm, private-key, send, or network-post behavior.
"""

import json
from pathlib import Path

import scripts.verify_nip59_static_bundle as bundle_check

DOC = Path("docs/ops/NIP59_STATIC_BUNDLE_INSPECTION.md")
SKELETON = Path("frontend/nip59/dependency-skeleton.json")
ROOT_PACKAGE = Path("package.json")
BUNDLE = Path("app/static/js/nip59_client_bundle.js")
SCRIPT = Path("scripts/verify_nip59_static_bundle.py")


def test_static_bundle_inspection_script_exists_and_passes():
    assert SCRIPT.exists()
    assert bundle_check.main() == 0


def test_static_bundle_contains_required_skeleton_terms():
    text = BUNDLE.read_text(encoding="utf-8")

    for term in bundle_check.REQUIRED_TERMS:
        assert term in text


def test_static_bundle_contains_no_forbidden_terms():
    text = BUNDLE.read_text(encoding="utf-8")

    for term in bundle_check.FORBIDDEN_TERMS:
        assert term not in text


def test_static_bundle_inspector_detects_bad_bundle(tmp_path):
    bad = tmp_path / "bad_bundle.js"
    bad.write_text(
        'const x = "skeleton";\n' 'fetch("/api/messages/nip17/envelopes");\n' "const runtime = WebAssembly;\n",
        encoding="utf-8",
    )

    violations = bundle_check.inspect_bundle(bad)
    assert violations
    assert any("fetch(" in violation for violation in violations)
    assert any("WebAssembly" in violation for violation in violations)


def test_doc_explains_static_bundle_inspection_scope():
    text = DOC.read_text(encoding="utf-8")

    assert "does not build the bundle" in text
    assert 'status: "skeleton"' in text
    assert "`WebAssembly`" in text
    assert "`fetch(`" in text
    assert "enable send" in text


def test_skeleton_tracks_static_bundle_inspection_without_approval():
    payload = json.loads(SKELETON.read_text(encoding="utf-8"))

    assert payload["staticBundleInspection"] == "scripts/verify_nip59_static_bundle.py"
    assert payload["staticBundleInspectionRequiredBeforeCrypto"] is True
    assert payload["staticBundlePath"] == "app/static/js/nip59_client_bundle.js"
    assert payload["staticBundleStatus"] == "skeleton-inspected"
    assert payload["candidateApprovedForCrypto"] is False
    assert payload["exactVersionSelected"] is False
    assert payload["realCryptoImplemented"] is False
    assert payload["sendEnabled"] is False


def test_root_package_remains_zero_dependency():
    root = json.loads(ROOT_PACKAGE.read_text(encoding="utf-8"))

    assert root["dependencies"] == {}
    assert root["devDependencies"] == {}
    assert not Path("package-lock.json").exists()
    assert not Path("frontend/nip59/package-lock.json").exists()
