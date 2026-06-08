"""NIP-59 builder package template contract.

P29 adds a builder-only package template without installing dependencies,
mutating the root production package, adding a lockfile, or enabling crypto.
"""

import json
from pathlib import Path

ROOT_PACKAGE = Path("package.json")
TEMPLATE = Path("frontend/nip59/package.builder.template.json")
SKELETON = Path("frontend/nip59/dependency-skeleton.json")
BUNDLE = Path("app/static/js/nip59_client_bundle.js")


def assert_live_bundle_is_safe_no_send(text: str) -> None:
    assert 'status: "skeleton"' in text or 'status: "generated-experiment-no-send"' in text
    assert "fetch(" not in text
    assert "/api/messages/nip17/envelopes" not in text
    assert "WebAssembly" not in text
    assert "nostr-wasm" not in text


def test_builder_package_template_exists_but_is_not_root_package():
    payload = json.loads(TEMPLATE.read_text(encoding="utf-8"))

    assert payload["name"] == "hodlxxi-nip59-client-builder"
    assert payload["private"] is True
    assert payload["type"] == "module"
    assert payload["dependencies"]["nostr-tools"] == "PIN_EXACT_VERSION_IN_BUILDER_PR"
    assert payload["devDependencies"] == {}


def test_root_package_remains_zero_dependency():
    payload = json.loads(ROOT_PACKAGE.read_text(encoding="utf-8"))

    assert payload["dependencies"] == {}
    assert payload["devDependencies"] == {}
    assert "nostr-tools" not in json.dumps(payload)


def test_no_lockfile_is_added_in_p29():
    assert not Path("package-lock.json").exists()
    assert not Path("frontend/nip59/package-lock.json").exists()
    assert not Path("pnpm-lock.yaml").exists()
    assert not Path("yarn.lock").exists()


def test_dependency_skeleton_tracks_template_without_enabling_install_or_crypto():
    payload = json.loads(SKELETON.read_text(encoding="utf-8"))

    assert payload["builderPackageTemplate"] == "frontend/nip59/package.builder.template.json"
    assert payload["exactVersionSelected"] is False
    assert payload["productionNpmRequired"] is False
    assert payload["rootPackageMutationAllowed"] is False
    assert payload["productionInstallAllowed"] is False
    assert payload["realCryptoImplemented"] is False
    assert payload["sendEnabled"] is False
    assert payload["postEnabled"] is False
    assert payload["relayPublishing"] is False


def test_static_bundle_still_skeleton_only():
    text = BUNDLE.read_text(encoding="utf-8")

    assert_live_bundle_is_safe_no_send(text)
    assert "canFinalizeGiftWrap: false" in text
    # P47 live bundle may include reviewed narrow-import nostr-tools code.
    # P47 live generated no-send bundle may include local finalizeEvent probe code.
    assert "fetch(" not in text
