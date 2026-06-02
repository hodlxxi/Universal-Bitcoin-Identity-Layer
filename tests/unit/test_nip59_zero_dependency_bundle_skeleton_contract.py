"""NIP-59 zero-dependency bundle skeleton contract.

P24 creates a frontend package/bundle shape without introducing real crypto,
delivery, npm installation, or production intake.
"""

import json
from pathlib import Path

PACKAGE = Path("package.json")
BUILDER = Path("scripts/build_nip59_client_bundle.mjs")
BUNDLE = Path("app/static/js/nip59_client_bundle.js")
BROWSER = Path("app/browser_routes.py")


def test_package_json_exists_without_dependencies_or_install_requirement():
    payload = json.loads(PACKAGE.read_text(encoding="utf-8"))

    assert payload["private"] is True
    assert payload["type"] == "module"
    assert payload["scripts"]["build:nip59-client"] == "node scripts/build_nip59_client_bundle.mjs"
    assert payload["dependencies"] == {}
    assert payload["devDependencies"] == {}


def test_bundle_builder_is_zero_dependency_and_writes_local_static_asset():
    text = BUILDER.read_text(encoding="utf-8")

    assert 'import { mkdirSync, writeFileSync } from "node:fs";' in text
    assert 'const out = "app/static/js/nip59_client_bundle.js";' in text
    assert "nostr-tools" not in text
    assert "finalizeEvent" not in text
    assert "getEventHash" not in text
    assert "fetch(" not in text


def test_generated_bundle_is_explicitly_non_crypto_and_non_delivery():
    text = BUNDLE.read_text(encoding="utf-8")

    assert 'status: "skeleton"' in text
    assert "cryptoReady: false" in text
    assert "canFinalizeGiftWrap: false" in text
    assert "canPostEnvelope: false" in text
    assert "relayPublishing: false" in text
    assert "plaintextPost: false" in text
    assert "dependencies: []" in text
    assert "privateKey" not in text
    assert "private_key" not in text
    assert "secretKey" not in text
    assert "fetch(" not in text
    assert "XMLHttpRequest" not in text


def test_bundle_is_not_wired_into_runtime_ui_yet():
    text = BROWSER.read_text(encoding="utf-8")

    assert "nip59_client_bundle.js" not in text
    assert "HODLXXI_NIP59_CLIENT" not in text


def test_no_lockfile_or_real_frontend_dependency_is_added_yet():
    assert not Path("package-lock.json").exists()
    assert not Path("pnpm-lock.yaml").exists()
    assert not Path("yarn.lock").exists()
