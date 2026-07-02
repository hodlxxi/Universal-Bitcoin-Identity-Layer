from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote

import pytest

from app.blueprints.qr_pointer import is_allowed_qr_target

REGISTRY_PATH = Path("app/blueprints/qr_pointers.json")
ALLOWED_STATUSES = {"active", "revoked", "expired"}
SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SENSITIVE_MARKERS = {
    "private_key",
    "privkey",
    "seed phrase",
    "mnemonic",
    "macaroon",
    "rpc_password",
    "database_password",
    "session_id",
    "cookie",
    "raw credentials",
    "env values",
}
DISALLOWED_TARGETS = {
    "https://example.com/agent/discovery": "external URLs",
    "//example.com/agent/discovery": "protocol-relative URLs",
    "/agent/discovery?scan=1": "query strings",
    "/agent/discovery#fragment": "fragments",
    "/agent/../admin": "traversal paths",
    "/admin": "arbitrary local paths",
    "/agent/jobs/demo-job-001": "job mutation paths",
    "/agent/delegations": "delegation paths",
    "/agent/policy": "policy paths",
    "/agent/request": "request paths",
}


def _registry_text() -> str:
    return REGISTRY_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def registry() -> dict[str, object]:
    assert REGISTRY_PATH.exists()
    decoded = json.loads(_registry_text())
    assert isinstance(decoded, dict)
    return decoded


def test_qr_pointer_registry_exists_and_parses_as_json(registry):
    assert registry


@pytest.mark.parametrize("token", ["", "a/b", r"a\\b", "a%2fb", "a%5cb", "..", "a..b", "a b", "a:b", "a" * 129])
def test_token_contract_rejects_unsafe_examples(token):
    decoded = unquote(token).lower()

    assert not (
        SAFE_TOKEN_RE.fullmatch(token)
        and "/" not in token
        and r"\\" not in token
        and "/" not in decoded
        and r"\\" not in decoded
        and ".." not in token
    )


def test_every_pointer_token_is_a_safe_url_path_token(registry):
    for token, pointer in registry.items():
        decoded = unquote(token).lower()

        assert isinstance(token, str)
        assert token
        assert len(token) <= 128
        assert "/" not in token
        assert r"\\" not in token
        assert "/" not in decoded
        assert r"\\" not in decoded
        assert ".." not in token
        assert SAFE_TOKEN_RE.fullmatch(token)
        assert isinstance(pointer, dict)
        assert pointer.get("token") == token


def test_every_pointer_status_is_allowed(registry):
    for pointer in registry.values():
        assert pointer["status"] in ALLOWED_STATUSES


def test_active_pointers_have_allowed_local_targets(registry):
    for pointer in registry.values():
        if pointer["status"] == "active":
            assert is_allowed_qr_target(pointer["target"])


@pytest.mark.parametrize("target, target_class", DISALLOWED_TARGETS.items())
def test_registry_target_contract_rejects_disallowed_target_classes(target, target_class):
    assert not is_allowed_qr_target(target), target_class


def test_revoked_and_expired_pointers_fail_closed_even_with_allowed_targets(client, registry):
    for token, pointer in registry.items():
        if pointer["status"] in {"revoked", "expired"}:
            assert is_allowed_qr_target(pointer["target"])
            response = client.get(f"/qr/{token}")
            assert response.status_code == 410
            assert pointer["target"] not in response.get_data(as_text=True)


def test_registry_file_contains_no_sensitive_material_markers():
    lowered = _registry_text().lower()

    for marker in SENSITIVE_MARKERS:
        assert marker not in lowered


def test_capabilities_do_not_advertise_qr_pointer_surfaces(client):
    response = client.get("/agent/capabilities")
    assert response.status_code == 200
    serialized = json.dumps(response.get_json(), sort_keys=True).lower()

    assert "/qr/" not in serialized
    assert "/operator/qr" not in serialized


@pytest.mark.parametrize(
    ("path", "expected_status"),
    [
        ("/qr/demo-active", 200),
        ("/qr/verify-demo", 200),
        ("/qr/demo-revoked", 410),
        ("/qr/demo-expired", 410),
        ("/qr/unknown", 404),
        ("/qr/../agent/discovery", 404),
        ("/qr/a%2Fb", 404),
    ],
)
def test_existing_qr_pointer_route_behavior_remains_unchanged(client, path, expected_status):
    assert client.get(path).status_code == expected_status
