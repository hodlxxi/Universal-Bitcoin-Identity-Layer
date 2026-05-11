import importlib
import py_compile
from pathlib import Path

import pytest
import requests

import hodlxxi_sdk
from hodlxxi_sdk import AgentReceipt, HODLXXIClient, ReceiptError, SigningError


class FakeResponse:
    def __init__(self, status_code=200, data=None, text=""):
        self.status_code = status_code
        self._data = data if data is not None else {}
        self.text = text

    def json(self):
        return self._data


def test_package_imports_cleanly():
    module = importlib.import_module("hodlxxi_sdk")
    assert module.__name__ == "hodlxxi_sdk"


def test_public_exports_are_stable():
    expected = {
        "AgentReceipt",
        "Challenge",
        "HODLXXIClient",
        "HODLXXIError",
        "HODLXXIHTTPError",
        "ReceiptError",
        "SigningError",
        "canonical_json",
        "sha256_hex",
        "sign_challenge",
    }
    assert set(hodlxxi_sdk.__all__) == expected
    for name in expected:
        assert hasattr(hodlxxi_sdk, name)


@pytest.mark.parametrize(
    ("method_name", "expected_path"),
    [
        ("oidc_configuration", "/.well-known/openid-configuration"),
        ("agent_manifest", "/.well-known/agent.json"),
        ("capabilities", "/agent/capabilities"),
        ("reputation", "/agent/reputation"),
        ("chain_health", "/agent/chain/health"),
        ("public_status", "/api/public/status"),
    ],
)
def test_client_public_methods_build_expected_urls_without_secrets(monkeypatch, method_name, expected_path):
    calls = []

    def fake_request(method, url, json=None, timeout=None):
        calls.append((method, url, json, timeout))
        return FakeResponse(data={"ok": True})

    monkeypatch.setattr(requests, "request", fake_request)

    client = HODLXXIClient("https://hodlxxi.com")
    result = getattr(client, method_name)()

    assert result == {"ok": True}
    assert calls == [("GET", f"https://hodlxxi.com{expected_path}", None, 20.0)]


def test_create_challenge_verify_challenge_and_get_job_use_expected_endpoints(monkeypatch):
    calls = []

    def fake_request(method, url, json=None, timeout=None):
        calls.append((method, url, json, timeout))
        return FakeResponse(data={"ok": True, "job_id": "job-1"})

    monkeypatch.setattr(requests, "request", fake_request)

    client = HODLXXIClient("https://hodlxxi.com")
    client.create_challenge("02" + "a" * 64)
    client.verify_challenge("challenge-1", signature="sig")
    client.get_job("job-1")

    assert calls[0][1] == "https://hodlxxi.com/api/challenge"
    assert calls[1][1] == "https://hodlxxi.com/api/verify"
    assert calls[2][1] == "https://hodlxxi.com/agent/jobs/job-1"


def test_receipt_helpers_reject_malformed_payloads():
    with pytest.raises(ReceiptError):
        AgentReceipt.from_response(None)

    with pytest.raises(ReceiptError):
        AgentReceipt.from_response({"receipt": "not-a-mapping", "status": "done"})

    with pytest.raises(ReceiptError):
        AgentReceipt.from_response({"receipt": {"status": "done"}})

    with pytest.raises(ReceiptError):
        AgentReceipt.from_response({"receipt": {"job_id": "job-1"}})


def test_signing_helpers_do_not_capture_secret_material_in_results():
    secret_seed = "abandon abandon abandon"
    macaroon = "0201036c6e6402..."
    token = "tok_live_123"

    def signer(_msg: bytes) -> str:
        return "signature-from-wallet"

    signed = hodlxxi_sdk.sign_challenge(hodlxxi_sdk.Challenge("challenge-abc"), signer)
    serialized = str(signed)

    assert "signature" in signed
    assert secret_seed not in serialized
    assert macaroon not in serialized
    assert token not in serialized

    with pytest.raises(SigningError):
        hodlxxi_sdk.Challenge("").message()


def test_docs_sdk_claimed_exports_match_package_exports():
    readme = Path("docs/sdk/README.md").read_text(encoding="utf-8")

    assert "from hodlxxi_sdk import HODLXXIClient" in readme
    assert "from hodlxxi_sdk import AgentReceipt" in readme
    assert "from hodlxxi_sdk import Challenge, sign_challenge" in readme


def test_python_examples_compile_and_reference_real_sdk_functions():
    examples = [
        Path("examples/python/ping_agent.py"),
        Path("examples/python/auth_challenge_flow.py"),
        Path("examples/python/nostr_auth_challenge_flow.py"),
    ]

    for path in examples:
        py_compile.compile(str(path), doraise=True)

    ping_source = examples[0].read_text(encoding="utf-8")
    auth_source = examples[1].read_text(encoding="utf-8")
    nostr_source = examples[2].read_text(encoding="utf-8")

    assert "HODLXXIClient" in ping_source
    assert "create_job(" in ping_source
    assert "create_challenge(" in auth_source
    assert "verify_challenge(" in auth_source
    assert "create_challenge(" in nostr_source
    assert "verify_challenge(" in nostr_source
