import builtins
import json
import socket
from pathlib import Path

import pytest

from scripts import export_qr_pointer

VALID_RECORD = {"token": "Pointer_123", "target": "/agent/verify/job-123"}


def write_record(tmp_path: Path, record=None) -> Path:
    path = tmp_path / "pointer.json"
    path.write_text(json.dumps(record or VALID_RECORD), encoding="utf-8")
    return path


def run_cli(capsys, *args):
    code = export_qr_pointer.main(list(args))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_valid_record_and_base_url_generates_expected_payload_url(tmp_path, capsys):
    record_path = write_record(tmp_path)
    code, out, err = run_cli(capsys, "--dry-run", "--record", str(record_path), "--base-url", "https://example.com")
    assert code == 0, err
    assert "payload_url: https://example.com/qr/Pointer_123" in out
    assert "target_path: /agent/verify/job-123" in out
    assert "status: dry-run" in out


def test_trailing_slash_base_url_normalizes_correctly(tmp_path, capsys):
    record_path = write_record(tmp_path)
    code, out, err = run_cli(capsys, "--dry-run", "--record", str(record_path), "--base-url", "https://example.com/")
    assert code == 0, err
    assert "payload_url: https://example.com/qr/Pointer_123" in out


@pytest.mark.parametrize(
    "base_url,expected",
    [
        ("https://example.com?debug=1", "query string"),
        ("https://example.com#frag", "fragment"),
        ("file:///tmp/example", "http or https"),
    ],
)
def test_invalid_base_url_rejected(tmp_path, capsys, base_url, expected):
    record_path = write_record(tmp_path)
    code, _out, err = run_cli(capsys, "--dry-run", "--record", str(record_path), "--base-url", base_url)
    assert code == 2
    assert expected in err


def test_missing_token_rejected(tmp_path, capsys):
    record_path = write_record(tmp_path, {"target": "/agent/verify/job-123"})
    code, _out, err = run_cli(capsys, "--dry-run", "--record", str(record_path), "--base-url", "https://example.com")
    assert code == 2
    assert "token is required" in err


@pytest.mark.parametrize("token", ["short", "bad token", "bad/token", "x" * 129])
def test_short_or_invalid_token_rejected(tmp_path, capsys, token):
    record_path = write_record(tmp_path, {"token": token, "target": "/agent/verify/job-123"})
    code, _out, err = run_cli(capsys, "--dry-run", "--record", str(record_path), "--base-url", "https://example.com")
    assert code == 2
    assert "[A-Za-z0-9_-]{8,128}" in err


@pytest.mark.parametrize("target", ["https://evil.example/path", "http://evil.example/path"])
def test_external_target_rejected(tmp_path, capsys, target):
    record_path = write_record(tmp_path, {"token": "Pointer_123", "target": target})
    code, _out, err = run_cli(capsys, "--dry-run", "--record", str(record_path), "--base-url", "https://example.com")
    assert code == 2
    assert "external URL" in err


def test_protocol_relative_target_rejected(tmp_path, capsys):
    record_path = write_record(tmp_path, {"token": "Pointer_123", "target": "//evil.example/path"})
    code, _out, err = run_cli(capsys, "--dry-run", "--record", str(record_path), "--base-url", "https://example.com")
    assert code == 2
    assert "external URL" in err or "protocol-relative" in err


@pytest.mark.parametrize(
    "target",
    [
        "/.well-known/agent.json",
        "/.well-known/hodlxxi-operator.json",
        "/agent/discovery",
        "/agent/capabilities",
    ],
)
def test_exact_allowed_discovery_targets_pass(tmp_path, capsys, target):
    record_path = write_record(tmp_path, {"token": "Pointer_123", "target": target})
    code, out, err = run_cli(capsys, "--dry-run", "--record", str(record_path), "--base-url", "https://example.com")
    assert code == 0, err
    assert f"target_path: {target}" in out


@pytest.mark.parametrize(
    "job_id",
    [
        "job123",
        "job_123",
        "job-123",
        "job.123",
        "job:123",
        "a",
    ],
)
def test_valid_agent_verify_job_id_targets_pass(tmp_path, capsys, job_id):
    target = f"/agent/verify/{job_id}"
    record_path = write_record(tmp_path, {"token": "Pointer_123", "target": target})
    code, out, err = run_cli(capsys, "--dry-run", "--record", str(record_path), "--base-url", "https://example.com")
    assert code == 0, err
    assert f"target_path: {target}" in out


@pytest.mark.parametrize(
    "target",
    [
        "/agent/request",
        "/agent/request/x",
        "/agent/jobs/job_123",
        "/agent/delegations",
        "/agent/delegations/abc",
        "/agent/policy",
        "/.well-known/agent-delegation.json",
        "/admin",
        "/admin/x",
        "/some/unknown/local/path",
        "/agent/verify",
        "/agent/verify/",
        "/agent/verify/a/b",
        "/agent/verify/job?id=1",
        "/agent/verify/job#fragment",
        "/agent/verify/../x",
    ],
)
def test_non_allowlisted_local_targets_rejected(tmp_path, capsys, target):
    record_path = write_record(tmp_path, {"token": "Pointer_123", "target": target})
    code, _out, err = run_cli(capsys, "--dry-run", "--record", str(record_path), "--base-url", "https://example.com")
    assert code == 2
    assert "target" in err


def test_secret_like_field_rejected(tmp_path, capsys):
    record_path = write_record(
        tmp_path, {"token": "Pointer_123", "target": "/agent/verify/job-123", "metadata": {"private_key": "redacted"}}
    )
    code, _out, err = run_cli(capsys, "--dry-run", "--record", str(record_path), "--base-url", "https://example.com")
    assert code == 2
    assert "secret-like field" in err
    assert "redacted" not in err


def test_authority_claim_field_rejected(tmp_path, capsys):
    record_path = write_record(
        tmp_path, {"token": "Pointer_123", "target": "/agent/verify/job-123", "metadata": {"delegation": False}}
    )
    code, _out, err = run_cli(capsys, "--dry-run", "--record", str(record_path), "--base-url", "https://example.com")
    assert code == 2
    assert "authority-claim field" in err


def test_dry_run_does_not_write_output_file(tmp_path, capsys):
    record_path = write_record(tmp_path)
    output = tmp_path / "pointer.png"
    code, out, err = run_cli(
        capsys, "--dry-run", "--record", str(record_path), "--base-url", "https://example.com", "--output", str(output)
    )
    assert code == 0, err
    assert "not written (dry-run)" in out
    assert not output.exists()


def test_output_path_is_not_written_if_validation_fails(tmp_path, capsys):
    record_path = write_record(tmp_path, {"token": "bad token", "target": "/agent/verify/job-123"})
    output = tmp_path / "pointer.png"
    code, _out, _err = run_cli(
        capsys, "--record", str(record_path), "--base-url", "https://example.com", "--output", str(output)
    )
    assert code == 2
    assert not output.exists()


def test_stdout_warning_contains_discovery_only_non_claims(tmp_path, capsys):
    record_path = write_record(tmp_path)
    code, out, err = run_cli(capsys, "--dry-run", "--record", str(record_path), "--base-url", "https://example.com")
    assert code == 0, err
    assert "discovery-only" in out
    for claim in [
        "identity",
        "consent",
        "approval",
        "delegation",
        "authorization",
        "payment",
        "trust",
        "human presence",
    ]:
        assert claim in out


def test_no_network_calls_are_required(tmp_path, capsys, monkeypatch):
    def blocked(*_args, **_kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", blocked)
    record_path = write_record(tmp_path)
    code, out, err = run_cli(capsys, "--dry-run", "--record", str(record_path), "--base-url", "https://example.com")
    assert code == 0, err
    assert "https://example.com/qr/Pointer_123" in out


def test_qr_image_dependency_unavailable_fails_clearly_and_safely(tmp_path, capsys, monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "qrcode":
            raise ImportError("missing qrcode")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    record_path = write_record(tmp_path)
    output = tmp_path / "pointer.png"
    code, _out, err = run_cli(
        capsys, "--record", str(record_path), "--base-url", "https://example.com", "--output", str(output)
    )
    assert code == 2
    assert "requires the optional 'qrcode' dependency" in err
    assert not output.exists()


def test_registry_dir_token_loads_matching_record(tmp_path, capsys):
    registry = tmp_path / "registry"
    registry.mkdir()
    (registry / "Pointer_123.json").write_text(json.dumps(VALID_RECORD), encoding="utf-8")
    code, out, err = run_cli(
        capsys,
        "--dry-run",
        "--registry-dir",
        str(registry),
        "--token",
        "Pointer_123",
        "--base-url",
        "https://example.com",
    )
    assert code == 0, err
    assert "payload_url: https://example.com/qr/Pointer_123" in out
