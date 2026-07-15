from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import production_truth_audit as audit

ROOT = Path(__file__).resolve().parents[2]


def result(returncode=0, stdout="", stderr=""):
    return audit.CommandResult(returncode=returncode, stdout=stdout, stderr=stderr)


def make_runner(mapping):
    def runner(command, cwd):
        return mapping.get(tuple(command), result(returncode=1, stderr="unexpected command"))

    return runner


def good_evidence(name, status="MATCH", *, mandatory=True):
    return audit.Evidence(name=name, status=status, summary=f"{name} {status.lower()}", mandatory=mandatory)


class FakeVerifierReport:
    def __init__(self, status):
        self.status = status

    def to_dict(self):
        return {"status": self.status}


def real_source_details():
    return audit.audit_source_contract(ROOT)[1]


def test_git_not_a_repository(tmp_path):
    runner = make_runner({("git", "rev-parse", "--show-toplevel"): result(returncode=128, stderr="fatal")})

    evidence = audit.audit_git(tmp_path, runner=runner)

    assert evidence.status == "BLOCKED"
    assert "Not a Git repository" in evidence.summary


def test_git_missing_origin(tmp_path):
    runner = make_runner(
        {
            ("git", "rev-parse", "--show-toplevel"): result(stdout=str(tmp_path)),
            ("git", "remote", "get-url", "origin"): result(returncode=2, stderr="missing"),
        }
    )

    evidence = audit.audit_git(tmp_path, runner=runner)

    assert evidence.status == "BLOCKED"
    assert "missing" in evidence.details["origin"]["stderr"]


def test_git_fetch_failure(tmp_path):
    runner = make_runner(
        {
            ("git", "rev-parse", "--show-toplevel"): result(stdout=str(tmp_path)),
            ("git", "remote", "get-url", "origin"): result(stdout="https://example.com/repo.git"),
            ("git", "fetch", "--prune", "origin", "main"): result(returncode=1, stderr="network"),
            ("git", "rev-parse", "HEAD"): result(stdout="aaa\n"),
            ("git", "rev-parse", "origin/main"): result(returncode=1, stderr="unknown revision"),
            ("git", "status", "--short"): result(stdout=""),
        }
    )

    evidence = audit.audit_git(tmp_path, runner=runner)

    assert evidence.status == "BLOCKED"
    assert evidence.summary == "Git fetch failed."


def test_git_missing_origin_main(tmp_path):
    runner = make_runner(
        {
            ("git", "rev-parse", "--show-toplevel"): result(stdout=str(tmp_path)),
            ("git", "remote", "get-url", "origin"): result(stdout="https://example.com/repo.git"),
            ("git", "fetch", "--prune", "origin", "main"): result(stdout="ok"),
            ("git", "rev-parse", "HEAD"): result(stdout="aaa\n"),
            ("git", "rev-parse", "origin/main"): result(returncode=1, stderr="unknown revision"),
            ("git", "status", "--short"): result(stdout=""),
        }
    )

    evidence = audit.audit_git(tmp_path, runner=runner)

    assert evidence.status == "BLOCKED"
    assert evidence.summary == "origin/main is missing."


def test_git_head_mismatch(tmp_path):
    runner = make_runner(
        {
            ("git", "rev-parse", "--show-toplevel"): result(stdout=str(tmp_path)),
            ("git", "remote", "get-url", "origin"): result(stdout="https://example.com/repo.git"),
            ("git", "fetch", "--prune", "origin", "main"): result(stdout="ok"),
            ("git", "rev-parse", "HEAD"): result(stdout="aaa\n"),
            ("git", "rev-parse", "origin/main"): result(stdout="bbb\n"),
            ("git", "status", "--short"): result(stdout=""),
        }
    )

    evidence = audit.audit_git(tmp_path, runner=runner)

    assert evidence.status == "MISMATCH"
    assert "does not match" in evidence.summary


def test_git_dirty_tree(tmp_path):
    runner = make_runner(
        {
            ("git", "rev-parse", "--show-toplevel"): result(stdout=str(tmp_path)),
            ("git", "remote", "get-url", "origin"): result(stdout="https://example.com/repo.git"),
            ("git", "fetch", "--prune", "origin", "main"): result(stdout="ok"),
            ("git", "rev-parse", "HEAD"): result(stdout="aaa\n"),
            ("git", "rev-parse", "origin/main"): result(stdout="aaa\n"),
            ("git", "status", "--short"): result(stdout=" M docs/file.md\n"),
        }
    )

    evidence = audit.audit_git(tmp_path, runner=runner)

    assert evidence.status == "RED"
    assert "dirty" in evidence.summary.lower()


def test_github_blocked(monkeypatch):
    runner = make_runner({("git", "rev-parse", "HEAD"): result(stdout="abc\n")})
    monkeypatch.setattr(audit, "gh_available", lambda *_: False)
    monkeypatch.setattr(
        audit, "fetch_github_check_runs_via_http", lambda *_, **__: (_ for _ in ()).throw(RuntimeError("boom"))
    )

    evidence = audit.audit_github_checks(
        ROOT,
        source_details=real_source_details(),
        runner=runner,
        skip_live=False,
        timeout=1.0,
    )

    assert evidence.status == "BLOCKED"


def test_github_pending(monkeypatch):
    runner = make_runner({("git", "rev-parse", "HEAD"): result(stdout="abc\n")})
    monkeypatch.setattr(audit, "gh_available", lambda *_: False)
    monkeypatch.setattr(
        audit,
        "fetch_github_check_runs_via_http",
        lambda *_, **__: [{"name": "pytest", "status": "queued", "conclusion": None}],
    )

    evidence = audit.audit_github_checks(
        ROOT,
        source_details=real_source_details(),
        runner=runner,
        skip_live=False,
        timeout=1.0,
    )

    assert evidence.status == "PENDING"


def test_github_red(monkeypatch):
    runner = make_runner({("git", "rev-parse", "HEAD"): result(stdout="abc\n")})
    monkeypatch.setattr(audit, "gh_available", lambda *_: False)
    monkeypatch.setattr(
        audit,
        "fetch_github_check_runs_via_http",
        lambda *_, **__: [{"name": "pytest", "status": "completed", "conclusion": "failure"}],
    )

    evidence = audit.audit_github_checks(
        ROOT,
        source_details=real_source_details(),
        runner=runner,
        skip_live=False,
        timeout=1.0,
    )

    assert evidence.status == "RED"


def test_github_unknown_when_no_runs(monkeypatch):
    runner = make_runner({("git", "rev-parse", "HEAD"): result(stdout="abc\n")})
    monkeypatch.setattr(audit, "gh_available", lambda *_: False)
    monkeypatch.setattr(audit, "fetch_github_check_runs_via_http", lambda *_, **__: [])

    evidence = audit.audit_github_checks(
        ROOT,
        source_details=real_source_details(),
        runner=runner,
        skip_live=False,
        timeout=1.0,
    )

    assert evidence.status == "UNKNOWN"


def test_discovery_blocked(monkeypatch):
    monkeypatch.setattr(
        audit,
        "fetch_public_json",
        lambda *_, **__: (_ for _ in ()).throw(audit.VerificationError("dns", "lookup failed")),
    )

    evidence = audit.audit_discovery(
        ROOT,
        source_details=real_source_details(),
        endpoint=audit.DEFAULT_ENDPOINT,
        timeout=1.0,
        skip_live=False,
    )

    assert evidence.status == "BLOCKED"


def test_discovery_mismatch(monkeypatch):
    source = real_source_details()
    results = [
        {
            "path": path,
            "json": (
                {
                    "name": source["server_json"]["title"],
                    "version": source["server_json"]["version"],
                    "protocolVersion": source["protocol_version"],
                    "tool_count": source["tool_count"],
                    "transport": {"type": source["transport"]},
                    "endpoint": f"https://hodlxxi.com{source['endpoint_path']}",
                }
                if path == "/.well-known/mcp.json"
                else {
                    "mcp": {
                        "server_card": source["server_card_path"],
                        "endpoint": source["endpoint_path"],
                        "server_version": source["server_json"]["version"],
                    }
                }
            ),
        }
        for path in audit.PUBLIC_HTTP_PATHS
    ]
    results[0]["json"]["version"] = "0.0.0"
    iterator = iter(results)
    monkeypatch.setattr(audit, "fetch_public_json", lambda *_, **__: next(iterator))

    evidence = audit.audit_discovery(
        ROOT,
        source_details=source,
        endpoint=audit.DEFAULT_ENDPOINT,
        timeout=1.0,
        skip_live=False,
    )

    assert evidence.status == "MISMATCH"


def test_registry_blocked(monkeypatch):
    monkeypatch.setattr(
        audit,
        "fetch_public_json",
        lambda *_, **__: (_ for _ in ()).throw(audit.VerificationError("tls", "bad cert")),
    )

    evidence = audit.audit_registry(source_details=real_source_details(), timeout=1.0, skip_live=False)

    assert evidence.status == "BLOCKED"


def test_registry_mismatch(monkeypatch):
    source = real_source_details()
    monkeypatch.setattr(
        audit,
        "fetch_public_json",
        lambda *_, **__: {"json": {"servers": [{"name": source["server_json"]["name"], "versions": []}]}},
    )

    evidence = audit.audit_registry(source_details=source, timeout=1.0, skip_live=False)

    assert evidence.status == "MISMATCH"


def test_mcp_blocked(monkeypatch):
    monkeypatch.setattr(audit, "verify_remote_mcp", lambda **_: FakeVerifierReport("BLOCKED"))

    evidence = audit.audit_mcp(ROOT, endpoint=audit.DEFAULT_ENDPOINT, timeout=1.0, skip_live=False)

    assert evidence.status == "BLOCKED"


def test_mcp_mismatch(monkeypatch):
    monkeypatch.setattr(audit, "verify_remote_mcp", lambda **_: FakeVerifierReport("MISMATCH"))

    evidence = audit.audit_mcp(ROOT, endpoint=audit.DEFAULT_ENDPOINT, timeout=1.0, skip_live=False)

    assert evidence.status == "MISMATCH"


def test_stale_reference_detection(tmp_path):
    (tmp_path / "README.md").write_text("This public transport is disabled.\n", encoding="utf-8")

    evidence = audit.audit_stale_references(tmp_path)

    assert evidence.status == "STALE"
    assert evidence.details["findings"][0]["path"] == "README.md"


def test_stale_exclusions_ignore_dated_and_excluded_content(tmp_path):
    (tmp_path / "docs.md").write_text(
        "Validated on 2026-07-12.\nThe public transport is disabled.\nHistorical note only.\n",
        encoding="utf-8",
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "third_party.md").write_text("disabled production stub\n", encoding="utf-8")

    evidence = audit.audit_stale_references(tmp_path)

    assert evidence.status == "MATCH"


def test_skip_live_returns_partial_nonzero(tmp_path, monkeypatch):
    monkeypatch.setattr(
        audit, "audit_source_contract", lambda root: (good_evidence("source_contract"), {"server_json": {}})
    )
    monkeypatch.setattr(audit, "audit_git", lambda *_, **__: good_evidence("git"))
    monkeypatch.setattr(audit, "audit_github_checks", lambda *_, **__: good_evidence("github_checks", "GREEN"))
    monkeypatch.setattr(audit, "audit_stale_references", lambda *_, **__: good_evidence("stale_references"))
    monkeypatch.setattr(audit, "audit_discovery", lambda *_, **__: good_evidence("discovery"))
    monkeypatch.setattr(audit, "audit_mcp", lambda *_, **__: good_evidence("mcp", "VERIFIED"))
    monkeypatch.setattr(audit, "audit_registry", lambda *_, **__: good_evidence("registry"))
    monkeypatch.setattr(audit, "audit_covenant", lambda *_, **__: good_evidence("covenant"))
    monkeypatch.setattr(audit, "default_output_dir", lambda *_: tmp_path / "report")

    report = audit.run_audit(repo_root=ROOT, skip_live=True)

    assert report.status == "PENDING"
    assert report.exit_code == 3
    assert report.partial is True


def test_missing_mandatory_category():
    status, partial = audit.combine_required({"git": good_evidence("git")}, ["git", "mcp"])

    assert status == "PENDING"
    assert partial is True


def test_complete_all_good_result(tmp_path, monkeypatch):
    monkeypatch.setattr(
        audit, "audit_source_contract", lambda root: (good_evidence("source_contract"), {"server_json": {}})
    )
    monkeypatch.setattr(audit, "audit_git", lambda *_, **__: good_evidence("git"))
    monkeypatch.setattr(audit, "audit_github_checks", lambda *_, **__: good_evidence("github_checks", "GREEN"))
    monkeypatch.setattr(audit, "audit_stale_references", lambda *_, **__: good_evidence("stale_references"))
    monkeypatch.setattr(audit, "audit_discovery", lambda *_, **__: good_evidence("discovery"))
    monkeypatch.setattr(audit, "audit_mcp", lambda *_, **__: good_evidence("mcp", "VERIFIED"))
    monkeypatch.setattr(audit, "audit_registry", lambda *_, **__: good_evidence("registry"))
    monkeypatch.setattr(audit, "audit_covenant", lambda *_, **__: good_evidence("covenant"))
    monkeypatch.setattr(audit, "default_output_dir", lambda *_: tmp_path / "report")

    report = audit.run_audit(repo_root=ROOT, skip_live=False)

    assert report.status == "VERIFIED"
    assert report.exit_code == 0
    assert (tmp_path / "report" / "summary.json").exists()
    assert (tmp_path / "report" / "REPORT.md").exists()


def test_precedence():
    assert (
        audit.combine_required({"a": good_evidence("a", "MISMATCH"), "b": good_evidence("b", "BLOCKED")}, ["a", "b"])[0]
        == "MISMATCH"
    )
    assert (
        audit.combine_required({"a": good_evidence("a", "BLOCKED"), "b": good_evidence("b", "PENDING")}, ["a", "b"])[0]
        == "BLOCKED"
    )
    assert (
        audit.combine_required({"a": good_evidence("a", "PENDING"), "b": good_evidence("b", "UNKNOWN")}, ["a", "b"])[0]
        == "PENDING"
    )
    assert (
        audit.combine_required({"a": good_evidence("a", "UNKNOWN"), "b": good_evidence("b", "STALE")}, ["a", "b"])[0]
        == "UNKNOWN"
    )


@pytest.mark.parametrize(
    ("status", "exit_code"),
    [("VERIFIED", 0), ("MISMATCH", 1), ("RED", 1), ("BLOCKED", 2), ("PENDING", 3), ("UNKNOWN", 3), ("STALE", 3)],
)
def test_exit_codes(status, exit_code):
    assert audit.exit_code_for_status(status) == exit_code


def test_source_parsing():
    evidence, details = audit.audit_source_contract(ROOT)

    assert evidence.status == "MATCH"
    assert details["mcp_package_version"] == details["module_version"]
    assert details["tool_count"] == len(details["tool_names"])


def test_registry_parsing():
    payload = {
        "servers": [
            {
                "name": "io.github.hodlxxi/hodlxxi-readonly",
                "versions": [
                    {
                        "version": "0.1.1",
                        "isLatest": True,
                        "status": "active",
                        "publishedAt": "2026-07-14T00:00:00Z",
                        "websiteUrl": "https://hodlxxi.com",
                        "repository": {
                            "url": "https://github.com/hodlxxi/Universal-Bitcoin-Identity-Layer",
                            "subfolder": "packages/hodlxxi_mcp",
                        },
                        "remotes": [{"url": "https://hodlxxi.com/agent/mcp"}],
                    }
                ],
            }
        ]
    }

    versions = audit.parse_registry_versions(payload, expected_name="io.github.hodlxxi/hodlxxi-readonly")

    assert versions == [
        {
            "version": "0.1.1",
            "isLatest": True,
            "status": "active",
            "publishedAt": "2026-07-14T00:00:00Z",
            "remote_url": "https://hodlxxi.com/agent/mcp",
            "website_url": "https://hodlxxi.com",
            "repository_url": "https://github.com/hodlxxi/Universal-Bitcoin-Identity-Layer",
            "subfolder": "packages/hodlxxi_mcp",
        }
    ]


def test_p2wsh_calculation():
    payload = json.loads((ROOT / "app" / "data" / "trust" / "covenant_hodlxxi-herald-covenant-v1.json").read_text())

    evaluation = audit.evaluate_covenant_payload(payload)

    assert evaluation["status"] == "MATCH"
    assert evaluation["calculated_address"] == payload["anchor"]["address"]
    assert evaluation["delta_144"] is True


def test_output_dir_defaults_outside_repository():
    output_dir = audit.default_output_dir(ROOT)

    assert not str(output_dir).startswith(str(ROOT))
