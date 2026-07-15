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


def load_real_covenant_payload():
    return json.loads((ROOT / "app" / "data" / "trust" / "covenant_hodlxxi-herald-covenant-v1.json").read_text())


def build_registry_payload(source_details, versions):
    return {
        "json": {
            "servers": [
                {
                    "name": source_details["server_json"]["name"],
                    "versions": versions,
                }
            ]
        }
    }


def build_registry_version(source_details, *, version=None, is_latest=True, status="active", remote_url=None):
    source_server = source_details["server_json"]
    return {
        "version": version or source_server["version"],
        "isLatest": is_latest,
        "status": status,
        "publishedAt": "2026-07-14T00:00:00Z",
        "websiteUrl": source_server["websiteUrl"],
        "repository": {
            "url": source_server["repository"]["url"],
            "subfolder": source_server["repository"]["subfolder"],
        },
        "remotes": [{"url": remote_url or source_server["remotes"][0]["url"]}],
    }


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


def test_registry_source_version_present_but_not_latest_is_mismatch(monkeypatch):
    source = real_source_details()
    payload = build_registry_payload(source, [build_registry_version(source, is_latest=False)])
    monkeypatch.setattr(audit, "fetch_public_json", lambda *_, **__: payload)

    evidence = audit.audit_registry(source_details=source, timeout=1.0, skip_live=False)

    assert evidence.status == "MISMATCH"
    assert "not marked latest" in " ".join(evidence.details["mismatches"])


def test_registry_other_version_marked_latest_is_mismatch(monkeypatch):
    source = real_source_details()
    payload = build_registry_payload(
        source,
        [
            build_registry_version(source, is_latest=False),
            build_registry_version(source, version="0.1.0", is_latest=True),
        ],
    )
    monkeypatch.setattr(audit, "fetch_public_json", lambda *_, **__: payload)

    evidence = audit.audit_registry(source_details=source, timeout=1.0, skip_live=False)

    assert evidence.status == "MISMATCH"
    assert "latest version 0.1.0" in " ".join(evidence.details["mismatches"])


def test_registry_multiple_latest_versions_is_mismatch(monkeypatch):
    source = real_source_details()
    payload = build_registry_payload(
        source,
        [
            build_registry_version(source, version=source["server_json"]["version"], is_latest=True),
            build_registry_version(source, version="0.1.0", is_latest=True),
        ],
    )
    monkeypatch.setattr(audit, "fetch_public_json", lambda *_, **__: payload)

    evidence = audit.audit_registry(source_details=source, timeout=1.0, skip_live=False)

    assert evidence.status == "MISMATCH"
    assert "exactly 1" in " ".join(evidence.details["mismatches"])


def test_registry_expected_version_inactive_is_mismatch(monkeypatch):
    source = real_source_details()
    payload = build_registry_payload(source, [build_registry_version(source, status="inactive")])
    monkeypatch.setattr(audit, "fetch_public_json", lambda *_, **__: payload)

    evidence = audit.audit_registry(source_details=source, timeout=1.0, skip_live=False)

    assert evidence.status == "MISMATCH"
    assert "not active" in " ".join(evidence.details["mismatches"])


def test_registry_single_latest_active_version_matches(monkeypatch):
    source = real_source_details()
    payload = build_registry_payload(source, [build_registry_version(source)])
    monkeypatch.setattr(audit, "fetch_public_json", lambda *_, **__: payload)

    evidence = audit.audit_registry(source_details=source, timeout=1.0, skip_live=False)

    assert evidence.status == "MATCH"


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


def test_stale_reference_detection_in_python_source(tmp_path):
    (tmp_path / "stale_contract.py").write_text('MESSAGE = "disabled production stub"\n', encoding="utf-8")

    evidence = audit.audit_stale_references(tmp_path)

    assert evidence.status == "STALE"
    assert evidence.details["findings"][0]["path"] == "stale_contract.py"


def test_stale_reference_ignores_egg_info_directory(tmp_path):
    egg_info = tmp_path / "package.egg-info"
    egg_info.mkdir()
    (egg_info / "PKG-INFO").write_text("disabled production stub\n", encoding="utf-8")

    evidence = audit.audit_stale_references(tmp_path)

    assert evidence.status == "MATCH"


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
    payload = load_real_covenant_payload()

    evaluation = audit.evaluate_covenant_payload(payload)

    assert evaluation["status"] == "MATCH"
    assert evaluation["calculated_address"] == payload["anchor"]["address"]
    assert evaluation["delta_144"] is True


def test_funded_covenant_without_utxo_evidence_does_not_prove_locked_capital():
    payload = load_real_covenant_payload()
    payload["funding_status"] = "funded"
    payload["status"] = "funded"

    evaluation = audit.evaluate_covenant_payload(payload)

    assert evaluation["status"] == "UNKNOWN"
    assert evaluation["declared_funding_status"] == "funded"
    assert evaluation["utxo_evidence_checked"] is False
    assert evaluation["utxo_evidence_verified"] is False
    assert evaluation["time_locked_capital_proof"] is False
    assert evaluation["funding_claim_status"] == "UNVERIFIED"


def test_cooperative_path_prevents_time_locked_capital_proof():
    payload = load_real_covenant_payload()
    payload["funding_status"] = "funded"
    payload["status"] = "funded"

    evaluation = audit.evaluate_covenant_payload(payload)

    assert evaluation["cooperative_path_present"] is True
    assert evaluation["time_locked_capital_proof"] is False


def test_missing_required_lock_heights_cannot_match():
    payload = load_real_covenant_payload()
    payload["policy"]["future_exit_logic"] = payload["policy"]["future_exit_logic"][:1]

    evaluation = audit.evaluate_covenant_payload(payload)

    assert evaluation["status"] == "MISMATCH"
    assert evaluation["timelock_structure_valid"] is False
    assert "incomplete" in " ".join(evaluation["mismatches"]).lower()


def test_descriptor_address_equality_alone_does_not_prove_funding():
    payload = load_real_covenant_payload()
    payload["funding_status"] = "funded"
    payload["status"] = "funded"

    evaluation = audit.evaluate_covenant_payload(payload)

    assert evaluation["declared_address"] == evaluation["calculated_address"]
    assert evaluation["status"] == "UNKNOWN"
    assert evaluation["time_locked_capital_proof"] is False


def test_output_dir_defaults_outside_repository():
    output_dir = audit.default_output_dir(ROOT)

    assert not str(output_dir).startswith(str(ROOT))


def test_redact_sensitive_text_masks_credentials_and_tokens():
    text = "Authorization: Bearer secret-token\n" "proxy_set_header Cookie session=abc123;\n" "API_TOKEN=shhh\n"

    redacted = audit.redact_sensitive_text(text)

    assert "secret-token" not in redacted
    assert "abc123" not in redacted
    assert "shhh" not in redacted
    assert "<redacted>" in redacted


def test_extract_nginx_agent_mcp_evidence_redacts_and_bounds_route_snippets():
    text = """
    location /agent/mcp {
        proxy_pass http://127.0.0.1:8765/mcp;
        proxy_set_header Authorization Bearer secret-token;
        proxy_set_header Cookie session=abc123;
    }
    """

    snippets = audit.extract_nginx_agent_mcp_evidence(text)

    assert snippets
    assert any("/agent/mcp" in snippet for snippet in snippets)
    assert any("127.0.0.1:8765" in snippet for snippet in snippets)
    assert all("secret-token" not in snippet for snippet in snippets)
    assert all("abc123" not in snippet for snippet in snippets)


def test_report_outputs_do_not_serialize_raw_public_payloads():
    evidence = audit.Evidence(
        name="discovery",
        status="MATCH",
        summary="bounded",
        details={
            "results": [
                {
                    "path": "/.well-known/mcp.json",
                    "summary": {"name": "HODLXXI Read-Only"},
                    "json": {"huge_blob": "X" * 5000, "irrelevant": "should-not-leak"},
                }
            ]
        },
    )
    report = audit.AuditReport(
        repo_root=str(ROOT),
        output_dir="/tmp/test-report",
        timestamp_utc="2026-07-14T00:00:00Z",
        status="MATCH",
        exit_code=3,
        evidences=[evidence],
        required_categories=["discovery"],
    )

    payload = json.dumps(report.to_dict(), sort_keys=True)
    markdown = audit.render_markdown_report(report)

    assert "huge_blob" not in payload
    assert "should-not-leak" not in payload
    assert "huge_blob" not in markdown
    assert "should-not-leak" not in markdown
