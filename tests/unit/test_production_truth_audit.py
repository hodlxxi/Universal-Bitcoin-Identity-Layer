from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

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


def systemctl_show_command(service):
    return ("systemctl", "show", service, *[f"--property={item}" for item in audit.HOST_CHECK_PROPERTIES])


def active_host_runner(expected_head):
    return make_runner(
        {
            systemctl_show_command("hodlxxi.service"): result(stdout="ActiveState=active\nSubState=running\n"),
            systemctl_show_command("hodlxxi-mcp.service"): result(stdout="ActiveState=active\nSubState=running\n"),
            systemctl_show_command("nginx.service"): result(stdout="ActiveState=active\nSubState=running\n"),
            ("git", "rev-parse", "HEAD"): result(stdout=f"{expected_head}\n"),
        }
    )


def mock_sidecar_host_items(
    *,
    expected_head,
    expected_version,
    include_current_symlink=True,
    include_release_sha=True,
    release_sha=None,
    release_target=None,
    wildcard_listener=False,
    include_nginx_route=True,
):
    observed_release_sha = release_sha or expected_head
    observed_target = release_target or str(audit.HOST_MCP_RELEASES_DIR / observed_release_sha)

    items = []
    if include_current_symlink:
        items.append(
            audit.host_item(
                "mcp_current_symlink",
                "direct",
                "Captured MCP current release symlink target.",
                {"path": str(audit.HOST_MCP_CURRENT_SYMLINK), "target": observed_target},
            )
        )
    if include_release_sha:
        items.append(
            audit.host_item(
                "mcp_release_sha",
                "inference",
                "Derived MCP release SHA from current symlink target.",
                {"target": observed_target, "release_sha": observed_release_sha},
            )
        )

    items.extend(
        [
            audit.host_item(
                "mcp_loopback_listener",
                "direct",
                "Collected bounded MCP loopback listener evidence.",
                {
                    "loopback_listener_detected": not wildcard_listener,
                    "wildcard_listener_detected": wildcard_listener,
                    "listener_lines": ["0.0.0.0:8765" if wildcard_listener else "127.0.0.1:8765"],
                },
            ),
            audit.host_item(
                "mcp_sidecar_package_version",
                "direct",
                "Read the sidecar virtualenv package version.",
                {"version": expected_version},
            ),
            audit.host_item(
                "flask_service_checkout",
                "direct",
                "Captured Flask service working directory, executable, and checkout SHA.",
                {"checkout_sha": expected_head},
            ),
        ]
    )
    if include_nginx_route:
        items.append(
            audit.host_item(
                "nginx_agent_mcp_route",
                "direct",
                "Collected bounded nginx /agent/mcp route evidence.",
                {"matches": [{"snippets": ["/agent/mcp", "proxy_pass http://127.0.0.1:8765/mcp;"]}]},
            )
        )
    return items


def patch_release_identity(
    monkeypatch,
    *,
    status="MATCH",
    matched=None,
    exact=False,
    equivalent=True,
    changed_files=None,
    summary="component identity",
):
    monkeypatch.setattr(
        audit,
        "evaluate_mcp_release_identity",
        lambda **kwargs: {
            "status": status,
            "matched": (status == "MATCH") if matched is None else matched,
            "release_commit_exact_match": exact,
            "component_source_equivalent": equivalent,
            "component_scope_paths": audit.canonical_mcp_component_scope_paths(ROOT),
            "component_changed_files": changed_files or [],
            "release_commit_resolved": True,
            "release_commit_relation": "ancestor",
            "observed_release_sha": kwargs.get("observed_release_sha"),
            "expected_repo_sha": kwargs.get("expected_repo_sha"),
            "summary": summary,
        },
    )


def component_identity_runner(
    expected_head,
    release_sha,
    *,
    changed_files=None,
    relation="ancestor",
    release_exists=True,
    expected_exists=True,
):
    scope_paths = tuple(audit.canonical_mcp_component_scope_paths(ROOT))
    mapping = {
        ("git", "rev-parse", "--verify", f"{release_sha}^{{commit}}"): (
            result(stdout=f"{release_sha}\n") if release_exists else result(returncode=1, stderr="unknown revision")
        ),
        ("git", "rev-parse", "--verify", f"{expected_head}^{{commit}}"): (
            result(stdout=f"{expected_head}\n") if expected_exists else result(returncode=1, stderr="unknown revision")
        ),
        ("git", "diff", "--name-only", release_sha, expected_head, "--", *scope_paths): result(
            stdout="".join(f"{path}\n" for path in (changed_files or []))
        ),
    }
    if relation == "ancestor":
        mapping[("git", "merge-base", "--is-ancestor", release_sha, expected_head)] = result(returncode=0)
    elif relation == "descendant":
        mapping[("git", "merge-base", "--is-ancestor", release_sha, expected_head)] = result(returncode=1)
        mapping[("git", "merge-base", "--is-ancestor", expected_head, release_sha)] = result(returncode=0)
    elif relation == "comparable":
        mapping[("git", "merge-base", "--is-ancestor", release_sha, expected_head)] = result(returncode=1)
        mapping[("git", "merge-base", "--is-ancestor", expected_head, release_sha)] = result(returncode=1)
        mapping[("git", "merge-base", release_sha, expected_head)] = result(stdout="abc1234\n")
    else:
        mapping[("git", "merge-base", "--is-ancestor", release_sha, expected_head)] = result(returncode=2, stderr="bad")
    return make_runner(mapping)


def init_component_identity_repo(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )

    for relative_path in audit.canonical_mcp_component_scope_paths():
        target = repo / relative_path
        if target.suffix:
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.name == "pyproject.toml":
                target.write_text(
                    "[project]\nname = 'hodlxxi-mcp'\nversion = '0.1.1'\nreadme = 'README.md'\n",
                    encoding="utf-8",
                )
            elif target.name == "README.md":
                target.write_text("# package readme\n", encoding="utf-8")
            elif target.name == "server.json":
                target.write_text('{"name":"io.github.hodlxxi/hodlxxi-readonly"}\n', encoding="utf-8")
            elif target.name == "hodlxxi-mcp.service":
                target.write_text(
                    "WorkingDirectory=/opt/hodlxxi-mcp/current\n"
                    "ExecStart=/opt/hodlxxi-mcp/current/venv/bin/hodlxxi-mcp-http\n",
                    encoding="utf-8",
                )
            else:
                target.write_text("placeholder\n", encoding="utf-8")
        else:
            target.mkdir(parents=True, exist_ok=True)
            (target / "http_server.py").write_text("def main():\n    return None\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "commit", "-m", "release"], cwd=repo, check=True, capture_output=True, text=True)
    release_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return repo, release_sha, str(repo / "packages" / "hodlxxi_mcp" / "src" / "hodlxxi_mcp")


def git_commit_all(repo: Path, message: str) -> str:
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "commit", "-m", message], cwd=repo, check=True, capture_output=True, text=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def write_repo_file(repo: Path, relative_path: str, content: str) -> None:
    target = repo / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


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


def test_github_missing_gh_uses_public_http_fallback(monkeypatch):
    runner = make_runner({("git", "rev-parse", "HEAD"): result(stdout="abc\n")})
    monkeypatch.setattr(audit.shutil, "which", lambda command: None if command == "gh" else "/bin/other")
    monkeypatch.setattr(
        audit,
        "fetch_github_check_runs_via_http",
        lambda *_, **__: ("public_http", []),
    )

    evidence = audit.audit_github_checks(
        ROOT,
        source_details=real_source_details(),
        runner=runner,
        skip_live=False,
        timeout=1.0,
    )

    assert evidence.status == "UNKNOWN"
    assert evidence.details["transport"] == "public_http"


def test_github_unauthenticated_gh_uses_http_fallback(monkeypatch):
    runner = make_runner(
        {
            ("git", "rev-parse", "HEAD"): result(stdout="abc\n"),
            ("gh", "auth", "status", "-h", "github.com"): result(returncode=1, stderr="invalid token"),
        }
    )
    monkeypatch.setattr(audit.shutil, "which", lambda command: "/opt/homebrew/bin/gh" if command == "gh" else None)
    monkeypatch.setattr(
        audit,
        "fetch_github_check_runs_via_http",
        lambda *_, **__: ("public_http", [{"name": "pytest", "status": "completed", "conclusion": "success"}]),
    )

    evidence = audit.audit_github_checks(
        ROOT,
        source_details=real_source_details(),
        runner=runner,
        skip_live=False,
        timeout=1.0,
    )

    assert evidence.status == "GREEN"
    assert evidence.details["transport"] == "public_http"


def test_github_malformed_cli_response_uses_http_fallback(monkeypatch):
    runner = make_runner(
        {
            ("git", "rev-parse", "HEAD"): result(stdout="abc\n"),
            ("gh", "auth", "status", "-h", "github.com"): result(stdout="ok\n"),
        }
    )
    monkeypatch.setattr(audit.shutil, "which", lambda command: "/opt/homebrew/bin/gh" if command == "gh" else None)
    monkeypatch.setattr(
        audit,
        "fetch_github_check_runs_via_gh",
        lambda *_, **__: (_ for _ in ()).throw(ValueError("malformed cli output")),
    )
    monkeypatch.setattr(
        audit,
        "fetch_github_check_runs_via_http",
        lambda *_, **__: ("public_http", [{"name": "pytest", "status": "completed", "conclusion": "success"}]),
    )

    evidence = audit.audit_github_checks(
        ROOT,
        source_details=real_source_details(),
        runner=runner,
        skip_live=False,
        timeout=1.0,
    )

    assert evidence.status == "GREEN"
    assert evidence.details["transport"] == "public_http"


def test_github_successful_http_check_runs_return_green(monkeypatch):
    runner = make_runner({("git", "rev-parse", "HEAD"): result(stdout="abc\n")})
    monkeypatch.setattr(audit.shutil, "which", lambda command: None if command == "gh" else "/bin/other")
    monkeypatch.setattr(
        audit,
        "fetch_github_check_runs_via_http",
        lambda *_, **__: ("public_http", [{"name": "pytest", "status": "completed", "conclusion": "success"}]),
    )

    evidence = audit.audit_github_checks(
        ROOT,
        source_details=real_source_details(),
        runner=runner,
        skip_live=False,
        timeout=1.0,
    )

    assert evidence.status == "GREEN"


def test_github_pending(monkeypatch):
    runner = make_runner({("git", "rev-parse", "HEAD"): result(stdout="abc\n")})
    monkeypatch.setattr(audit.shutil, "which", lambda command: None if command == "gh" else "/bin/other")
    monkeypatch.setattr(
        audit,
        "fetch_github_check_runs_via_http",
        lambda *_, **__: ("public_http", [{"name": "pytest", "status": "queued", "conclusion": None}]),
    )

    evidence = audit.audit_github_checks(
        ROOT,
        source_details=real_source_details(),
        runner=runner,
        skip_live=False,
        timeout=1.0,
    )

    assert evidence.status == "PENDING"


def test_github_failed_http_check_runs_return_red(monkeypatch):
    runner = make_runner({("git", "rev-parse", "HEAD"): result(stdout="abc\n")})
    monkeypatch.setattr(audit.shutil, "which", lambda command: None if command == "gh" else "/bin/other")
    monkeypatch.setattr(
        audit,
        "fetch_github_check_runs_via_http",
        lambda *_, **__: ("public_http", [{"name": "pytest", "status": "completed", "conclusion": "failure"}]),
    )

    evidence = audit.audit_github_checks(
        ROOT,
        source_details=real_source_details(),
        runner=runner,
        skip_live=False,
        timeout=1.0,
    )

    assert evidence.status == "RED"


def test_github_rate_limiting_returns_blocked(monkeypatch):
    runner = make_runner({("git", "rev-parse", "HEAD"): result(stdout="abc\n")})
    monkeypatch.setattr(audit.shutil, "which", lambda command: None if command == "gh" else "/bin/other")
    monkeypatch.setattr(
        audit,
        "fetch_github_check_runs_via_http",
        lambda *_, **__: (_ for _ in ()).throw(
            audit.VerificationError("rate_limit", "GitHub API rate limit exceeded", http_status=403)
        ),
    )

    evidence = audit.audit_github_checks(
        ROOT,
        source_details=real_source_details(),
        runner=runner,
        skip_live=False,
        timeout=1.0,
    )

    assert evidence.status == "BLOCKED"
    assert evidence.details["error_category"] == "rate_limit"


def test_github_no_token_is_serialized(monkeypatch):
    runner = make_runner({("git", "rev-parse", "HEAD"): result(stdout="abc\n")})
    monkeypatch.setenv("GITHUB_TOKEN", "super-secret-token")
    monkeypatch.setattr(audit.shutil, "which", lambda command: None if command == "gh" else "/bin/other")
    monkeypatch.setattr(
        audit,
        "fetch_github_check_runs_via_http",
        lambda *_, **__: ("authenticated_http", [{"name": "pytest", "status": "completed", "conclusion": "success"}]),
    )

    evidence = audit.audit_github_checks(
        ROOT,
        source_details=real_source_details(),
        runner=runner,
        skip_live=False,
        timeout=1.0,
    )

    payload = json.dumps(audit.artifact_evidence_dict(evidence), sort_keys=True)
    assert evidence.details["transport"] == "authenticated_http"
    assert "super-secret-token" not in payload


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


def test_registry_timeout_then_success_retries_once():
    source = real_source_details()
    payload = build_registry_payload(source, [build_registry_version(source)])
    calls = {"count": 0}
    sleeps = []

    def fetcher(*_, **__):
        calls["count"] += 1
        if calls["count"] == 1:
            raise audit.VerificationError("timeout", "timed out")
        return payload

    evidence = audit.audit_registry(
        source_details=source,
        timeout=1.0,
        skip_live=False,
        http_fetch=fetcher,
        sleeper=sleeps.append,
    )

    assert evidence.status == "MATCH"
    assert evidence.details["attempt_count"] == 2
    assert evidence.details["final_error_category"] is None
    assert evidence.details["last_transient_error_category"] == "timeout"
    assert evidence.details["transient_error_count"] == 1
    assert len(sleeps) == 1


def test_registry_repeated_timeout_returns_blocked():
    source = real_source_details()
    sleeps = []

    evidence = audit.audit_registry(
        source_details=source,
        timeout=1.0,
        skip_live=False,
        http_fetch=lambda *_, **__: (_ for _ in ()).throw(audit.VerificationError("timeout", "timed out")),
        sleeper=sleeps.append,
    )

    assert evidence.status == "BLOCKED"
    assert evidence.details["attempt_count"] == audit.REGISTRY_MAX_ATTEMPTS
    assert evidence.details["final_error_category"] == "timeout"
    assert evidence.details["last_transient_error_category"] == "timeout"
    assert evidence.details["transient_error_count"] == audit.REGISTRY_MAX_ATTEMPTS - 1
    assert len(sleeps) == audit.REGISTRY_MAX_ATTEMPTS - 1


def test_registry_malformed_response_does_not_retry():
    source = real_source_details()
    sleeps = []

    evidence = audit.audit_registry(
        source_details=source,
        timeout=1.0,
        skip_live=False,
        http_fetch=lambda *_, **__: {"not_json": {}},
        sleeper=sleeps.append,
    )

    assert evidence.status == "BLOCKED"
    assert evidence.details["attempt_count"] == 1
    assert evidence.details["final_error_category"] == "malformed"
    assert evidence.details["last_transient_error_category"] is None
    assert evidence.details["transient_error_count"] == 0
    assert sleeps == []


def test_registry_mismatch(monkeypatch):
    source = real_source_details()
    monkeypatch.setattr(
        audit,
        "fetch_public_json",
        lambda *_, **__: {"json": {"servers": [{"name": source["server_json"]["name"], "versions": []}]}},
    )

    evidence = audit.audit_registry(source_details=source, timeout=1.0, skip_live=False)

    assert evidence.status == "MISMATCH"


def test_registry_metadata_mismatch_does_not_retry():
    source = real_source_details()
    payload = build_registry_payload(source, [build_registry_version(source, is_latest=False)])
    sleeps = []

    evidence = audit.audit_registry(
        source_details=source,
        timeout=1.0,
        skip_live=False,
        http_fetch=lambda *_, **__: payload,
        sleeper=sleeps.append,
    )

    assert evidence.status == "MISMATCH"
    assert evidence.details["attempt_count"] == 1
    assert evidence.details["final_error_category"] is None
    assert evidence.details["last_transient_error_category"] is None
    assert evidence.details["transient_error_count"] == 0
    assert sleeps == []


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
    assert evidence.details["attempt_count"] == 1
    assert evidence.details["final_error_category"] is None
    assert evidence.details["last_transient_error_category"] is None
    assert evidence.details["transient_error_count"] == 0


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


def test_real_repository_detector_constants_and_test_fixtures_not_reported():
    evidence = audit.audit_stale_references(ROOT)
    findings = evidence.details.get("findings", [])
    detector_paths = {
        "scripts/production_truth_audit.py": ROOT / "scripts" / "production_truth_audit.py",
        "scripts/mcp_remote_verify.py": ROOT / "scripts" / "mcp_remote_verify.py",
    }
    ignored_lines = {
        relative_path: audit.stale_detector_assignment_lines(path, path.read_text(encoding="utf-8"))
        for relative_path, path in detector_paths.items()
    }

    assert all(not finding["path"].startswith("tests/") for finding in findings)
    for finding in findings:
        lines = ignored_lines.get(finding["path"])
        assert not lines or finding["line"] not in lines


def test_stale_reference_detection_in_application_python_source(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "example.py").write_text('MESSAGE = "disabled production stub"\n', encoding="utf-8")

    evidence = audit.audit_stale_references(tmp_path)

    assert evidence.status == "STALE"
    assert evidence.details["findings"][0]["path"] == "app/example.py"


def test_stale_reference_detection_in_operational_script_outside_detector_assignment(tmp_path):
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    (scripts_dir / "check_runtime.py").write_text(
        'STALE_DESCRIPTION_PHRASES = ("disabled production stub",)\n' 'NOTICE = "disabled production stub"\n',
        encoding="utf-8",
    )

    evidence = audit.audit_stale_references(tmp_path)

    assert evidence.status == "STALE"
    assert evidence.details["findings"] == [
        {
            "path": "scripts/check_runtime.py",
            "line": 2,
            "phrase": "disabled production stub",
            "snippet": 'NOTICE = "disabled production stub"',
        }
    ]


def test_stale_reference_detection_ignores_tests_tree(tmp_path):
    tests_dir = tmp_path / "tests" / "unit"
    tests_dir.mkdir(parents=True)
    (tests_dir / "test_fixture.py").write_text('MESSAGE = "disabled production stub"\n', encoding="utf-8")

    evidence = audit.audit_stale_references(tmp_path)

    assert evidence.status == "MATCH"


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


def test_genuine_current_state_documentation_claim_remains_detected(tmp_path):
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()
    (docs_dir / "status.md").write_text("Current status: disabled production stub.\n", encoding="utf-8")

    evidence = audit.audit_stale_references(tmp_path)

    assert evidence.status == "STALE"
    assert evidence.details["findings"][0]["path"] == "docs/status.md"


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


def test_component_identity_exact_release_sha_matches():
    release_sha = "97e89853d17983129acf849e8b2ad2c1d634ff4c"

    evaluation = audit.evaluate_mcp_release_identity(
        root=ROOT,
        runner=make_runner({}),
        expected_repo_sha=release_sha,
        observed_release_sha=release_sha,
    )

    assert evaluation["status"] == "MATCH"
    assert evaluation["release_commit_exact_match"] is True
    assert evaluation["component_source_equivalent"] is True


def test_canonical_mcp_component_scope_is_complete_and_static():
    assert audit.canonical_mcp_component_scope_paths(ROOT) == [
        "packages/hodlxxi_mcp/pyproject.toml",
        "packages/hodlxxi_mcp/README.md",
        "packages/hodlxxi_mcp/src/hodlxxi_mcp",
        "deployment/systemd/hodlxxi-mcp.service",
        "server.json",
    ]


def test_component_identity_package_source_change_is_mismatch():
    expected_head = "5" * 40
    release_sha = "9" * 40

    evaluation = audit.evaluate_mcp_release_identity(
        root=ROOT,
        runner=component_identity_runner(
            expected_head,
            release_sha,
            changed_files=["packages/hodlxxi_mcp/src/hodlxxi_mcp/http_server.py"],
        ),
        expected_repo_sha=expected_head,
        observed_release_sha=release_sha,
    )

    assert evaluation["status"] == "MISMATCH"
    assert evaluation["component_source_equivalent"] is False


def test_component_identity_package_readme_change_is_mismatch():
    expected_head = "5" * 40
    release_sha = "9" * 40

    evaluation = audit.evaluate_mcp_release_identity(
        root=ROOT,
        runner=component_identity_runner(
            expected_head,
            release_sha,
            changed_files=["packages/hodlxxi_mcp/README.md"],
        ),
        expected_repo_sha=expected_head,
        observed_release_sha=release_sha,
    )

    assert evaluation["status"] == "MISMATCH"
    assert "packages/hodlxxi_mcp/README.md" in evaluation["component_changed_files"]


def test_component_identity_systemd_unit_change_is_mismatch():
    expected_head = "5" * 40
    release_sha = "9" * 40

    evaluation = audit.evaluate_mcp_release_identity(
        root=ROOT,
        runner=component_identity_runner(
            expected_head,
            release_sha,
            changed_files=["deployment/systemd/hodlxxi-mcp.service"],
        ),
        expected_repo_sha=expected_head,
        observed_release_sha=release_sha,
    )

    assert evaluation["status"] == "MISMATCH"
    assert "deployment/systemd/hodlxxi-mcp.service" in evaluation["component_changed_files"]


def test_component_identity_unknown_release_commit_is_not_match():
    expected_head = "5" * 40
    release_sha = "9" * 40

    evaluation = audit.evaluate_mcp_release_identity(
        root=ROOT,
        runner=component_identity_runner(expected_head, release_sha, release_exists=False),
        expected_repo_sha=expected_head,
        observed_release_sha=release_sha,
    )

    assert evaluation["status"] in {"UNKNOWN", "BLOCKED"}
    assert evaluation["matched"] is False


@pytest.mark.parametrize(
    "relative_path",
    [
        "deployment/systemd/hodlxxi-mcp.service",
        "server.json",
        "packages/hodlxxi_mcp/pyproject.toml",
        "packages/hodlxxi_mcp/README.md",
    ],
)
def test_component_identity_deleted_canonical_input_is_mismatch_in_real_git_repo(tmp_path, relative_path):
    repo, release_sha, _ = init_component_identity_repo(tmp_path)
    (repo / relative_path).unlink()
    expected_head = git_commit_all(repo, f"delete {relative_path}")

    evaluation = audit.evaluate_mcp_release_identity(
        root=repo,
        runner=audit.default_runner,
        expected_repo_sha=expected_head,
        observed_release_sha=release_sha,
    )

    assert evaluation["status"] == "MISMATCH"
    assert evaluation["component_source_equivalent"] is False
    assert relative_path in evaluation["missing_current_scope_paths"]
    assert relative_path in evaluation["component_changed_files"]


def test_deleted_canonical_path_remains_in_git_diff_pathspec(tmp_path):
    deleted_path = "deployment/systemd/hodlxxi-mcp.service"
    for relative_path in audit.canonical_mcp_component_scope_paths():
        if relative_path == deleted_path:
            continue
        target = tmp_path / relative_path
        if relative_path.endswith("src/hodlxxi_mcp"):
            target.mkdir(parents=True, exist_ok=True)
            (target / "http_server.py").write_text("def main():\n    return None\n", encoding="utf-8")
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("placeholder\n", encoding="utf-8")

    expected_head = "5" * 40
    release_sha = "9" * 40
    captured_command: list[str] = []

    def runner(command, cwd):
        nonlocal captured_command
        if command == ["git", "rev-parse", "--verify", f"{release_sha}^{{commit}}"]:
            return result(stdout=f"{release_sha}\n")
        if command == ["git", "rev-parse", "--verify", f"{expected_head}^{{commit}}"]:
            return result(stdout=f"{expected_head}\n")
        if command == ["git", "merge-base", "--is-ancestor", release_sha, expected_head]:
            return result(returncode=0)
        if command[:4] == ["git", "diff", "--name-only", release_sha]:
            captured_command = command
            return result(stdout=f"{deleted_path}\n")
        return result(returncode=1, stderr="unexpected command")

    evaluation = audit.evaluate_mcp_release_identity(
        root=tmp_path,
        runner=runner,
        expected_repo_sha=expected_head,
        observed_release_sha=release_sha,
    )

    assert evaluation["status"] == "MISMATCH"
    assert deleted_path in captured_command
    assert deleted_path in evaluation["missing_current_scope_paths"]


@pytest.mark.parametrize(
    "relative_path,content",
    [
        ("docs/guide.md", "docs-only change\n"),
        ("tests/unit/test_placeholder.py", "def test_placeholder():\n    assert True\n"),
        (".github/workflows/example.yml", "name: example\n"),
        ("scripts/production_truth_audit.py", "# audit-only change\n"),
    ],
)
def test_component_identity_non_component_changes_remain_equivalent_in_real_git_repo(tmp_path, relative_path, content):
    repo, release_sha, _ = init_component_identity_repo(tmp_path)
    write_repo_file(repo, relative_path, content)
    expected_head = git_commit_all(repo, f"change {relative_path}")

    evaluation = audit.evaluate_mcp_release_identity(
        root=repo,
        runner=audit.default_runner,
        expected_repo_sha=expected_head,
        observed_release_sha=release_sha,
    )

    assert evaluation["status"] == "MATCH"
    assert evaluation["component_source_equivalent"] is True
    assert evaluation["component_changed_files"] == []


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


def test_collect_nginx_route_item_detects_extensionless_sites_enabled_file(tmp_path):
    nginx_root = tmp_path / "etc" / "nginx"
    site_file = nginx_root / "sites-enabled" / "hodlxxi"
    site_file.parent.mkdir(parents=True)
    site_file.write_text(
        "location = /agent/mcp {\n    proxy_pass http://127.0.0.1:8765/mcp;\n}\n",
        encoding="utf-8",
    )

    item = audit.collect_nginx_route_item(
        candidates=(site_file, nginx_root / "sites-enabled"),
        nginx_root=nginx_root,
    )

    assert item["classification"] == "direct"
    assert any(match["path"].endswith("sites-enabled/hodlxxi") for match in item["details"]["matches"])


def test_collect_nginx_route_item_requires_same_block_route_and_upstream(tmp_path):
    nginx_root = tmp_path / "etc" / "nginx"
    site_file = nginx_root / "sites-enabled" / "hodlxxi"
    site_file.parent.mkdir(parents=True)
    site_file.write_text(
        "server {\n" "  location = /agent/mcp {\n" "    proxy_pass http://127.0.0.1:8765/mcp;\n" "  }\n" "}\n",
        encoding="utf-8",
    )

    item = audit.collect_nginx_route_item(candidates=(nginx_root / "sites-enabled",), nginx_root=nginx_root)

    assert item["classification"] == "direct"


def test_collect_nginx_route_item_staging_only_file_does_not_prove_production(tmp_path):
    nginx_root = tmp_path / "etc" / "nginx"
    staging = nginx_root / "conf.d" / "hodlxxi-mcp-staging.conf"
    staging.parent.mkdir(parents=True)
    staging.write_text(
        "location = /agent/mcp {\n    proxy_pass http://127.0.0.1:8765/mcp;\n}\n",
        encoding="utf-8",
    )

    item = audit.collect_nginx_route_item(candidates=(nginx_root / "conf.d",), nginx_root=nginx_root)

    assert item["classification"] == "unavailable"
    assert item["details"]["rejected"][0]["reason"] == "staging_candidate"


def test_collect_nginx_route_item_does_not_mix_location_and_upstream_from_different_files(tmp_path):
    nginx_root = tmp_path / "etc" / "nginx"
    sites_enabled = nginx_root / "sites-enabled"
    conf_d = nginx_root / "conf.d"
    sites_enabled.mkdir(parents=True)
    conf_d.mkdir(parents=True)
    (sites_enabled / "hodlxxi").write_text(
        "location = /agent/mcp {\n    proxy_set_header Host $host;\n}\n", encoding="utf-8"
    )
    (conf_d / "upstream.conf").write_text("proxy_pass http://127.0.0.1:8765/mcp;\n", encoding="utf-8")

    item = audit.collect_nginx_route_item(candidates=(sites_enabled, conf_d), nginx_root=nginx_root)

    assert item["classification"] == "unavailable"


def test_collect_nginx_route_item_ignores_symlink_loops(tmp_path):
    nginx_root = tmp_path / "etc" / "nginx"
    sites_enabled = nginx_root / "sites-enabled"
    sites_enabled.mkdir(parents=True)
    (sites_enabled / "loop").symlink_to(sites_enabled, target_is_directory=True)

    item = audit.collect_nginx_route_item(candidates=(sites_enabled,), nginx_root=nginx_root)

    assert item["classification"] == "unavailable"


def test_collect_nginx_route_item_redacts_sensitive_headers(tmp_path):
    nginx_root = tmp_path / "etc" / "nginx"
    site_file = nginx_root / "sites-enabled" / "hodlxxi"
    site_file.parent.mkdir(parents=True)
    site_file.write_text(
        "location = /agent/mcp {\n"
        "    proxy_pass http://127.0.0.1:8765/mcp;\n"
        "    proxy_set_header Authorization Bearer secret-token;\n"
        "    proxy_set_header Cookie session=abc123;\n"
        "}\n",
        encoding="utf-8",
    )

    item = audit.collect_nginx_route_item(candidates=(site_file,), nginx_root=nginx_root)
    snippets = item["details"]["matches"][0]["snippets"]

    assert all("secret-token" not in snippet for snippet in snippets)
    assert all("abc123" not in snippet for snippet in snippets)


def test_real_production_regression_release_commit_is_component_equivalent():
    evaluation = audit.evaluate_mcp_release_identity(
        root=ROOT,
        runner=audit.default_runner,
        expected_repo_sha="5b1c6e50d172ca916c67e0281c84ef043d89446a",
        observed_release_sha="97e89853d17983129acf849e8b2ad2c1d634ff4c",
    )

    assert evaluation["status"] == "MATCH"
    assert evaluation["release_commit_exact_match"] is False
    assert evaluation["component_source_equivalent"] is True
    assert evaluation["component_changed_files"] == []
    assert "packages/hodlxxi_mcp/pyproject.toml" in evaluation["component_scope_paths"]
    assert "packages/hodlxxi_mcp/README.md" in evaluation["component_scope_paths"]
    assert "deployment/systemd/hodlxxi-mcp.service" in evaluation["component_scope_paths"]
    assert "server.json" in evaluation["component_scope_paths"]


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


def test_host_checks_one_successful_systemctl_call_does_not_auto_match(monkeypatch):
    expected_head = "1" * 40
    runner = make_runner(
        {
            systemctl_show_command("hodlxxi.service"): result(stdout="ActiveState=active\nSubState=running\n"),
            systemctl_show_command("hodlxxi-mcp.service"): result(returncode=1, stderr="missing"),
            systemctl_show_command("nginx.service"): result(returncode=1, stderr="missing"),
            ("git", "rev-parse", "HEAD"): result(stdout=f"{expected_head}\n"),
        }
    )
    monkeypatch.setattr(audit.shutil, "which", lambda command: "/bin/systemctl" if command == "systemctl" else None)
    monkeypatch.setattr(
        audit,
        "load_canonical_contract",
        lambda *_: SimpleNamespace(server_version=real_source_details()["server_version"]),
    )
    monkeypatch.setattr(audit, "collect_sidecar_host_items", lambda **_: [])

    evidence = audit.audit_host_checks(ROOT, runner=runner)

    assert evidence.status == "UNKNOWN"


def test_host_checks_inactive_required_service_is_mismatch(monkeypatch):
    expected_head = "1" * 40
    runner = make_runner(
        {
            systemctl_show_command("hodlxxi.service"): result(stdout="ActiveState=inactive\nSubState=dead\n"),
            systemctl_show_command("hodlxxi-mcp.service"): result(stdout="ActiveState=active\nSubState=running\n"),
            systemctl_show_command("nginx.service"): result(stdout="ActiveState=active\nSubState=running\n"),
            ("git", "rev-parse", "HEAD"): result(stdout=f"{expected_head}\n"),
        }
    )
    monkeypatch.setattr(audit.shutil, "which", lambda command: "/bin/systemctl" if command == "systemctl" else None)
    monkeypatch.setattr(
        audit,
        "load_canonical_contract",
        lambda *_: SimpleNamespace(server_version=real_source_details()["server_version"]),
    )
    monkeypatch.setattr(audit, "collect_sidecar_host_items", lambda **_: [])

    evidence = audit.audit_host_checks(ROOT, runner=runner)

    assert evidence.status == "MISMATCH"
    assert "hodlxxi.service ActiveState=inactive" in " ".join(evidence.details["verdict"]["mismatches"])


def test_host_checks_wildcard_listener_is_mismatch(monkeypatch):
    expected_head = "1" * 40
    expected_version = real_source_details()["server_version"]
    runner = active_host_runner(expected_head)
    monkeypatch.setattr(audit.shutil, "which", lambda command: "/bin/systemctl" if command == "systemctl" else None)
    monkeypatch.setattr(audit, "load_canonical_contract", lambda *_: SimpleNamespace(server_version=expected_version))
    patch_release_identity(monkeypatch)
    monkeypatch.setattr(
        audit,
        "collect_sidecar_host_items",
        lambda **_: mock_sidecar_host_items(
            expected_head=expected_head,
            expected_version=expected_version,
            wildcard_listener=True,
        ),
    )

    evidence = audit.audit_host_checks(ROOT, runner=runner)

    assert evidence.status == "MISMATCH"
    assert "wildcard listener detected" in " ".join(evidence.details["verdict"]["mismatches"])


def test_host_checks_partial_direct_evidence_is_unknown(monkeypatch):
    expected_head = "1" * 40
    expected_version = real_source_details()["server_version"]
    runner = active_host_runner(expected_head)
    monkeypatch.setattr(audit.shutil, "which", lambda command: "/bin/systemctl" if command == "systemctl" else None)
    monkeypatch.setattr(audit, "load_canonical_contract", lambda *_: SimpleNamespace(server_version=expected_version))
    patch_release_identity(monkeypatch)
    monkeypatch.setattr(
        audit,
        "collect_sidecar_host_items",
        lambda **_: mock_sidecar_host_items(
            expected_head=expected_head,
            expected_version=expected_version,
            include_nginx_route=False,
        ),
    )

    evidence = audit.audit_host_checks(ROOT, runner=runner)

    assert evidence.status == "UNKNOWN"


def test_host_checks_mismatched_release_sha_is_mismatch(monkeypatch):
    expected_head = "1" * 40
    expected_version = real_source_details()["server_version"]
    observed_release_sha = "2" * 40
    runner = active_host_runner(expected_head)
    monkeypatch.setattr(audit.shutil, "which", lambda command: "/bin/systemctl" if command == "systemctl" else None)
    monkeypatch.setattr(audit, "load_canonical_contract", lambda *_: SimpleNamespace(server_version=expected_version))
    patch_release_identity(
        monkeypatch,
        status="MISMATCH",
        matched=False,
        equivalent=False,
        changed_files=["packages/hodlxxi_mcp/src/hodlxxi_mcp/http_server.py"],
        summary="Canonical MCP build inputs changed after the deployed sidecar release.",
    )
    monkeypatch.setattr(
        audit,
        "collect_sidecar_host_items",
        lambda **_: mock_sidecar_host_items(
            expected_head=expected_head,
            expected_version=expected_version,
            release_sha=observed_release_sha,
        ),
    )

    evidence = audit.audit_host_checks(ROOT, runner=runner)

    assert evidence.status == "MISMATCH"
    assert "http_server.py" in " ".join(evidence.details["verdict"]["mismatches"])


def test_host_checks_missing_current_symlink_and_release_sha_is_unknown(monkeypatch):
    expected_head = "1" * 40
    expected_version = real_source_details()["server_version"]
    runner = active_host_runner(expected_head)
    monkeypatch.setattr(audit.shutil, "which", lambda command: "/bin/systemctl" if command == "systemctl" else None)
    monkeypatch.setattr(audit, "load_canonical_contract", lambda *_: SimpleNamespace(server_version=expected_version))
    monkeypatch.setattr(
        audit,
        "collect_sidecar_host_items",
        lambda **_: mock_sidecar_host_items(
            expected_head=expected_head,
            expected_version=expected_version,
            include_current_symlink=False,
            include_release_sha=False,
        ),
    )

    evidence = audit.audit_host_checks(ROOT, runner=runner)

    assert evidence.status == "UNKNOWN"
    assert "mcp_current_symlink" in evidence.details["verdict"]["missing_invariants_for_match"]
    assert "mcp_release_sha" in evidence.details["verdict"]["missing_invariants_for_match"]


def test_host_checks_package_version_equality_alone_cannot_match(monkeypatch):
    expected_head = "1" * 40
    expected_version = real_source_details()["server_version"]
    runner = active_host_runner(expected_head)
    monkeypatch.setattr(audit.shutil, "which", lambda command: "/bin/systemctl" if command == "systemctl" else None)
    monkeypatch.setattr(audit, "load_canonical_contract", lambda *_: SimpleNamespace(server_version=expected_version))
    monkeypatch.setattr(
        audit,
        "collect_sidecar_host_items",
        lambda **_: mock_sidecar_host_items(
            expected_head=expected_head,
            expected_version=expected_version,
            include_current_symlink=False,
            include_release_sha=False,
        ),
    )

    evidence = audit.audit_host_checks(ROOT, runner=runner)

    assert evidence.status == "UNKNOWN"
    assert "mcp_sidecar_package_version" in evidence.details["verdict"]["matched_invariants"]
    assert "mcp_current_symlink" in evidence.details["verdict"]["missing_invariants_for_match"]
    assert "mcp_release_sha" in evidence.details["verdict"]["missing_invariants_for_match"]


def test_host_checks_fully_mocked_all_good_contract_can_match(monkeypatch):
    expected_head = "1" * 40
    expected_version = real_source_details()["server_version"]
    runner = active_host_runner(expected_head)
    monkeypatch.setattr(audit.shutil, "which", lambda command: "/bin/systemctl" if command == "systemctl" else None)
    monkeypatch.setattr(audit, "load_canonical_contract", lambda *_: SimpleNamespace(server_version=expected_version))
    patch_release_identity(monkeypatch)
    monkeypatch.setattr(
        audit,
        "collect_sidecar_host_items",
        lambda **_: mock_sidecar_host_items(
            expected_head=expected_head,
            expected_version=expected_version,
        ),
    )

    evidence = audit.audit_host_checks(ROOT, runner=runner)

    assert evidence.status == "MATCH"
    assert evidence.details["verdict"]["mismatches"] == []
    assert evidence.details["verdict"]["missing_invariants_for_match"] == []
    assert "mcp_current_symlink" in evidence.details["verdict"]["matched_invariants"]
    assert "mcp_release_sha" in evidence.details["verdict"]["matched_invariants"]
