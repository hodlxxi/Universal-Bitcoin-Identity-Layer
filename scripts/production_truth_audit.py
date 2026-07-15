from __future__ import annotations

import argparse
import ast
import datetime as dt
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.parse
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.mcp_remote_verify import (  # noqa: E402
    DEFAULT_ENDPOINT,
    DEFAULT_TIMEOUT,
    MAX_SUMMARY_CHARS,
    StdlibHTTPTransport,
    VerificationError,
    _bounded_text,
    _content_type,
    _load_assignment_literal,
    _load_assignment_literals,
    _load_json_from_bytes,
    _read_limited,
    load_canonical_contract,
    verify_remote_mcp,
)

SUCCESS_STATUSES = {"VERIFIED", "MATCH", "GREEN"}
ERROR_STATUSES = {"MISMATCH", "RED"}
GIT_REMOTE_NAME = "origin"
REGISTRY_SEARCH_URL = "https://registry.modelcontextprotocol.io/v0.1/servers"
REGISTRY_MAX_ATTEMPTS = 3
REGISTRY_RETRY_BACKOFF_SECONDS = 0.25
PUBLIC_HTTP_PATHS = (
    "/.well-known/mcp.json",
    "/.well-known/agent.json",
    "/agent/capabilities",
    "/agent/discovery",
    "/.well-known/hodlxxi-operator.json",
    "/agent/chain/health",
    "/agent/reputation",
    "/agent/covenants/hodlxxi-herald-covenant-v1.json",
    "/agent/covenant-countdown.json",
    "/api/public/status",
)
HOST_CHECK_SERVICES = ("hodlxxi.service", "hodlxxi-mcp.service", "nginx.service")
HOST_CHECK_PROPERTIES = ("ActiveState", "SubState", "ExecStart", "WorkingDirectory", "FragmentPath", "MainPID")
STALE_PHRASES = (
    "disabled production stub",
    "public transport is disabled",
    "no live /agent/mcp integration",
)
TEXT_FILE_SUFFIXES = {
    ".py",
    ".md",
    ".json",
    ".toml",
    ".yml",
    ".yaml",
    ".txt",
    ".html",
}
EXCLUDED_DIRECTORY_NAMES = {
    ".git",
    "venv",
    ".venv",
    "build",
    "dist",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
}
EXCLUDED_DIRECTORY_MARKERS = {"generated", "vendor", "vendors", "vendored", "third_party", "third-party"}
STALE_SCAN_EXCLUDED_DIRECTORY_NAMES = {
    "tests",
    "fixtures",
    "fixture",
    "__fixtures__",
    "__fixture__",
    "testdata",
    "test_data",
    "mock_data",
    "mock_responses",
}
STALE_SCAN_DETECTOR_ASSIGNMENTS = {"STALE_PHRASES", "STALE_DESCRIPTION_PHRASES"}
ARTIFACT_DROPPED_KEYS = {"json"}
HOST_EVIDENCE_KINDS = {"direct", "inference", "unavailable", "blocked"}
HOST_MCP_CURRENT_SYMLINK = Path("/opt/hodlxxi-mcp/current")
HOST_MCP_RELEASES_DIR = Path("/opt/hodlxxi-mcp/releases")
HOST_NGINX_ROOT = Path("/etc/nginx")
HOST_NGINX_PATHS = (
    HOST_NGINX_ROOT / "nginx.conf",
    HOST_NGINX_ROOT / "conf.d",
    HOST_NGINX_ROOT / "sites-enabled" / "hodlxxi",
    HOST_NGINX_ROOT / "sites-enabled",
)
HOST_MCP_PORT = 8765
HOST_NGINX_MAX_FILES = 64
HOST_NGINX_MAX_FILE_BYTES = 64 * 1024
HOST_NGINX_MAX_SNIPPETS = 20
GITHUB_CHECKS_USER_AGENT = "hodlxxi-production-truth-audit/1.0"
MCP_COMPONENT_SCOPE_PATHS = (
    "packages/hodlxxi_mcp/pyproject.toml",
    "packages/hodlxxi_mcp/README.md",
    "packages/hodlxxi_mcp/src/hodlxxi_mcp",
    "deployment/systemd/hodlxxi-mcp.service",
    "server.json",
)
SENSITIVE_HEADER_RE = re.compile(r"(?im)\b(authorization|cookie|set-cookie)\b(?:\s*[:=]\s*|\s+)[^\n]+")
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b([A-Za-z0-9_-]*(?:token|secret|password|credential|cookie|macaroon|authorization)[A-Za-z0-9_-]*)\b"
    r"(\s*=\s*)([^ \n;]+)"
)
BEARER_TOKEN_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
GITHUB_BAD_CREDENTIALS_RE = re.compile(r"bad credentials|requires authentication|token", re.IGNORECASE)
DATE_CONTEXT_RE = re.compile(
    r"\b(?:20\d{2}-\d{2}-\d{2}|"
    r"Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
    r"Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b"
)
RAW_DESCRIPTOR_RE = re.compile(r"raw\(([0-9A-Fa-f]+)\)")
TAGGED_CHECKSUM_RE = re.compile(r"#([0-9A-Za-z]+)$")
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


@dataclass
class Evidence:
    name: str
    status: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    mandatory: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    repo_root: str
    output_dir: str
    timestamp_utc: str
    status: str
    exit_code: int
    evidences: list[Evidence]
    required_categories: list[str]
    partial: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_root": self.repo_root,
            "output_dir": self.output_dir,
            "timestamp_utc": self.timestamp_utc,
            "status": self.status,
            "exit_code": self.exit_code,
            "partial": self.partial,
            "required_categories": self.required_categories,
            "evidences": [artifact_evidence_dict(evidence) for evidence in self.evidences],
        }


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[Sequence[str], Path | None], CommandResult]


def combine_required(evidence_by_name: Mapping[str, Evidence], required_categories: Sequence[str]) -> tuple[str, bool]:
    missing = [name for name in required_categories if name not in evidence_by_name]
    if missing:
        return "PENDING", True

    statuses = [evidence_by_name[name].status for name in required_categories]
    if all(status in SUCCESS_STATUSES for status in statuses):
        return "VERIFIED", False
    if any(status in ERROR_STATUSES for status in statuses):
        return "MISMATCH", False
    if any(status == "BLOCKED" for status in statuses):
        return "BLOCKED", False
    if any(status == "PENDING" for status in statuses):
        return "PENDING", False
    if any(status == "UNKNOWN" for status in statuses):
        return "UNKNOWN", False
    if any(status == "STALE" for status in statuses):
        return "STALE", False
    return "UNKNOWN", False


def exit_code_for_status(status: str) -> int:
    if status == "VERIFIED":
        return 0
    if status in ERROR_STATUSES:
        return 1
    if status == "BLOCKED":
        return 2
    return 3


def run_audit(
    *,
    repo_root: Path | None = None,
    output_dir: Path | None = None,
    endpoint: str = DEFAULT_ENDPOINT,
    timeout: float = DEFAULT_TIMEOUT,
    skip_live: bool = False,
    host_checks: bool = False,
    runner: Runner | None = None,
) -> AuditReport:
    root = (repo_root or Path(__file__).resolve().parents[1]).resolve()
    source_evidence, source_details = audit_source_contract(root)
    run = runner or default_runner

    evidences = [
        audit_git(root, runner=run),
        audit_github_checks(root, source_details=source_details, runner=run, skip_live=skip_live, timeout=timeout),
        source_evidence,
        audit_stale_references(root),
        audit_discovery(root, source_details=source_details, endpoint=endpoint, timeout=timeout, skip_live=skip_live),
        audit_mcp(root, endpoint=endpoint, timeout=timeout, skip_live=skip_live),
        audit_registry(source_details=source_details, timeout=timeout, skip_live=skip_live),
        audit_covenant(root, endpoint=endpoint, timeout=timeout, skip_live=skip_live),
    ]

    if host_checks:
        evidences.append(audit_host_checks(root, runner=run))

    evidence_by_name = {evidence.name: evidence for evidence in evidences}
    required_categories = [evidence.name for evidence in evidences if evidence.mandatory]
    status, missing = combine_required(evidence_by_name, required_categories)
    if skip_live and status == "VERIFIED":
        status = "PENDING"
        missing = True
    output_path = output_dir or default_output_dir(root)
    report = AuditReport(
        repo_root=str(root),
        output_dir=str(output_path),
        timestamp_utc=utc_now().isoformat().replace("+00:00", "Z"),
        status=status,
        exit_code=exit_code_for_status(status),
        evidences=evidences,
        required_categories=required_categories,
        partial=missing or skip_live,
    )
    write_report_outputs(report)
    return report


def audit_git(root: Path, *, runner: Runner) -> Evidence:
    top_level = runner(["git", "rev-parse", "--show-toplevel"], root)
    if top_level.returncode != 0:
        return Evidence(
            name="git",
            status="BLOCKED",
            summary="Not a Git repository.",
            details={"show_toplevel": command_details(top_level)},
        )

    remote = runner(["git", "remote", "get-url", GIT_REMOTE_NAME], root)
    if remote.returncode != 0:
        return Evidence(
            name="git",
            status="BLOCKED",
            summary="Git remote 'origin' is missing.",
            details={
                "show_toplevel": command_details(top_level),
                "origin": command_details(remote),
            },
        )

    fetch = runner(["git", "fetch", "--prune", GIT_REMOTE_NAME, "main"], root)
    head = runner(["git", "rev-parse", "HEAD"], root)
    origin_main = runner(["git", "rev-parse", "origin/main"], root)
    status_result = runner(["git", "status", "--short"], root)

    details = {
        "show_toplevel": command_details(top_level),
        "origin": command_details(remote),
        "fetch": command_details(fetch),
        "head": command_details(head),
        "origin_main": command_details(origin_main),
        "status": command_details(status_result),
    }

    if head.returncode != 0:
        return Evidence(name="git", status="BLOCKED", summary="Unable to read Git HEAD.", details=details)
    if origin_main.returncode != 0 and fetch.returncode == 0:
        return Evidence(name="git", status="BLOCKED", summary="origin/main is missing.", details=details)
    if fetch.returncode != 0 and origin_main.returncode == 0:
        return Evidence(
            name="git",
            status="STALE",
            summary="Fetch failed; origin/main evidence is stale.",
            details=details,
        )
    if fetch.returncode != 0:
        return Evidence(name="git", status="BLOCKED", summary="Git fetch failed.", details=details)

    head_sha = head.stdout.strip()
    origin_sha = origin_main.stdout.strip()
    dirty = bool(status_result.stdout.strip())

    if head_sha != origin_sha:
        return Evidence(
            name="git",
            status="MISMATCH",
            summary=f"HEAD {head_sha} does not match origin/main {origin_sha}.",
            details=details,
        )
    if dirty:
        return Evidence(
            name="git",
            status="RED",
            summary="Git worktree is dirty.",
            details=details,
        )

    return Evidence(
        name="git",
        status="MATCH",
        summary=f"Clean worktree on origin/main {origin_sha}.",
        details=details,
    )


def audit_github_checks(
    root: Path,
    *,
    source_details: dict[str, Any],
    runner: Runner,
    skip_live: bool,
    timeout: float,
) -> Evidence:
    if skip_live:
        return Evidence(
            name="github_checks",
            status="PENDING",
            summary="GitHub checks skipped by --skip-live.",
            details={},
        )

    repository_url = (
        source_details.get("server_json", {})
        .get("repository", {})
        .get("url", "https://github.com/hodlxxi/Universal-Bitcoin-Identity-Layer")
    )
    owner_repo = parse_github_owner_repo(repository_url)
    head_result = runner(["git", "rev-parse", "HEAD"], root)
    if head_result.returncode != 0:
        return Evidence(
            name="github_checks",
            status="BLOCKED",
            summary="Unable to determine HEAD SHA for GitHub checks.",
            details={"head": command_details(head_result)},
        )

    sha = head_result.stdout.strip()
    transport = "public_http"
    try:
        if gh_available(runner, root):
            try:
                runs = fetch_github_check_runs_via_gh(owner_repo, sha, runner=runner, root=root)
                transport = "gh"
            except (RuntimeError, ValueError, OSError):
                transport, runs = fetch_github_check_runs_via_http(owner_repo, sha, timeout=timeout)
        else:
            transport, runs = fetch_github_check_runs_via_http(owner_repo, sha, timeout=timeout)
    except VerificationError as exc:
        return Evidence(
            name="github_checks",
            status="BLOCKED",
            summary=f"Unable to query GitHub check runs: {exc.message}",
            details={"transport": transport, "sha": sha, "error_category": exc.category},
        )
    except Exception as exc:
        return Evidence(
            name="github_checks",
            status="BLOCKED",
            summary="Unable to query GitHub check runs.",
            details={"transport": transport, "error": _bounded_text(str(exc), MAX_SUMMARY_CHARS), "sha": sha},
        )

    classified = [classify_check_run(run) for run in runs]
    if not classified:
        status = "UNKNOWN"
        summary = "No GitHub check runs were returned."
    elif any(item["audit_status"] == "RED" for item in classified):
        status = "RED"
        summary = "One or more GitHub check runs failed."
    elif any(item["audit_status"] == "PENDING" for item in classified):
        status = "PENDING"
        summary = "One or more GitHub check runs are still pending."
    elif any(item["audit_status"] == "UNKNOWN" for item in classified):
        status = "UNKNOWN"
        summary = "One or more GitHub check runs had unknown status."
    else:
        status = "GREEN"
        summary = "All GitHub check runs completed green."

    return Evidence(
        name="github_checks",
        status=status,
        summary=summary,
        details={"transport": transport, "sha": sha, "check_runs": classified},
    )


def audit_source_contract(root: Path) -> tuple[Evidence, dict[str, Any]]:
    try:
        canonical = load_canonical_contract(root)
        server_json_path = root / "server.json"
        pyproject_path = root / "packages" / "hodlxxi_mcp" / "pyproject.toml"
        discovery_path = root / "app" / "services" / "mcp_discovery.py"
        init_path = root / "packages" / "hodlxxi_mcp" / "src" / "hodlxxi_mcp" / "__init__.py"
        tools_path = root / "packages" / "hodlxxi_mcp" / "src" / "hodlxxi_mcp" / "tools.py"

        server_json = json.loads(server_json_path.read_text(encoding="utf-8"))
        pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        discovery_values = _load_assignment_literals(
            discovery_path,
            {
                "MCP_SERVER_NAME",
                "MCP_SERVER_VERSION",
                "MCP_PROTOCOL_VERSION",
                "MCP_TRANSPORT_TYPE",
                "MCP_ENDPOINT_PATH",
                "MCP_SERVER_CARD_PATH",
                "MCP_TOOL_COUNT",
                "MCP_ACCESS_MODE",
            },
        )
        contract_shape = extract_mcp_contract_shape(discovery_path, discovery_values)
        init_version = _load_assignment_literal(init_path, "__version__")
        tool_names = _load_assignment_literal(tools_path, "TOOL_NAMES")

        details = {
            "server_json": server_json,
            "mcp_package_version": pyproject["project"]["version"],
            "module_version": init_version,
            "server_name": discovery_values["MCP_SERVER_NAME"],
            "server_version": discovery_values["MCP_SERVER_VERSION"],
            "protocol_version": discovery_values["MCP_PROTOCOL_VERSION"],
            "transport": discovery_values["MCP_TRANSPORT_TYPE"],
            "endpoint_path": discovery_values["MCP_ENDPOINT_PATH"],
            "server_card_path": discovery_values["MCP_SERVER_CARD_PATH"],
            "tool_count": discovery_values["MCP_TOOL_COUNT"],
            "tool_names": list(tool_names),
            "access_mode": discovery_values["MCP_ACCESS_MODE"],
            "safety_flags": contract_shape,
        }

        mismatches: list[str] = []
        if server_json["title"] != canonical.server_name:
            mismatches.append("server.json title does not match canonical server name")
        if server_json["version"] != canonical.server_version:
            mismatches.append("server.json version does not match canonical server version")
        if pyproject["project"]["version"] != canonical.server_version:
            mismatches.append("pyproject version does not match canonical server version")
        if init_version != canonical.server_version:
            mismatches.append("__init__.__version__ does not match canonical server version")
        if discovery_values["MCP_TOOL_COUNT"] != len(tool_names):
            mismatches.append("MCP_TOOL_COUNT does not match TOOL_NAMES length")
        if len(tool_names) != canonical.tool_count:
            mismatches.append("canonical TOOL_NAMES length mismatch")
        remote = server_json["remotes"][0]
        if remote["type"] != str(discovery_values["MCP_TRANSPORT_TYPE"]).replace("_", "-"):
            mismatches.append("server.json transport does not match discovery transport")
        if not remote["url"].endswith(str(discovery_values["MCP_ENDPOINT_PATH"])):
            mismatches.append("server.json remote URL does not match endpoint path")
        if contract_shape.get("authentication") != {"type": "none"}:
            mismatches.append("mcp_contract authentication is not the expected public none-auth contract")
        if contract_shape.get("writes_enabled") is not False:
            mismatches.append("mcp_contract writes_enabled must remain false")
        if contract_shape.get("payments_enabled") is not False:
            mismatches.append("mcp_contract payments_enabled must remain false")
        if contract_shape.get("access_mode") != discovery_values["MCP_ACCESS_MODE"]:
            mismatches.append("mcp_contract access_mode does not match MCP_ACCESS_MODE")

        if mismatches:
            return (
                Evidence(
                    name="source_contract",
                    status="MISMATCH",
                    summary="Source MCP contract files are inconsistent.",
                    details={**details, "mismatches": mismatches},
                ),
                details,
            )
        return (
            Evidence(
                name="source_contract",
                status="MATCH",
                summary="Source MCP contract files are internally consistent.",
                details=details,
            ),
            details,
        )
    except Exception as exc:
        details = {"error": _bounded_text(str(exc), MAX_SUMMARY_CHARS)}
        return (
            Evidence(
                name="source_contract", status="BLOCKED", summary="Unable to parse source contract.", details=details
            ),
            details,
        )


def audit_stale_references(root: Path) -> Evidence:
    findings: list[dict[str, Any]] = []
    for path in iter_repo_text_files(root):
        text = path.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        ignored_lines = stale_detector_assignment_lines(path, text)
        for index, line in enumerate(lines, start=1):
            if index in ignored_lines:
                continue
            lowered = line.lower()
            for phrase in STALE_PHRASES:
                if phrase in lowered and not dated_context(lines, index - 1):
                    findings.append(
                        {
                            "path": str(path.relative_to(root)),
                            "line": index,
                            "phrase": phrase,
                            "snippet": _bounded_text(line.strip(), MAX_SUMMARY_CHARS),
                        }
                    )
    if findings:
        return Evidence(
            name="stale_references",
            status="STALE",
            summary="Repository contains stale current-state claims.",
            details={"findings": findings[:50]},
        )
    return Evidence(
        name="stale_references",
        status="MATCH",
        summary="No stale current-state claims were found in repository-controlled text.",
        details={"phrases": list(STALE_PHRASES)},
    )


def audit_discovery(
    root: Path,
    *,
    source_details: dict[str, Any],
    endpoint: str,
    timeout: float,
    skip_live: bool,
) -> Evidence:
    if skip_live:
        return Evidence(
            name="discovery",
            status="PENDING",
            summary="Public HTTP discovery checks skipped by --skip-live.",
            details={},
        )

    http = StdlibHTTPTransport()
    base_url = endpoint.rsplit("/agent/mcp", 1)[0] if endpoint.endswith("/agent/mcp") else "https://hodlxxi.com"
    results: list[dict[str, Any]] = []
    artifact_results: list[dict[str, Any]] = []
    mismatches: list[str] = []

    try:
        for path in PUBLIC_HTTP_PATHS:
            url = urllib.parse.urljoin(base_url + "/", path.lstrip("/"))
            payload = fetch_public_json(url, timeout=timeout, http=http)
            results.append(payload)
            artifact_results.append(public_result_for_artifact(payload))
    except VerificationError as exc:
        status = "BLOCKED" if exc.category in {"timeout", "dns", "tls", "network"} else "MISMATCH"
        return Evidence(
            name="discovery",
            status=status,
            summary=f"Public HTTP discovery check failed: {exc.message}",
            details={"results": artifact_results},
        )

    source_server = source_details.get("server_json", {})
    source_transport = source_details.get("transport")
    source_protocol = source_details.get("protocol_version")
    source_endpoint_path = source_details.get("endpoint_path")
    source_server_card_path = source_details.get("server_card_path")
    server_card = first_result(results, "/.well-known/mcp.json").get("json") or {}
    agent_json = first_result(results, "/.well-known/agent.json").get("json") or {}
    capabilities = first_result(results, "/agent/capabilities").get("json") or {}

    if server_card.get("name") != source_server.get("title"):
        mismatches.append("server card name does not match source metadata")
    if server_card.get("version") != source_server.get("version"):
        mismatches.append("server card version does not match source metadata")
    if server_card.get("protocolVersion") != source_protocol:
        mismatches.append("server card protocolVersion does not match source metadata")
    if server_card.get("tool_count") != source_details.get("tool_count"):
        mismatches.append("server card tool_count does not match source metadata")
    if str((server_card.get("transport") or {}).get("type")) != source_transport:
        mismatches.append("server card transport type does not match source metadata")
    if not str(server_card.get("endpoint") or "").endswith(str(source_endpoint_path)):
        mismatches.append("server card endpoint does not match source endpoint path")

    agent_mcp = (agent_json.get("mcp") or {}) if isinstance(agent_json, dict) else {}
    caps_mcp = (capabilities.get("mcp") or {}) if isinstance(capabilities, dict) else {}
    if agent_mcp.get("server_card") != source_server_card_path:
        mismatches.append("agent.json mcp.server_card does not match source metadata")
    if caps_mcp.get("endpoint") != source_endpoint_path:
        mismatches.append("agent/capabilities mcp.endpoint does not match source metadata")
    if caps_mcp.get("server_version") != source_server.get("version"):
        mismatches.append("agent/capabilities mcp.server_version does not match source metadata")

    if mismatches:
        return Evidence(
            name="discovery",
            status="MISMATCH",
            summary="Public HTTP discovery metadata does not match repository source truth.",
            details={"results": artifact_results, "mismatches": mismatches},
        )
    return Evidence(
        name="discovery",
        status="MATCH",
        summary="Public HTTP discovery metadata matches repository source truth.",
        details={"results": artifact_results},
    )


def audit_mcp(root: Path, *, endpoint: str, timeout: float, skip_live: bool) -> Evidence:
    if skip_live:
        return Evidence(name="mcp", status="PENDING", summary="Live MCP protocol verification skipped by --skip-live.")

    report = verify_remote_mcp(endpoint=endpoint, timeout=timeout, root=root)
    status = {
        "VERIFIED": "VERIFIED",
        "MISMATCH": "MISMATCH",
        "BLOCKED": "BLOCKED",
    }[report.status]
    return Evidence(
        name="mcp",
        status=status,
        summary=f"Remote MCP verifier returned {report.status}.",
        details=report.to_dict(),
    )


def audit_registry(
    *,
    source_details: dict[str, Any],
    timeout: float,
    skip_live: bool,
    http_fetch: Callable[..., dict[str, Any]] | None = None,
    sleeper: Callable[[float], None] | None = None,
    max_attempts: int = REGISTRY_MAX_ATTEMPTS,
) -> Evidence:
    if skip_live:
        return Evidence(name="registry", status="PENDING", summary="Registry query skipped by --skip-live.")

    source_server = source_details.get("server_json", {})
    expected_name = source_server.get("name")
    expected_version = source_server.get("version")
    expected_remote = ((source_server.get("remotes") or [{}])[0]).get("url")
    expected_site = source_server.get("websiteUrl")
    expected_repo = (source_server.get("repository") or {}).get("url")
    expected_subfolder = (source_server.get("repository") or {}).get("subfolder")

    if not expected_name:
        return Evidence(name="registry", status="BLOCKED", summary="Source registry metadata is missing a server name.")

    http = StdlibHTTPTransport()
    fetcher = http_fetch or fetch_public_json
    sleep_fn = sleeper or time.sleep
    attempts = max(1, max_attempts)
    query_url = f"{REGISTRY_SEARCH_URL}?search={urllib.parse.quote(str(expected_name))}"
    attempt_count = 0
    final_error_category: str | None = None
    last_transient_error_category: str | None = None
    transient_error_count = 0
    try:
        while True:
            attempt_count += 1
            try:
                payload = fetcher(query_url, timeout=timeout, http=http)
                break
            except VerificationError as exc:
                final_error_category = exc.category
                if exc.category not in {"timeout", "dns", "tls", "network"} or attempt_count >= attempts:
                    raise
                last_transient_error_category = exc.category
                transient_error_count += 1
                sleep_fn(REGISTRY_RETRY_BACKOFF_SECONDS * attempt_count)
        final_error_category = None
        versions = parse_registry_versions(payload["json"], expected_name=str(expected_name))
    except VerificationError as exc:
        return Evidence(
            name="registry",
            status="BLOCKED" if exc.category in {"timeout", "dns", "tls", "network"} else "MISMATCH",
            summary=f"Registry query failed: {exc.message}",
            details={
                "attempt_count": attempt_count or 1,
                "final_error_category": final_error_category or exc.category,
                "last_transient_error_category": last_transient_error_category,
                "transient_error_count": transient_error_count,
            },
        )
    except Exception as exc:
        return Evidence(
            name="registry",
            status="BLOCKED",
            summary=f"Registry parsing failed: {exc}",
            details={
                "attempt_count": attempt_count or 1,
                "final_error_category": "malformed",
                "last_transient_error_category": last_transient_error_category,
                "transient_error_count": transient_error_count,
            },
        )

    if not versions:
        return Evidence(
            name="registry",
            status="MISMATCH",
            summary=f"Registry entry {expected_name} was not found.",
            details={"versions": []},
        )

    matching_version = next((item for item in versions if item.get("version") == expected_version), None)
    latest_versions = [item for item in versions if item.get("isLatest") is True]
    mismatches: list[str] = []
    if not matching_version:
        mismatches.append(f"Registry does not contain source version {expected_version}")
    else:
        if matching_version.get("remote_url") != expected_remote:
            mismatches.append("Registry remote URL does not match source metadata")
        if matching_version.get("website_url") != expected_site:
            mismatches.append("Registry website URL does not match source metadata")
        if matching_version.get("repository_url") != expected_repo:
            mismatches.append("Registry repository URL does not match source metadata")
        if matching_version.get("subfolder") != expected_subfolder:
            mismatches.append("Registry subfolder does not match source metadata")
        if matching_version.get("isLatest") is not True:
            mismatches.append(f"Source version {expected_version} exists in Registry but is not marked latest")
        if matching_version.get("status") not in {None, "", "active"}:
            mismatches.append(f"Source version {expected_version} is not active in Registry")

    if len(latest_versions) != 1:
        mismatches.append(f"Registry latest-version count must be exactly 1, got {len(latest_versions)}")
    elif latest_versions[0].get("version") != expected_version:
        mismatches.append(
            f"Registry latest version {latest_versions[0].get('version')} does not match source version {expected_version}"
        )

    status = "MATCH" if not mismatches else "MISMATCH"
    summary = (
        "Registry metadata includes the source MCP version as the single latest active release."
        if not mismatches
        else "Registry metadata does not yet match the source MCP release metadata."
    )
    return Evidence(
        name="registry",
        status=status,
        summary=summary,
        details={
            "attempt_count": attempt_count or 1,
            "final_error_category": final_error_category,
            "last_transient_error_category": last_transient_error_category,
            "transient_error_count": transient_error_count,
            "versions": versions,
            "mismatches": mismatches,
        },
    )


def audit_covenant(root: Path, *, endpoint: str, timeout: float, skip_live: bool) -> Evidence:
    if skip_live:
        return Evidence(
            name="covenant",
            status="PENDING",
            summary="Public covenant declaration check skipped by --skip-live.",
            details={},
        )

    http = StdlibHTTPTransport()
    covenant_url = endpoint.rsplit("/agent/mcp", 1)[0] + "/agent/covenants/hodlxxi-herald-covenant-v1.json"
    try:
        payload = fetch_public_json(covenant_url, timeout=timeout, http=http)
    except VerificationError as exc:
        return Evidence(
            name="covenant",
            status="BLOCKED" if exc.category in {"timeout", "dns", "tls", "network"} else "MISMATCH",
            summary=f"Covenant declaration fetch failed: {exc.message}",
            details={},
        )

    try:
        evaluation = evaluate_covenant_payload(payload["json"])
    except Exception as exc:
        return Evidence(name="covenant", status="BLOCKED", summary=f"Covenant evaluation failed: {exc}", details={})

    return Evidence(
        name="covenant",
        status=evaluation["status"],
        summary=evaluation["summary"],
        details=evaluation,
    )


def audit_host_checks(root: Path, *, runner: Runner) -> Evidence:
    if shutil.which("systemctl") is None:
        return Evidence(
            name="host_checks",
            status="BLOCKED",
            summary="systemctl is unavailable for optional host checks.",
            details={},
            mandatory=False,
        )

    items: list[dict[str, Any]] = []
    service_properties: dict[str, dict[str, str]] = {}
    systemd_direct_count = 0
    for service in HOST_CHECK_SERVICES:
        command = ["systemctl", "show", service, *[f"--property={item}" for item in HOST_CHECK_PROPERTIES]]
        result = runner(command, root)
        parsed = parse_systemctl_show_output(result.stdout)
        properties = {
            key: _bounded_text(redact_sensitive_text(str(parsed.get(key) or "")), 240)
            for key in HOST_CHECK_PROPERTIES
            if parsed.get(key)
        }
        service_properties[service] = properties
        if result.returncode == 0:
            systemd_direct_count += 1
        items.append(
            {
                "name": f"systemd:{service}",
                "classification": "direct" if result.returncode == 0 else "blocked",
                "summary": (
                    f"Collected bounded systemd properties for {service}."
                    if result.returncode == 0
                    else f"Unable to inspect {service} via systemctl show."
                ),
                "details": {
                    "service": service,
                    "properties": properties,
                    "returncode": result.returncode,
                    "stderr": _bounded_text(redact_sensitive_text(result.stderr.strip()), 240),
                },
            }
        )

    expected_repo_sha = None
    head_result = runner(["git", "rev-parse", "HEAD"], root)
    if head_result.returncode == 0:
        expected_repo_sha = head_result.stdout.strip()

    expected_mcp_version = None
    try:
        expected_mcp_version = load_canonical_contract(root).server_version
    except Exception:
        expected_mcp_version = None

    items.extend(collect_sidecar_host_items(service_properties=service_properties, runner=runner, root=root))
    verdict = evaluate_host_check_verdict(
        root=root,
        runner=runner,
        items=items,
        service_properties=service_properties,
        expected_mcp_version=expected_mcp_version,
        expected_repo_sha=expected_repo_sha,
        systemd_direct_count=systemd_direct_count,
    )

    classification_counts = {
        kind: sum(1 for item in items if item.get("classification") == kind) for kind in HOST_EVIDENCE_KINDS
    }
    return Evidence(
        name="host_checks",
        status=verdict["status"],
        summary=(
            "Optional host checks collected bounded host evidence "
            f"(direct={classification_counts['direct']}, inference={classification_counts['inference']}, "
            f"unavailable={classification_counts['unavailable']}, blocked={classification_counts['blocked']}); "
            f"host verdict={verdict['status']}."
        ),
        details={"items": items, "verdict": verdict},
        mandatory=False,
    )


def extract_mcp_contract_shape(discovery_path: Path, discovery_values: Mapping[str, Any]) -> dict[str, Any]:
    tree = ast.parse(discovery_path.read_text(encoding="utf-8"), filename=str(discovery_path))
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or node.name != "mcp_contract":
            continue
        for statement in node.body:
            if not isinstance(statement, ast.Return) or not isinstance(statement.value, ast.Dict):
                continue
            result: dict[str, Any] = {}
            for key_node, value_node in zip(statement.value.keys, statement.value.values):
                key = ast.literal_eval(key_node)
                if key in {"authentication", "writes_enabled", "payments_enabled"}:
                    result[str(key)] = ast.literal_eval(value_node)
                elif key == "access_mode":
                    if isinstance(value_node, ast.Name):
                        result["access_mode"] = discovery_values[value_node.id]
            return result
    raise ValueError("Unable to locate mcp_contract return shape")


def artifact_evidence_dict(evidence: Evidence) -> dict[str, Any]:
    return {
        "name": evidence.name,
        "status": evidence.status,
        "summary": evidence.summary,
        "mandatory": evidence.mandatory,
        "details": sanitize_artifact_value(evidence.details),
    }


def sanitize_artifact_value(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text in ARTIFACT_DROPPED_KEYS:
                continue
            if sensitive_key(key_text):
                sanitized[key_text] = "<redacted>"
                continue
            sanitized[key_text] = sanitize_artifact_value(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_artifact_value(item) for item in value[:50]]
    if isinstance(value, str):
        return _bounded_text(redact_sensitive_text(value), 400)
    return value


def sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(
        token in lowered
        for token in ("authorization", "cookie", "token", "secret", "password", "credential", "macaroon")
    )


def public_result_for_artifact(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "path": payload.get("path"),
        "status_code": payload.get("status_code"),
        "content_type": payload.get("content_type"),
        "summary": sanitize_artifact_value(payload.get("summary")),
    }


def stale_detector_assignment_lines(path: Path, text: str) -> set[int]:
    if path.suffix != ".py":
        return set()
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError:
        return set()

    ignored_lines: set[int] = set()
    for node in tree.body:
        target_names: set[str] = set()
        if isinstance(node, ast.Assign):
            target_names = {
                target.id
                for target in node.targets
                if isinstance(target, ast.Name) and target.id in STALE_SCAN_DETECTOR_ASSIGNMENTS
            }
            value_node = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id in STALE_SCAN_DETECTOR_ASSIGNMENTS:
                target_names = {node.target.id}
            value_node = node.value
        else:
            continue

        if not target_names or value_node is None:
            continue

        for child in ast.walk(value_node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                start = getattr(child, "lineno", None)
                end = getattr(child, "end_lineno", start)
                if start is None:
                    continue
                ignored_lines.update(range(start, (end or start) + 1))
    return ignored_lines


def parse_systemctl_show_output(text: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key:
            parsed[key] = value
    return parsed


def redact_sensitive_text(text: str) -> str:
    redacted = SENSITIVE_HEADER_RE.sub(lambda match: f"{match.group(1)}: <redacted>", text)
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(r"\1\2<redacted>", redacted)
    redacted = BEARER_TOKEN_RE.sub("Bearer <redacted>", redacted)
    return redacted


def host_item(name: str, classification: str, summary: str, details: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "classification": classification if classification in HOST_EVIDENCE_KINDS else "blocked",
        "summary": _bounded_text(summary, 240),
        "details": sanitize_artifact_value(dict(details)),
    }


def canonical_current_symlink_target(item: Mapping[str, Any] | None) -> str | None:
    if not item or item.get("classification") != "direct":
        return None
    details = item.get("details", {})
    path = str(details.get("path") or "")
    target = str(details.get("target") or "")
    if path != str(HOST_MCP_CURRENT_SYMLINK) or not target:
        return None
    return target


def canonical_release_sha_from_item(item: Mapping[str, Any] | None, *, expected_target: str | None) -> str | None:
    if not item or item.get("classification") not in {"direct", "inference"}:
        return None
    details = item.get("details", {})
    target = str(details.get("target") or "")
    release_sha = str(details.get("release_sha") or "")
    if not target or not release_sha or not SHA_RE.fullmatch(release_sha):
        return None
    target_path = Path(target)
    if target_path.parent != HOST_MCP_RELEASES_DIR or target_path.name != release_sha:
        return None
    if expected_target and target != expected_target:
        return None
    return release_sha


def canonical_mcp_component_scope_paths(root: Path | None = None) -> list[str]:
    del root
    return list(MCP_COMPONENT_SCOPE_PATHS)


def current_tree_missing_mcp_component_scope_paths(root: Path) -> list[str]:
    return [path for path in canonical_mcp_component_scope_paths() if not (root / path).exists()]


def evaluate_mcp_release_identity(
    *,
    root: Path,
    runner: Runner,
    expected_repo_sha: str | None,
    observed_release_sha: str | None,
) -> dict[str, Any]:
    scope_paths = canonical_mcp_component_scope_paths(root)
    missing_current_paths = current_tree_missing_mcp_component_scope_paths(root)
    details: dict[str, Any] = {
        "status": "UNKNOWN",
        "matched": False,
        "release_commit_exact_match": False,
        "component_source_equivalent": None,
        "component_scope_paths": scope_paths,
        "missing_current_scope_paths": missing_current_paths,
        "component_changed_files": [],
        "release_commit_resolved": False,
        "release_commit_relation": None,
        "observed_release_sha": observed_release_sha,
        "expected_repo_sha": expected_repo_sha,
        "summary": "MCP release identity could not be fully verified.",
    }
    if not expected_repo_sha or not observed_release_sha:
        return details
    if observed_release_sha == expected_repo_sha:
        details.update(
            {
                "status": "MATCH",
                "matched": True,
                "release_commit_exact_match": True,
                "component_source_equivalent": True,
                "release_commit_resolved": True,
                "release_commit_relation": "exact",
                "summary": "MCP release SHA exactly matches the expected repository SHA.",
            }
        )
        return details

    release_commit = verify_git_commit_exists(root, runner, observed_release_sha)
    if release_commit is None:
        details["summary"] = f"MCP release SHA {observed_release_sha} could not be resolved as a Git commit."
        return details
    details["release_commit_resolved"] = True

    expected_commit = verify_git_commit_exists(root, runner, expected_repo_sha)
    if expected_commit is None:
        details["status"] = "BLOCKED"
        details["summary"] = f"Expected repository SHA {expected_repo_sha} could not be resolved as a Git commit."
        return details

    relation = git_commit_relation(root, runner, observed_release_sha, expected_repo_sha)
    details["release_commit_relation"] = relation
    if relation is None:
        details["status"] = "BLOCKED"
        details["summary"] = "MCP release commit could not be compared to the expected repository commit."
        return details

    diff_result = runner(
        ["git", "diff", "--name-only", observed_release_sha, expected_repo_sha, "--", *scope_paths],
        root,
    )
    if diff_result.returncode != 0:
        details["status"] = "BLOCKED"
        details["summary"] = "Unable to diff canonical MCP build inputs between release and expected repository SHAs."
        return details

    changed_files = [line.strip() for line in diff_result.stdout.splitlines() if line.strip()]
    details["component_changed_files"] = changed_files[:20]
    if missing_current_paths:
        details.update(
            {
                "status": "MISMATCH",
                "component_source_equivalent": False,
                "summary": "Canonical MCP build inputs are missing from the current tree.",
            }
        )
        return details
    if not changed_files:
        details.update(
            {
                "status": "MATCH",
                "matched": True,
                "component_source_equivalent": True,
                "summary": "MCP release SHA differs from repository HEAD, but canonical MCP build inputs are unchanged.",
            }
        )
        return details

    details.update(
        {
            "status": "MISMATCH",
            "component_source_equivalent": False,
            "summary": "Canonical MCP build inputs changed after the deployed sidecar release.",
        }
    )
    return details


def verify_git_commit_exists(root: Path, runner: Runner, sha: str) -> str | None:
    result = runner(["git", "rev-parse", "--verify", f"{sha}^{{commit}}"], root)
    return result.stdout.strip() if result.returncode == 0 else None


def git_commit_relation(root: Path, runner: Runner, older_sha: str, newer_sha: str) -> str | None:
    ancestor = runner(["git", "merge-base", "--is-ancestor", older_sha, newer_sha], root)
    if ancestor.returncode == 0:
        return "ancestor"
    if ancestor.returncode > 1:
        return None
    descendant = runner(["git", "merge-base", "--is-ancestor", newer_sha, older_sha], root)
    if descendant.returncode == 0:
        return "descendant"
    if descendant.returncode > 1:
        return None
    merge_base = runner(["git", "merge-base", older_sha, newer_sha], root)
    return "comparable" if merge_base.returncode == 0 and merge_base.stdout.strip() else None


def evaluate_host_check_verdict(
    *,
    root: Path,
    runner: Runner,
    items: Sequence[Mapping[str, Any]],
    service_properties: Mapping[str, Mapping[str, str]],
    expected_mcp_version: str | None,
    expected_repo_sha: str | None,
    systemd_direct_count: int,
) -> dict[str, Any]:
    mismatches: list[str] = []
    matched_invariants: list[str] = []
    blocked_requirements: list[str] = []
    direct_invariant_count = 0

    item_by_name = {str(item.get("name")): item for item in items}

    for service in HOST_CHECK_SERVICES:
        item_name = f"systemd:{service}"
        item = item_by_name.get(item_name)
        if not item or item.get("classification") != "direct":
            blocked_requirements.append(item_name)
            continue
        active_state = str(service_properties.get(service, {}).get("ActiveState") or "")
        sub_state = str(service_properties.get(service, {}).get("SubState") or "")
        if active_state and active_state != "active":
            mismatches.append(f"{service} ActiveState={active_state}")
            continue
        if sub_state in {"failed", "dead", "inactive"}:
            mismatches.append(f"{service} SubState={sub_state}")
            continue
        if active_state == "active":
            matched_invariants.append(item_name)
            direct_invariant_count += 1

    listener_item = item_by_name.get("mcp_loopback_listener")
    if listener_item and listener_item.get("classification") == "direct":
        details = listener_item.get("details", {})
        wildcard_detected = bool(details.get("wildcard_listener_detected"))
        loopback_detected = bool(details.get("loopback_listener_detected"))
        if wildcard_detected:
            mismatches.append("mcp_loopback_listener wildcard listener detected")
        elif not loopback_detected:
            mismatches.append("mcp_loopback_listener missing loopback listener evidence")
        else:
            matched_invariants.append("mcp_loopback_listener")
            direct_invariant_count += 1
    else:
        blocked_requirements.append("mcp_loopback_listener")

    current_symlink_item = item_by_name.get("mcp_current_symlink")
    current_symlink_target = canonical_current_symlink_target(current_symlink_item)
    if current_symlink_target:
        matched_invariants.append("mcp_current_symlink")
        direct_invariant_count += 1
    else:
        blocked_requirements.append("mcp_current_symlink")

    release_sha_item = item_by_name.get("mcp_release_sha")
    observed_release_sha = canonical_release_sha_from_item(
        release_sha_item,
        expected_target=current_symlink_target,
    )
    release_identity = evaluate_mcp_release_identity(
        root=root,
        runner=runner,
        expected_repo_sha=expected_repo_sha,
        observed_release_sha=observed_release_sha,
    )
    if release_identity["matched"]:
        matched_invariants.append("mcp_release_sha")
    elif release_identity["status"] == "MISMATCH":
        mismatches.append(
            "mcp_release_sha differs from the expected component identity "
            f"({observed_release_sha or '?'} vs {expected_repo_sha or '?'}): "
            + str(release_identity["component_changed_files"] or release_identity["summary"])
        )
    else:
        blocked_requirements.append("mcp_release_sha")

    version_item = item_by_name.get("mcp_sidecar_package_version")
    if version_item and version_item.get("classification") == "direct" and expected_mcp_version:
        observed_version = str((version_item.get("details") or {}).get("version") or "")
        if observed_version != expected_mcp_version:
            mismatches.append(
                f"mcp_sidecar_package_version version={observed_version or '?'} expected={expected_mcp_version}"
            )
        else:
            matched_invariants.append("mcp_sidecar_package_version")
            direct_invariant_count += 1
    elif expected_mcp_version:
        blocked_requirements.append("mcp_sidecar_package_version")

    checkout_item = item_by_name.get("flask_service_checkout")
    if checkout_item and checkout_item.get("classification") == "direct" and expected_repo_sha:
        observed_sha = str((checkout_item.get("details") or {}).get("checkout_sha") or "")
        if observed_sha != expected_repo_sha:
            mismatches.append(f"flask_service_checkout checkout_sha={observed_sha or '?'} expected={expected_repo_sha}")
        else:
            matched_invariants.append("flask_service_checkout")
            direct_invariant_count += 1
    elif expected_repo_sha:
        blocked_requirements.append("flask_service_checkout")

    route_item = item_by_name.get("nginx_agent_mcp_route")
    if route_item and route_item.get("classification") == "direct":
        serialized = json.dumps(route_item.get("details", {}), sort_keys=True)
        if "/agent/mcp" not in serialized or "127.0.0.1:8765" not in serialized:
            mismatches.append("nginx_agent_mcp_route missing expected /agent/mcp loopback route evidence")
        else:
            matched_invariants.append("nginx_agent_mcp_route")
            direct_invariant_count += 1
    else:
        blocked_requirements.append("nginx_agent_mcp_route")

    complete_required_invariants = {f"systemd:{service}" for service in HOST_CHECK_SERVICES} | {
        "mcp_current_symlink",
        "mcp_release_sha",
        "mcp_loopback_listener",
        "mcp_sidecar_package_version",
        "flask_service_checkout",
        "nginx_agent_mcp_route",
    }

    matched_required = set(matched_invariants)
    complete_match = complete_required_invariants.issubset(matched_required)

    if mismatches:
        status = "MISMATCH"
    elif complete_match:
        status = "MATCH"
    elif systemd_direct_count == 0 and direct_invariant_count == 0:
        status = "BLOCKED"
    else:
        status = "UNKNOWN"

    return {
        "status": status,
        "matched_invariants": sorted(matched_required),
        "missing_invariants_for_match": sorted(complete_required_invariants - matched_required),
        "blocked_requirements": sorted(set(blocked_requirements)),
        "mismatches": mismatches,
        "release_identity_status": release_identity["status"],
        "release_commit_exact_match": release_identity["release_commit_exact_match"],
        "component_source_equivalent": release_identity["component_source_equivalent"],
        "component_scope_paths": release_identity["component_scope_paths"],
        "component_changed_files": release_identity["component_changed_files"],
        "release_commit_resolved": release_identity["release_commit_resolved"],
        "release_commit_relation": release_identity["release_commit_relation"],
        "observed_release_sha": release_identity["observed_release_sha"],
        "expected_repo_sha": release_identity["expected_repo_sha"],
        "release_identity_summary": release_identity["summary"],
    }


def collect_sidecar_host_items(
    *, service_properties: Mapping[str, Mapping[str, str]], runner: Runner, root: Path
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    current_target: Path | None = None

    if HOST_MCP_CURRENT_SYMLINK.is_symlink():
        current_target = HOST_MCP_CURRENT_SYMLINK.resolve(strict=False)
        items.append(
            host_item(
                "mcp_current_symlink",
                "direct",
                "Captured MCP current release symlink target.",
                {"path": str(HOST_MCP_CURRENT_SYMLINK), "target": str(current_target)},
            )
        )
        release_sha = current_target.name if SHA_RE.fullmatch(current_target.name) else None
        if release_sha and current_target.parent == HOST_MCP_RELEASES_DIR:
            items.append(
                host_item(
                    "mcp_release_sha",
                    "inference",
                    "Derived MCP release SHA from current symlink target.",
                    {"target": str(current_target), "release_sha": release_sha},
                )
            )
        else:
            items.append(
                host_item(
                    "mcp_release_sha",
                    "unavailable",
                    "Current MCP symlink target does not expose a canonical release SHA.",
                    {"target": str(current_target)},
                )
            )
    else:
        items.append(
            host_item(
                "mcp_current_symlink",
                "unavailable",
                "Canonical MCP current symlink is not present on this host.",
                {"path": str(HOST_MCP_CURRENT_SYMLINK)},
            )
        )

    mcp_exec = extract_execstart_path(service_properties.get("hodlxxi-mcp.service", {}).get("ExecStart", ""))
    if mcp_exec:
        items.append(
            host_item(
                "mcp_executable",
                "direct",
                "Captured MCP sidecar executable path from systemd.",
                {"executable": mcp_exec},
            )
        )
    elif current_target is not None:
        items.append(
            host_item(
                "mcp_executable",
                "inference",
                "Inferred MCP sidecar executable path from the current release layout.",
                {"executable": str(current_target / "venv" / "bin" / "hodlxxi-mcp-http")},
            )
        )
    else:
        items.append(host_item("mcp_executable", "unavailable", "MCP executable path is not available.", {}))

    items.append(collect_sidecar_venv_version_item(current_target=current_target, runner=runner, root=root))
    items.append(collect_loopback_listener_item(runner=runner, root=root, port=HOST_MCP_PORT))
    items.append(collect_flask_checkout_item(service_properties=service_properties, runner=runner, root=root))
    items.append(collect_nginx_route_item())
    return items


def extract_execstart_path(value: str) -> str | None:
    if not value:
        return None
    path_match = re.search(r"\bpath=([^ ;]+)", value)
    if path_match:
        return path_match.group(1)
    argv_match = re.search(r"\bargv\[\]=([^ ;]+)", value)
    if argv_match:
        return argv_match.group(1)
    try:
        parts = shlex.split(value)
    except ValueError:
        parts = value.split()
    return parts[0] if parts else None


def collect_sidecar_venv_version_item(*, current_target: Path | None, runner: Runner, root: Path) -> dict[str, Any]:
    if current_target is None:
        return host_item(
            "mcp_sidecar_package_version",
            "unavailable",
            "MCP sidecar virtualenv version is unavailable without a current release path.",
            {},
        )
    venv_python = current_target / "venv" / "bin" / "python"
    if not venv_python.exists():
        return host_item(
            "mcp_sidecar_package_version",
            "unavailable",
            "MCP sidecar virtualenv Python is not present.",
            {"python": str(venv_python)},
        )
    result = runner(
        [
            str(venv_python),
            "-c",
            "import importlib.metadata as m; print(m.version('hodlxxi-mcp'))",
        ],
        root,
    )
    if result.returncode != 0:
        return host_item(
            "mcp_sidecar_package_version",
            "blocked",
            "Unable to read the sidecar virtualenv package version.",
            {"python": str(venv_python), "stderr": result.stderr.strip()},
        )
    return host_item(
        "mcp_sidecar_package_version",
        "direct",
        "Read the sidecar virtualenv package version.",
        {"python": str(venv_python), "version": result.stdout.strip()},
    )


def collect_loopback_listener_item(*, runner: Runner, root: Path, port: int) -> dict[str, Any]:
    commands = [
        ["ss", "-ltnp"],
        ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
        ["netstat", "-ltn"],
    ]
    for command in commands:
        if shutil.which(command[0]) is None:
            continue
        result = runner(command, root)
        if result.returncode != 0:
            return host_item(
                "mcp_loopback_listener",
                "blocked",
                "Unable to inspect loopback listener state for the MCP port.",
                {"command": command, "stderr": result.stderr.strip()},
            )
        listener = summarize_listener_output(result.stdout, port)
        if listener["listener_lines"]:
            return host_item(
                "mcp_loopback_listener",
                "direct",
                "Collected bounded MCP loopback listener evidence.",
                {"command": command, **listener},
            )
        return host_item(
            "mcp_loopback_listener",
            "unavailable",
            "No bounded MCP loopback listener evidence was found in the selected command output.",
            {"command": command, **listener},
        )
    return host_item(
        "mcp_loopback_listener",
        "unavailable",
        "No supported listener-inspection command is available on this host.",
        {"port": port},
    )


def summarize_listener_output(text: str, port: int) -> dict[str, Any]:
    port_text = str(port)
    lines = [line.strip() for line in text.splitlines() if port_text in line]
    bounded_lines = [_bounded_text(redact_sensitive_text(line), 240) for line in lines[:10]]
    has_loopback = any(f"127.0.0.1:{port}" in line or f"[::1]:{port}" in line for line in lines)
    wildcard_detected = any(
        marker in line for line in lines for marker in (f"0.0.0.0:{port}", f"[::]:{port}", f"*:{port}")
    )
    return {
        "listener_lines": bounded_lines,
        "loopback_listener_detected": has_loopback,
        "wildcard_listener_detected": wildcard_detected,
    }


def collect_flask_checkout_item(
    *, service_properties: Mapping[str, Mapping[str, str]], runner: Runner, root: Path
) -> dict[str, Any]:
    properties = service_properties.get("hodlxxi.service", {})
    working_directory = properties.get("WorkingDirectory")
    executable = extract_execstart_path(properties.get("ExecStart", ""))
    details: dict[str, Any] = {
        "working_directory": working_directory,
        "cwd": working_directory,
        "executable": executable,
    }
    if not working_directory:
        return host_item(
            "flask_service_checkout",
            "unavailable",
            "Flask service working directory is unavailable from systemd output.",
            details,
        )
    repo_path = Path(working_directory)
    if (repo_path / ".git").exists():
        checkout = runner(["git", "-C", str(repo_path), "rev-parse", "HEAD"], root)
        if checkout.returncode == 0:
            details["checkout_sha"] = checkout.stdout.strip()
            return host_item(
                "flask_service_checkout",
                "direct",
                "Captured Flask service working directory, executable, and checkout SHA.",
                details,
            )
        details["checkout_error"] = checkout.stderr.strip()
        return host_item(
            "flask_service_checkout",
            "blocked",
            "Flask service checkout SHA could not be read from the declared working directory.",
            details,
        )
    return host_item(
        "flask_service_checkout",
        "inference",
        "Captured Flask service working directory and executable, but no checkout SHA was directly provable.",
        details,
    )


def collect_nginx_route_item(
    *,
    candidates: Sequence[Path] = HOST_NGINX_PATHS,
    nginx_root: Path = HOST_NGINX_ROOT,
    max_files: int = HOST_NGINX_MAX_FILES,
    max_file_bytes: int = HOST_NGINX_MAX_FILE_BYTES,
    max_snippets: int = HOST_NGINX_MAX_SNIPPETS,
) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    unreadable: list[str] = []
    total_snippets = 0
    inspected_files = 0
    for display_path, resolved_path in iter_nginx_candidate_files(
        candidates,
        nginx_root=nginx_root,
        max_files=max_files,
    ):
        inspected_files += 1
        try:
            text = read_bounded_text_file(resolved_path, max_bytes=max_file_bytes)
        except OSError:
            unreadable.append(str(display_path))
            continue
        blocks = extract_nginx_agent_mcp_blocks(text)
        if not blocks:
            continue
        production_candidate = is_production_nginx_path(display_path)
        matched_block = next((block for block in blocks if block["has_upstream"]), None)
        if matched_block and production_candidate:
            remaining = max(0, max_snippets - total_snippets)
            if remaining <= 0:
                break
            snippets = matched_block["snippets"][:remaining]
            matches.append({"path": str(display_path), "snippets": snippets})
            total_snippets += len(snippets)
            continue
        reason = "staging_candidate" if not production_candidate else "missing_same_block_upstream"
        rejected.append(
            {
                "path": str(display_path),
                "reason": reason,
                "snippets": blocks[0]["snippets"][: min(4, max_snippets)],
            }
        )
    if matches:
        return host_item(
            "nginx_agent_mcp_route",
            "direct",
            "Collected bounded nginx /agent/mcp route evidence.",
            {"matches": matches[:10], "inspected_files": inspected_files, "rejected": rejected[:10]},
        )
    if unreadable:
        return host_item(
            "nginx_agent_mcp_route",
            "blocked",
            "nginx configuration paths exist but could not be fully read.",
            {"paths": unreadable[:10], "inspected_files": inspected_files, "rejected": rejected[:10]},
        )
    return host_item(
        "nginx_agent_mcp_route",
        "unavailable",
        "No bounded production nginx /agent/mcp route evidence was found on this host.",
        {"inspected_files": inspected_files, "rejected": rejected[:10]},
    )


def iter_nginx_candidate_files(
    candidates: Sequence[Path],
    *,
    nginx_root: Path,
    max_files: int,
) -> Sequence[tuple[Path, Path]]:
    safe_root = nginx_root.resolve(strict=False)
    files: list[tuple[Path, Path]] = []
    seen_targets: set[str] = set()
    for candidate in candidates:
        if len(files) >= max_files:
            break
        if not candidate.exists() and not candidate.is_symlink():
            continue
        if candidate.is_dir():
            if candidate.is_symlink():
                continue
            for dirpath, dirnames, filenames in os.walk(candidate, followlinks=False):
                dirnames[:] = [name for name in sorted(dirnames) if not (Path(dirpath) / name).is_symlink()]
                for filename in sorted(filenames):
                    if len(files) >= max_files:
                        break
                    maybe_file = Path(dirpath) / filename
                    safe_file = safe_nginx_file_target(maybe_file, safe_root)
                    if safe_file is None:
                        continue
                    safe_key = str(safe_file)
                    if safe_key in seen_targets:
                        continue
                    seen_targets.add(safe_key)
                    files.append((maybe_file, safe_file))
            continue
        safe_file = safe_nginx_file_target(candidate, safe_root)
        if safe_file is None:
            continue
        safe_key = str(safe_file)
        if safe_key in seen_targets:
            continue
        seen_targets.add(safe_key)
        files.append((candidate, safe_file))
    return files[:max_files]


def safe_nginx_file_target(path: Path, nginx_root: Path) -> Path | None:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    try:
        resolved.relative_to(nginx_root)
    except ValueError:
        return None
    return resolved if resolved.is_file() else None


def read_bounded_text_file(path: Path, *, max_bytes: int) -> str:
    with path.open("rb") as handle:
        payload = handle.read(max_bytes + 1)
    return payload[:max_bytes].decode("utf-8", errors="ignore")


def is_production_nginx_path(path: Path) -> bool:
    return "staging" not in str(path).lower()


def extract_nginx_agent_mcp_blocks(text: str) -> list[dict[str, Any]]:
    lines = text.splitlines()
    blocks: list[dict[str, Any]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if "/agent/mcp" not in line or "location" not in line:
            index += 1
            continue
        block_lines = [line]
        brace_depth = line.count("{") - line.count("}")
        index += 1
        while index < len(lines):
            block_line = lines[index]
            block_lines.append(block_line)
            brace_depth += block_line.count("{") - block_line.count("}")
            index += 1
            if brace_depth <= 0:
                break
        blocks.append(
            {
                "has_location": True,
                "has_upstream": any(
                    "proxy_pass" in block_line and "127.0.0.1:8765/mcp" in block_line for block_line in block_lines
                ),
                "snippets": bounded_nginx_snippets(block_lines),
            }
        )
    return blocks


def bounded_nginx_snippets(lines: Sequence[str]) -> list[str]:
    markers = ("/agent/mcp", "127.0.0.1:8765", "proxy_pass", "upstream", "authorization", "cookie")
    snippets: list[str] = []
    seen: set[str] = set()
    for line in lines:
        if not any(marker in line.lower() for marker in markers):
            continue
        cleaned = _bounded_text(redact_sensitive_text(line.strip()), 240)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            snippets.append(cleaned)
        if len(snippets) >= 12:
            break
    return snippets


def extract_nginx_agent_mcp_evidence(text: str) -> list[str]:
    snippets: list[str] = []
    seen: set[str] = set()
    for block in extract_nginx_agent_mcp_blocks(text):
        for snippet in block["snippets"]:
            if snippet not in seen:
                seen.add(snippet)
                snippets.append(snippet)
            if len(snippets) >= 12:
                return snippets[:12]
    return snippets[:12]


def fetch_public_json(url: str, *, timeout: float, http: StdlibHTTPTransport) -> dict[str, Any]:
    response = http.open(
        method="GET",
        url=url,
        headers={"Accept": "application/json, application/linkset+json"},
        body=None,
        timeout=timeout,
    )
    try:
        content_type = _content_type(response.headers)
        if response.status < 200 or response.status >= 300:
            raise VerificationError("http", f"{url} returned HTTP {response.status}", http_status=response.status)
        if content_type not in {"application/json", "application/linkset+json"}:
            raise VerificationError(
                "http", f"{url} returned unexpected content type {content_type}", http_status=response.status
            )
        raw = _read_limited(response)
        payload = _load_json_from_bytes(raw, label=url)
        return {
            "path": urllib.parse.urlsplit(url).path,
            "url": url,
            "status_code": response.status,
            "content_type": content_type,
            "json": payload,
            "summary": summarize_public_payload(payload),
        }
    finally:
        response.close()


def summarize_public_payload(payload: Any) -> Any:
    if isinstance(payload, dict):
        summary: dict[str, Any] = {}
        for key in (
            "name",
            "version",
            "protocolVersion",
            "schema",
            "status",
            "service_name",
            "tool_count",
            "enabled",
            "availability",
            "funding_status",
            "created_at",
        ):
            if key in payload:
                summary[key] = payload[key]
        if "endpoint" in payload:
            summary["endpoint"] = payload["endpoint"]
        if "anchor" in payload and isinstance(payload["anchor"], dict):
            summary["anchor"] = {"address": payload["anchor"].get("address")}
        if "mcp" in payload and isinstance(payload["mcp"], dict):
            summary["mcp"] = {
                key: payload["mcp"].get(key)
                for key in (
                    "endpoint",
                    "server_card",
                    "server_name",
                    "server_version",
                    "protocol_version",
                    "tool_count",
                )
                if key in payload["mcp"]
            }
        return summary
    if isinstance(payload, list):
        return {"count": len(payload)}
    return None


def first_result(results: Sequence[dict[str, Any]], path: str) -> dict[str, Any]:
    for item in results:
        if item.get("path") == path:
            return item
    return {}


def parse_github_owner_repo(repository_url: str) -> str:
    match = re.search(r"github\.com[:/]+([^/]+/[^/.]+)", repository_url)
    if not match:
        raise ValueError(f"Unrecognized GitHub repository URL: {repository_url}")
    return match.group(1)


def gh_available(runner: Runner, root: Path) -> bool:
    if shutil.which("gh") is None:
        return False
    try:
        auth = runner(["gh", "auth", "status", "-h", "github.com"], root)
    except (FileNotFoundError, OSError):
        return False
    return auth.returncode == 0


def fetch_github_check_runs_via_gh(owner_repo: str, sha: str, *, runner: Runner, root: Path) -> list[dict[str, Any]]:
    page = 1
    results: list[dict[str, Any]] = []
    while True:
        command = [
            "gh",
            "api",
            "-H",
            "Accept: application/vnd.github+json",
            f"repos/{owner_repo}/commits/{sha}/check-runs?per_page=100&page={page}",
        ]
        try:
            response = runner(command, root)
        except (FileNotFoundError, OSError) as exc:
            raise RuntimeError(str(exc)) from exc
        if response.returncode != 0:
            raise RuntimeError(response.stderr.strip() or "gh api failed")
        try:
            payload = json.loads(response.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise ValueError("GitHub CLI returned malformed JSON") from exc
        batch = payload.get("check_runs", [])
        if not isinstance(batch, list):
            raise ValueError("GitHub check_runs payload is malformed")
        results.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return results


def fetch_github_check_runs_via_http(owner_repo: str, sha: str, *, timeout: float) -> tuple[str, list[dict[str, Any]]]:
    http = StdlibHTTPTransport()
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        try:
            return "authenticated_http", _fetch_github_check_runs_http_pages(
                owner_repo,
                sha,
                timeout=timeout,
                http=http,
                token=token,
            )
        except VerificationError as exc:
            if not is_github_auth_failure(exc):
                raise
    return "public_http", _fetch_github_check_runs_http_pages(owner_repo, sha, timeout=timeout, http=http, token=None)


def _fetch_github_check_runs_http_pages(
    owner_repo: str,
    sha: str,
    *,
    timeout: float,
    http: StdlibHTTPTransport,
    token: str | None,
) -> list[dict[str, Any]]:
    page = 1
    results: list[dict[str, Any]] = []
    while True:
        url = f"https://api.github.com/repos/{owner_repo}/commits/{sha}/check-runs?per_page=100&page={page}"
        headers = {"Accept": "application/vnd.github+json", "User-Agent": GITHUB_CHECKS_USER_AGENT}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        response = http.open(method="GET", url=url, headers=headers, body=None, timeout=timeout)
        try:
            payload_bytes = _read_limited(response)
            if response.status < 200 or response.status >= 300:
                raise classify_github_http_error(
                    response.status, response.headers, payload_bytes, token_present=token is not None
                )
            payload = _load_json_from_bytes(payload_bytes, label="GitHub check-runs response")
        finally:
            response.close()
        batch = payload.get("check_runs", [])
        if not isinstance(batch, list):
            raise ValueError("GitHub check_runs payload is malformed")
        results.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return results


def classify_github_http_error(
    status: int,
    headers: Mapping[str, str],
    payload_bytes: bytes,
    *,
    token_present: bool,
) -> VerificationError:
    payload = try_load_json_bytes(payload_bytes)
    message = (
        str(payload.get("message") or f"GitHub API returned HTTP {status}")
        if payload
        else f"GitHub API returned HTTP {status}"
    )
    remaining = str(headers.get("x-ratelimit-remaining", ""))
    if status == 429 or remaining == "0" or "rate limit" in message.lower():
        return VerificationError("rate_limit", message, http_status=status)
    if token_present and status in {401, 403} and GITHUB_BAD_CREDENTIALS_RE.search(message):
        return VerificationError("auth", message, http_status=status)
    return VerificationError("http", message, http_status=status)


def try_load_json_bytes(payload_bytes: bytes) -> dict[str, Any] | None:
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def is_github_auth_failure(exc: VerificationError) -> bool:
    return exc.category == "auth" or (
        exc.category == "http" and exc.http_status in {401, 403} and GITHUB_BAD_CREDENTIALS_RE.search(exc.message or "")
    )


def classify_check_run(run: Mapping[str, Any]) -> dict[str, Any]:
    name = str(run.get("name") or "unknown")
    status = str(run.get("status") or "unknown")
    conclusion = run.get("conclusion")
    if conclusion in {"failure", "timed_out", "cancelled", "action_required", "startup_failure", "stale"}:
        audit_status = "RED"
    elif status in {"queued", "in_progress", "waiting", "requested", "pending"}:
        audit_status = "PENDING"
    elif conclusion in {"success", "neutral", "skipped"}:
        audit_status = "GREEN"
    elif status == "completed" and conclusion is None:
        audit_status = "UNKNOWN"
    else:
        audit_status = "UNKNOWN"
    return {
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "started_at": run.get("started_at"),
        "completed_at": run.get("completed_at"),
        "details_url": run.get("details_url"),
        "audit_status": audit_status,
    }


def parse_registry_versions(payload: Any, *, expected_name: str) -> list[dict[str, Any]]:
    items: list[Mapping[str, Any]]
    if isinstance(payload, list):
        items = [item for item in payload if isinstance(item, Mapping)]
    elif isinstance(payload, dict):
        if isinstance(payload.get("servers"), list):
            items = [item for item in payload["servers"] if isinstance(item, Mapping)]
        elif isinstance(payload.get("items"), list):
            items = [item for item in payload["items"] if isinstance(item, Mapping)]
        elif isinstance(payload.get("results"), list):
            items = [item for item in payload["results"] if isinstance(item, Mapping)]
        elif "name" in payload:
            items = [payload]
        else:
            items = []
    else:
        items = []

    matches: list[tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]] = []
    for item in items:
        server = item.get("server") if isinstance(item.get("server"), Mapping) else item
        meta = ((item.get("_meta") or {}) if isinstance(item.get("_meta"), Mapping) else {}).get(
            "io.modelcontextprotocol.registry/official", {}
        )
        if not isinstance(server, Mapping):
            continue
        if str(server.get("name")) == expected_name:
            matches.append((item, server, meta if isinstance(meta, Mapping) else {}))
    versions: list[dict[str, Any]] = []
    for item, server, meta in matches:
        if isinstance(server.get("versions"), list):
            for version_item in server["versions"]:
                if not isinstance(version_item, Mapping):
                    continue
                versions.append(normalize_registry_version(server, version_item, meta))
        else:
            versions.append(normalize_registry_version(server, server, meta))
    return versions


def normalize_registry_version(
    parent: Mapping[str, Any], item: Mapping[str, Any], meta: Mapping[str, Any]
) -> dict[str, Any]:
    repository = item.get("repository") or parent.get("repository") or {}
    remote = item.get("remote") or item.get("remotes") or parent.get("remote") or parent.get("remotes")
    remote_url = None
    if isinstance(remote, Mapping):
        remote_url = remote.get("url")
    elif isinstance(remote, list) and remote and isinstance(remote[0], Mapping):
        remote_url = remote[0].get("url")
    return {
        "version": item.get("version") or parent.get("version"),
        "isLatest": item.get("isLatest", parent.get("isLatest", meta.get("isLatest"))),
        "status": item.get("status", parent.get("status", meta.get("status"))),
        "publishedAt": item.get("publishedAt", parent.get("publishedAt", meta.get("publishedAt"))),
        "remote_url": remote_url,
        "website_url": item.get("websiteUrl", parent.get("websiteUrl")),
        "repository_url": repository.get("url") if isinstance(repository, Mapping) else None,
        "subfolder": repository.get("subfolder") if isinstance(repository, Mapping) else None,
    }


def evaluate_covenant_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    descriptor_value = str(
        ((payload.get("descriptor") or {}) if isinstance(payload.get("descriptor"), dict) else {}).get("value") or ""
    )
    anchor = payload.get("anchor") if isinstance(payload.get("anchor"), Mapping) else {}
    declared_address = str(anchor.get("address") or "")
    script_hex = extract_raw_script_hex(descriptor_value)
    calculated_address = p2wsh_address_from_script(script_hex, hrp="bc")
    policy = payload.get("policy") if isinstance(payload.get("policy"), Mapping) else {}
    future_exit_logic = policy.get("future_exit_logic") if isinstance(policy.get("future_exit_logic"), list) else []
    timelock_paths = [
        item
        for item in future_exit_logic
        if isinstance(item, Mapping) and str(item.get("type") or "") == "timelocked_path"
    ]
    lock_heights = sorted(
        [int(item["lock_height"]) for item in timelock_paths if isinstance(item.get("lock_height"), int)]
    )
    required_lock_height_count = 2 if str(policy.get("mode_now") or "") == "cooperative" or timelock_paths else 0
    delta_144 = len(lock_heights) >= 2 and (lock_heights[1] - lock_heights[0] == 144)
    declared_funding_status = str(payload.get("funding_status") or payload.get("status") or "unknown")
    cooperative_path = str(policy.get("mode_now") or "") == "cooperative"
    declared_match = declared_address == calculated_address
    utxo_evidence_checked = False
    utxo_evidence_verified = False
    timelock_structure_valid = (
        declared_match
        and len(lock_heights) >= required_lock_height_count
        and (required_lock_height_count < 2 or delta_144)
    )
    declared_funding_lower = declared_funding_status.lower()
    funding_declared = declared_funding_lower == "funded" or declared_funding_lower.startswith("funded_")
    funding_claim_status = "UNVERIFIED" if funding_declared and not utxo_evidence_verified else "DECLARED_ONLY"
    time_locked_capital_proof = False

    mismatches: list[str] = []
    warnings: list[str] = []
    if not declared_match:
        mismatches.append("Declared anchor address does not match calculated P2WSH address")
    if required_lock_height_count and len(lock_heights) < required_lock_height_count:
        mismatches.append("Required covenant lock-height data is incomplete")
    if len(lock_heights) >= 2 and not delta_144:
        mismatches.append("Timelock heights are present but do not differ by 144 blocks")
    if funding_declared and not utxo_evidence_checked:
        warnings.append("Funding is self-declared only; no direct UTXO evidence was checked")
    if cooperative_path:
        warnings.append("Immediate cooperative path is present, so the capital is not exclusively time-locked")

    if mismatches:
        status = "MISMATCH"
        summary = "Public covenant declaration has mismatched script/address or incomplete timelock data."
    elif funding_declared and not utxo_evidence_verified:
        status = "UNKNOWN"
        summary = (
            "Public covenant declaration is structurally consistent, but any funding claim remains unverified "
            "without direct UTXO evidence."
        )
    else:
        status = "MATCH"
        summary = (
            "Public covenant declaration is internally consistent; script/address equality is declaration evidence, "
            "not funding proof."
        )
    return {
        "status": status,
        "summary": summary,
        "descriptor": _bounded_text(descriptor_value, MAX_SUMMARY_CHARS),
        "declared_address": declared_address,
        "calculated_address": calculated_address,
        "script_hex": script_hex,
        "lock_heights": lock_heights,
        "required_lock_height_count": required_lock_height_count,
        "delta_144": delta_144,
        "declared_funding_status": declared_funding_status,
        "funding_claim_status": funding_claim_status,
        "utxo_evidence_checked": utxo_evidence_checked,
        "utxo_evidence_verified": utxo_evidence_verified,
        "cooperative_path_present": cooperative_path,
        "timelock_structure_valid": timelock_structure_valid,
        "time_locked_capital_proof": time_locked_capital_proof,
        "mismatches": mismatches,
        "warnings": warnings,
    }


def extract_raw_script_hex(descriptor: str) -> str:
    cleaned = TAGGED_CHECKSUM_RE.sub("", descriptor.strip())
    match = RAW_DESCRIPTOR_RE.search(cleaned)
    if not match:
        raise ValueError("Descriptor does not contain raw(<hex>) witness script")
    return match.group(1).lower()


def p2wsh_address_from_script(script_hex: str, *, hrp: str) -> str:
    script = bytes.fromhex(script_hex)
    witness_program = hashlib_sha256(script)
    return segwit_encode(hrp, 0, witness_program)


def hashlib_sha256(payload: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(payload).digest()


def segwit_encode(hrp: str, witver: int, witprog: bytes) -> str:
    data = [witver, *convertbits(witprog, 8, 5, True)]
    combined = data + bech32_create_checksum(hrp, data, bech32m=witver != 0)
    return hrp + "1" + "".join(BECH32_CHARSET[item] for item in combined)


def convertbits(data: bytes, from_bits: int, to_bits: int, pad: bool) -> list[int]:
    acc = 0
    bits = 0
    result: list[int] = []
    maxv = (1 << to_bits) - 1
    for value in data:
        if value < 0 or value >> from_bits:
            raise ValueError("invalid convertbits input")
        acc = (acc << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((acc >> bits) & maxv)
    if pad:
        if bits:
            result.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        raise ValueError("invalid convertbits padding")
    return result


def bech32_create_checksum(hrp: str, data: list[int], *, bech32m: bool) -> list[int]:
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ (0x2BC830A3 if bech32m else 1)
    return [(polymod >> 5 * (5 - index)) & 31 for index in range(6)]


def bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def bech32_polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for index in range(5):
            if (top >> index) & 1:
                chk ^= generator[index]
    return chk


def iter_repo_text_files(root: Path) -> Sequence[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        lowered_parts = {part.lower() for part in path.relative_to(root).parts}
        if any(part in EXCLUDED_DIRECTORY_NAMES for part in lowered_parts):
            continue
        if any(part.endswith(".egg-info") for part in lowered_parts):
            continue
        if any(part in EXCLUDED_DIRECTORY_MARKERS for part in lowered_parts):
            continue
        if any(part in STALE_SCAN_EXCLUDED_DIRECTORY_NAMES for part in lowered_parts):
            continue
        if path.suffix == ".pyc":
            continue
        if path.suffix and path.suffix not in TEXT_FILE_SUFFIXES:
            continue
        files.append(path)
    return files


def dated_context(lines: Sequence[str], index: int) -> bool:
    start = max(0, index - 2)
    end = min(len(lines), index + 3)
    context = "\n".join(lines[start:end])
    return bool(DATE_CONTEXT_RE.search(context))


def command_details(result: CommandResult) -> dict[str, Any]:
    return {
        "returncode": result.returncode,
        "stdout": _bounded_text(result.stdout.strip(), 400),
        "stderr": _bounded_text(result.stderr.strip(), 400),
    }


def redact_nginx_output(text: str) -> str:
    lines = []
    for line in text.splitlines():
        if line.startswith("ExecStart="):
            value = line.split("=", 1)[1]
            value = value.split()[0] if value else value
            lines.append(f"ExecStart={Path(value).name}" if value else "ExecStart=")
        else:
            lines.append(_bounded_text(line, 200))
    return "\n".join(lines)


def default_runner(command: Sequence[str], cwd: Path | None) -> CommandResult:
    completed = subprocess.run(
        list(command),
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=False,
    )
    return CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def default_output_dir(root: Path) -> Path:
    timestamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    candidate = Path(tempfile.gettempdir()) / f"hodlxxi-production-truth-audit-{timestamp}"
    return candidate if not str(candidate).startswith(str(root)) else Path(tempfile.gettempdir()) / f"audit-{timestamp}"


def write_report_outputs(report: AuditReport) -> None:
    output_dir = Path(report.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.json").write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "REPORT.md").write_text(render_markdown_report(report) + "\n", encoding="utf-8")


def render_markdown_report(report: AuditReport) -> str:
    lines = [
        "# Production Truth Audit",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Status | `{report.status}` |",
        f"| Exit code | `{report.exit_code}` |",
        f"| Timestamp (UTC) | `{report.timestamp_utc}` |",
        f"| Repo root | `{report.repo_root}` |",
        f"| Output dir | `{report.output_dir}` |",
        f"| Partial | `{report.partial}` |",
        "",
        "## Evidence",
        "",
    ]
    for evidence in report.evidences:
        sanitized_details = sanitize_artifact_value(evidence.details)
        lines.extend(
            [
                f"### {evidence.name}",
                "",
                f"- status: `{evidence.status}`",
                f"- summary: {evidence.summary}",
                f"- mandatory: `{evidence.mandatory}`",
                f"- details: `{json.dumps(sanitized_details, sort_keys=True)[:1500]}`",
                "",
            ]
        )
    return "\n".join(lines)


def render_terminal_report(report: AuditReport) -> str:
    summary_lines = [
        f"status={report.status}",
        f"exit_code={report.exit_code}",
        f"output_dir={report.output_dir}",
    ]
    for evidence in report.evidences:
        summary_lines.append(f"{evidence.name}={evidence.status} {evidence.summary}")
    return "\n".join(summary_lines)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit HODLXXI production-truth evidence.")
    parser.add_argument("--output-dir")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--skip-live", action="store_true")
    parser.add_argument("--host-checks", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    report = run_audit(
        output_dir=Path(args.output_dir).resolve() if args.output_dir else None,
        endpoint=args.endpoint,
        timeout=args.timeout,
        skip_live=args.skip_live,
        host_checks=args.host_checks,
    )
    print(render_terminal_report(report))
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
