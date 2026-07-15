from __future__ import annotations

import argparse
import ast
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
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
            "evidences": [evidence.to_dict() for evidence in self.evidences],
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
    try:
        if gh_available(runner, root):
            runs = fetch_github_check_runs_via_gh(owner_repo, sha, runner=runner, root=root)
            source = "gh"
        else:
            runs = fetch_github_check_runs_via_http(owner_repo, sha, timeout=timeout)
            source = "public_api"
    except Exception as exc:
        return Evidence(
            name="github_checks",
            status="BLOCKED",
            summary="Unable to query GitHub check runs.",
            details={"error": _bounded_text(str(exc), MAX_SUMMARY_CHARS), "sha": sha},
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
        details={"source": source, "sha": sha, "check_runs": classified},
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
        for index, line in enumerate(lines, start=1):
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
    mismatches: list[str] = []

    try:
        for path in PUBLIC_HTTP_PATHS:
            url = urllib.parse.urljoin(base_url + "/", path.lstrip("/"))
            payload = fetch_public_json(url, timeout=timeout, http=http)
            results.append(payload)
    except VerificationError as exc:
        status = "BLOCKED" if exc.category in {"timeout", "dns", "tls", "network"} else "MISMATCH"
        return Evidence(
            name="discovery",
            status=status,
            summary=f"Public HTTP discovery check failed: {exc.message}",
            details={"results": results},
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
            details={"results": results, "mismatches": mismatches},
        )
    return Evidence(
        name="discovery",
        status="MATCH",
        summary="Public HTTP discovery metadata matches repository source truth.",
        details={"results": results},
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


def audit_registry(*, source_details: dict[str, Any], timeout: float, skip_live: bool) -> Evidence:
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
    try:
        query_url = f"{REGISTRY_SEARCH_URL}?search={urllib.parse.quote(str(expected_name))}"
        payload = fetch_public_json(query_url, timeout=timeout, http=http)
        versions = parse_registry_versions(payload["json"], expected_name=str(expected_name))
    except VerificationError as exc:
        return Evidence(
            name="registry",
            status="BLOCKED" if exc.category in {"timeout", "dns", "tls", "network"} else "MISMATCH",
            summary=f"Registry query failed: {exc.message}",
            details={},
        )
    except Exception as exc:
        return Evidence(
            name="registry",
            status="BLOCKED",
            summary=f"Registry parsing failed: {exc}",
            details={},
        )

    if not versions:
        return Evidence(
            name="registry",
            status="MISMATCH",
            summary=f"Registry entry {expected_name} was not found.",
            details={"versions": []},
        )

    matching_version = next((item for item in versions if item.get("version") == expected_version), None)
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

    status = "MATCH" if not mismatches else "MISMATCH"
    summary = (
        "Registry metadata includes the source MCP version and matching remote metadata."
        if not mismatches
        else "Registry metadata does not yet match the source MCP release metadata."
    )
    return Evidence(
        name="registry",
        status=status,
        summary=summary,
        details={"versions": versions, "mismatches": mismatches},
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

    checks: list[dict[str, Any]] = []
    for service in HOST_CHECK_SERVICES:
        command = ["systemctl", "show", service, *[f"--property={item}" for item in HOST_CHECK_PROPERTIES]]
        result = runner(command, root)
        entry = {"service": service, **command_details(result)}
        if service == "nginx.service":
            entry["stdout"] = redact_nginx_output(entry.get("stdout", ""))
        checks.append(entry)
    return Evidence(
        name="host_checks",
        status="UNKNOWN",
        summary="Optional host checks collected bounded service metadata.",
        details={"services": checks},
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
        for key in ("name", "version", "protocolVersion", "schema", "status", "service_name", "tool_count"):
            if key in payload:
                summary[key] = payload[key]
        if "endpoint" in payload:
            summary["endpoint"] = payload["endpoint"]
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
    version = runner(["gh", "--version"], root)
    auth = runner(["gh", "auth", "status", "-h", "github.com"], root)
    return version.returncode == 0 and auth.returncode == 0


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
        response = runner(command, root)
        if response.returncode != 0:
            raise RuntimeError(response.stderr.strip() or "gh api failed")
        payload = json.loads(response.stdout or "{}")
        batch = payload.get("check_runs", [])
        if not isinstance(batch, list):
            raise ValueError("GitHub check_runs payload is malformed")
        results.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return results


def fetch_github_check_runs_via_http(owner_repo: str, sha: str, *, timeout: float) -> list[dict[str, Any]]:
    http = StdlibHTTPTransport()
    page = 1
    results: list[dict[str, Any]] = []
    while True:
        url = f"https://api.github.com/repos/{owner_repo}/commits/{sha}/check-runs?per_page=100&page={page}"
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "hodlxxi-production-truth-audit/1.0"}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        response = http.open(method="GET", url=url, headers=headers, body=None, timeout=timeout)
        try:
            if response.status < 200 or response.status >= 300:
                raise VerificationError(
                    "http", f"GitHub API returned HTTP {response.status}", http_status=response.status
                )
            payload = _load_json_from_bytes(_read_limited(response), label="GitHub check-runs response")
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
    future_exit_logic = policy.get("future_exit_logic") or []
    lock_heights = sorted(
        [
            int(item["lock_height"])
            for item in future_exit_logic
            if isinstance(item, Mapping) and isinstance(item.get("lock_height"), int)
        ]
    )
    delta_144 = len(lock_heights) >= 2 and (lock_heights[1] - lock_heights[0] == 144)
    funding_status = str(payload.get("funding_status") or payload.get("status") or "unknown")
    cooperative_path = str(policy.get("mode_now") or "") == "cooperative"
    declared_match = declared_address == calculated_address
    capital_proof = funding_status == "funded" and declared_match and delta_144

    mismatches: list[str] = []
    if not declared_match:
        mismatches.append("Declared anchor address does not match calculated P2WSH address")
    if len(lock_heights) >= 2 and not delta_144:
        mismatches.append("Timelock heights are present but do not differ by 144 blocks")

    status = "MATCH" if not mismatches else "MISMATCH"
    summary = (
        "Public covenant declaration is internally consistent; script/address equality is declaration evidence, not funding proof."
        if status == "MATCH"
        else "Public covenant declaration has mismatched script/address or timelock data."
    )
    return {
        "status": status,
        "summary": summary,
        "descriptor": _bounded_text(descriptor_value, MAX_SUMMARY_CHARS),
        "declared_address": declared_address,
        "calculated_address": calculated_address,
        "script_hex": script_hex,
        "lock_heights": lock_heights,
        "delta_144": delta_144,
        "funding_status": funding_status,
        "cooperative_path_present": cooperative_path,
        "time_locked_capital_proof": capital_proof,
        "mismatches": mismatches,
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
        if any(part in EXCLUDED_DIRECTORY_NAMES for part in path.parts):
            continue
        if path.suffix == ".pyc" or path.name.endswith(".egg-info"):
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
        lines.extend(
            [
                f"### {evidence.name}",
                "",
                f"- status: `{evidence.status}`",
                f"- summary: {evidence.summary}",
                f"- mandatory: `{evidence.mandatory}`",
                f"- details: `{json.dumps(evidence.details, sort_keys=True)[:1500]}`",
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
