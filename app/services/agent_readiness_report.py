"""Agent Readiness Report v1 self-scan builder.

This module builds a deterministic readiness report for the local HODLXXI
runtime from the Flask route map. It does not perform external network scans,
does not create paid jobs, and does not issue receipts or attestations.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

SCHEMA = "hodlxxi.agent_readiness_report.v1"
REPORT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
DEFAULT_REPORT_DIR = Path("data") / "agent_readiness_reports"

REQUIRED_CHECKS: tuple[dict[str, str], ...] = (
    {
        "id": "well_known_agent_json",
        "title": "Agent descriptor",
        "path": "/.well-known/agent.json",
    },
    {
        "id": "agent_capabilities",
        "title": "Agent capabilities",
        "path": "/agent/capabilities",
    },
    {
        "id": "agent_capabilities_schema",
        "title": "Agent capabilities schema",
        "path": "/agent/capabilities/schema",
    },
    {
        "id": "nostr_dm_policy",
        "title": "Nostr DM policy",
        "path": "/.well-known/nostr-dm-policy.json",
    },
    {
        "id": "public_status",
        "title": "Public runtime status",
        "path": "/api/public/status",
    },
    {
        "id": "health_ready",
        "title": "Operational readiness endpoint",
        "path": "/health/ready",
    },
    {
        "id": "reputation_surface",
        "title": "Public reputation surface",
        "path": "/agent/reputation",
    },
    {
        "id": "attestations_surface",
        "title": "Public attestations surface",
        "path": "/agent/attestations",
    },
    {
        "id": "chain_health_surface",
        "title": "Agent chain health surface",
        "path": "/agent/chain/health",
    },
    {
        "id": "receipt_verification_surface",
        "title": "Receipt verification surface",
        "path": "/agent/verify/<job_id>",
    },
    {
        "id": "report_json_surface",
        "title": "Machine-readable report surface",
        "path": "/reports/<report_id>.json",
    },
    {
        "id": "human_verify_report_surface",
        "title": "Human report verification surface",
        "path": "/verify/report/<report_id>",
    },
)

OPTIONAL_SUPPORTING_SURFACES: tuple[str, ...] = (
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/oauth/jwks.json",
    "/agent/skills",
    "/agent/marketplace/listing",
    "/agent/nostr/announcement",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_origin(base_url: str) -> str:
    return base_url.rstrip("/")


def _route_index(app: Any) -> dict[str, Any]:
    return {str(rule): rule for rule in app.url_map.iter_rules()}


def _rule_methods(rule: Any | None) -> list[str]:
    if rule is None:
        return []
    return sorted(method for method in rule.methods if method not in {"HEAD", "OPTIONS"})


def _build_check(base_url: str, rule_by_path: dict[str, Any], spec: dict[str, str]) -> dict[str, Any]:
    path = spec["path"]
    rule = rule_by_path.get(path)
    route_present = rule is not None
    get_supported = "GET" in _rule_methods(rule)

    status = "pass" if route_present and get_supported else "fail"

    return {
        "id": spec["id"],
        "title": spec["title"],
        "url": f"{base_url}{path}",
        "path": path,
        "method": "GET",
        "status": status,
        "http_status": None,
        "content_type": None,
        "evidence": {
            "route_present": route_present,
            "get_supported": get_supported,
            "endpoint": rule.endpoint if rule is not None else None,
        },
    }


def canonical_report_json(report: dict[str, Any]) -> str:
    """Return the canonical JSON representation used for report hashing."""

    return json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_report_hash(report: dict[str, Any]) -> str:
    """Compute a stable SHA256 hash over a report body.

    The hash intentionally excludes report_sha256 itself so callers may add the
    hash to the report without changing the hash value.
    """

    body = dict(report)
    body.pop("report_sha256", None)
    return sha256(canonical_report_json(body).encode("utf-8")).hexdigest()


def _validate_report_id(report_id: str) -> str:
    rid = str(report_id or "").strip()
    if not REPORT_ID_RE.fullmatch(rid):
        raise ValueError("invalid readiness report_id")
    return rid


def readiness_report_dir(storage_dir: str | Path | None = None) -> Path:
    """Return the local artifact directory for readiness self-scan reports."""

    if storage_dir is not None:
        return Path(storage_dir)

    configured = os.getenv("AGENT_READINESS_REPORT_DIR")
    if configured:
        return Path(configured)

    return DEFAULT_REPORT_DIR


def readiness_report_path(report_id: str, storage_dir: str | Path | None = None) -> Path:
    """Return the safe JSON artifact path for a readiness self-scan report."""

    rid = _validate_report_id(report_id)
    return readiness_report_dir(storage_dir) / f"{rid}.json"


def save_self_readiness_report(report: dict[str, Any], storage_dir: str | Path | None = None) -> Path:
    """Persist a readiness self-scan report as a local public artifact."""

    if report.get("schema") != SCHEMA:
        raise ValueError("unsupported readiness report schema")

    path = readiness_report_path(str(report.get("report_id") or ""), storage_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_report_json(report) + "\n", encoding="utf-8")
    return path


def load_self_readiness_report(
    report_id: str,
    storage_dir: str | Path | None = None,
) -> dict[str, Any] | None:
    """Load a persisted readiness self-scan report, if present."""

    try:
        path = readiness_report_path(report_id, storage_dir)
    except ValueError:
        return None

    if not path.is_file():
        return None

    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    if not isinstance(report, dict) or report.get("schema") != SCHEMA:
        return None

    return report


def build_self_readiness_report(
    app: Any,
    *,
    base_url: str = "https://hodlxxi.com",
    report_id: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a v1 readiness report for the local HODLXXI runtime.

    This function inspects local Flask routes only. It does not make network
    requests and does not create runtime jobs, receipts, or attestations.
    """

    origin = _normalize_origin(base_url)
    generated = generated_at or _utc_now()
    rid = report_id or f"readiness-self-scan-{generated.replace(':', '').replace('-', '')}"

    rule_by_path = _route_index(app)
    checks = [_build_check(origin, rule_by_path, spec) for spec in REQUIRED_CHECKS]

    passed = sum(1 for check in checks if check["status"] == "pass")
    failed = sum(1 for check in checks if check["status"] == "fail")
    warnings = sum(1 for check in checks if check["status"] == "warn")
    score = round((passed / len(checks)) * 100) if checks else 0

    if failed == 0:
        status = "runtime_ready"
    elif passed > 0:
        status = "partial"
    else:
        status = "not_ready"

    report: dict[str, Any] = {
        "schema": SCHEMA,
        "report_id": rid,
        "target": {
            "base_url": origin,
            "normalized_origin": origin,
            "declared_agent_pubkey": None,
            "operator": "HODLXXI",
        },
        "scanner": {
            "service": "HODLXXI",
            "runtime": origin,
            "capabilities_url": "/agent/capabilities",
            "agent_pubkey": None,
        },
        "summary": {
            "status": status,
            "score": score,
            "passed": passed,
            "warnings": warnings,
            "failed": failed,
        },
        "checks": checks,
        "receipt": {
            "status": "not_issued",
            "job_id": None,
            "verify_url": None,
            "request_hash": None,
            "result_hash": None,
            "reason": "self_scan_builder_does_not_create_paid_runtime_job",
        },
        "attestation": {
            "status": "not_issued",
            "attestations_url": "/agent/attestations",
            "latest_attestation_url": "/agent/attestations?limit=1",
            "reputation_url": "/agent/reputation",
            "chain_health_url": "/agent/chain/health",
        },
        "verification": {
            "report_json_url": f"/reports/{rid}.json",
            "human_verify_url": f"/verify/report/{rid}",
            "receipt_verify_url": None,
        },
        "optional_supporting_surfaces": list(OPTIONAL_SUPPORTING_SURFACES),
        "generated_at": generated,
    }
    report["report_sha256"] = compute_report_hash(report)
    return report
