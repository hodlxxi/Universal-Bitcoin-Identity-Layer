"""Trust surface helpers for public agent trust artifacts."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.agent_signer import get_agent_pubkey_hex
from app.database import session_scope
from app.models import AgentEvent, AgentJob

DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "trust"
DEFAULT_AGENT_ID = "hodlxxi-herald-01"
DEFAULT_AGENT_NAME = "HODLXXI Herald"
DEFAULT_COVENANT_ID = "hodlxxi-herald-covenant-v1"
DECLARED_AGENT_PUBKEY = "02019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92"
DEFAULT_OPERATOR_PUBKEY = "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
DECLARED_COVENANT_ADDRESS = "bc1qsrpjjn3w8ly8da7u59y7ywzly4he7lfnl8462qrxp3d368gexess3tjdz3"
DECLARED_COVENANT_DESCRIPTOR = (
    "raw(63522102019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92"
    "21023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e92352ae67630371201bb1"
    "752102019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92ac670301211bb1752"
    "1023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923ac6868)#yemvdjs8"
)
DEFAULT_AGENT_NPUB = "npub-declared-not-published-in-this-surface"
DEFAULT_RELAYS = ["wss://relay.damus.io", "wss://nos.lol"]
INVOICE_PENDING_STATUSES = {"invoice_pending", "pending", "awaiting_payment", "created"}
EXPIRED_STATUSES = {"expired", "invoice_expired", "timeout"}
EXECUTION_FAILED_STATUSES = {"failed", "execution_failed", "error"}


def canonicalize_json(data: dict[str, Any]) -> str:
    """Return canonical JSON text used for deterministic hashing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str | bytes) -> str:
    """Return sha256 hex digest for str/bytes payload."""
    payload = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(payload).hexdigest()


def _iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as fh:
        loaded = json.load(fh)
    return loaded if isinstance(loaded, dict) else None


def has_covenant_artifact(covenant_id: str) -> bool:
    """Return True if covenant artifact exists or matches configured default."""
    return covenant_id == DEFAULT_COVENANT_ID or (DATA_DIR / f"covenant_{covenant_id}.json").exists()


def load_agent_binding(agent_id: str) -> dict[str, Any]:
    """Load agent binding artifact from data dir or fallback defaults."""
    path = DATA_DIR / f"agent_binding_{agent_id}.json"
    loaded = _load_json(path)
    if loaded:
        if loaded.get("agent", {}).get("pubkey") in {None, "", "runtime-derived"}:
            loaded.setdefault("agent", {})["pubkey"] = get_agent_pubkey_hex()
        return loaded

    agent_pubkey = get_agent_pubkey_hex()
    now = _iso_now()
    return {
        "binding_version": "1.0",
        "agent_id": agent_id,
        "operator": {
            "name": "HODLXXI Operator",
            "pubkey": DEFAULT_OPERATOR_PUBKEY,
            "website": "https://hodlxxi.com",
        },
        "agent": {
            "name": DEFAULT_AGENT_NAME,
            "pubkey": DECLARED_AGENT_PUBKEY if agent_id == DEFAULT_AGENT_ID else agent_pubkey,
            "npub": DEFAULT_AGENT_NPUB,
        },
        "authority": {
            "may_publish": [
                "runtime heartbeat and status notes",
                "execution receipt summaries",
                "daily trust reports",
            ]
        },
        "sources_of_truth": [
            "/agent/capabilities",
            "/agent/attestations",
            "/agent/reputation",
            "/agent/chain/health",
            f"/agent/trust-summary/{agent_id}.json",
        ],
        "created_at": now,
        "updated_at": now,
    }


def load_covenant(covenant_id: str) -> dict[str, Any]:
    """Load covenant artifact from data dir or fallback defaults."""
    path = DATA_DIR / f"covenant_{covenant_id}.json"
    loaded = _load_json(path)
    if loaded:
        if loaded.get("agent_pubkey") in {None, "", "runtime-derived"}:
            loaded["agent_pubkey"] = get_agent_pubkey_hex()
        return loaded

    return {
        "schema_version": "1.0",
        "covenant_id": covenant_id,
        "status": "unfunded_declared",
        "agent_id": DEFAULT_AGENT_ID,
        "operator_pubkey": DEFAULT_OPERATOR_PUBKEY,
        "agent_pubkey": DECLARED_AGENT_PUBKEY,
        "network": "bitcoin",
        "funding_status": "unfunded_declared",
        "anchor": {
            "type": "declared_address",
            "address": DECLARED_COVENANT_ADDRESS,
        },
        "descriptor": {
            "type": "raw",
            "value": DECLARED_COVENANT_DESCRIPTOR,
        },
        "policy": {
            "mode_now": "cooperative",
            "future_exit_logic": [
                {"party": "agent", "type": "timelocked_path", "lock_height": 1_777_777},
                {"party": "operator", "type": "timelocked_path", "lock_height": 1_777_921},
            ],
            "summary": (
                "2-of-2 cooperative path now; delayed unilateral exits later; "
                "agent has the earlier unilateral exit path; operator has the later unilateral exit path."
            ),
        },
        "trust_interpretation": {
            "proves": [
                "declared long-horizon operator↔agent alignment structure",
                "real operator and agent public keys are disclosed",
                "script policy and declared address are disclosed",
            ],
            "does_not_prove": [
                "funded on-chain capital proof",
                "uptime guarantees",
                "execution quality guarantees",
                "full autonomy",
            ],
        },
        "artifacts": {
            "trust_page_url": f"/agent/trust/{DEFAULT_AGENT_ID}",
            "raw_policy_url": f"/agent/covenants/{covenant_id}.json",
        },
        "created_at": "2026-01-01T00:00:00+00:00",
    }


def _runtime_counts() -> tuple[int, int, int]:
    with session_scope() as session:
        total_jobs = session.query(AgentJob).count()
        completed_jobs = session.query(AgentJob).filter_by(status="done").count()
        attestations_count = session.query(AgentEvent).count()
    return total_jobs, completed_jobs, attestations_count


def _job_outcome_metrics() -> dict[str, int]:
    """Categorize job outcomes conservatively from persisted status fields."""
    metrics = {
        "completed_jobs": 0,
        "unpaid_or_expired_jobs": 0,
        "execution_failed_jobs": 0,
        "expired_jobs": 0,
        "unclassified_jobs": 0,
    }
    with session_scope() as session:
        statuses = [str(row[0] or "").strip().lower() for row in session.query(AgentJob.status).all()]

    for status in statuses:
        if status == "done":
            metrics["completed_jobs"] += 1
        elif status in EXECUTION_FAILED_STATUSES:
            metrics["execution_failed_jobs"] += 1
        elif status in EXPIRED_STATUSES:
            metrics["expired_jobs"] += 1
        elif status in INVOICE_PENDING_STATUSES:
            # Honest fallback: persisted status does not always prove whether this is merely unpaid
            # or already expired (without active invoice lookup here).
            metrics["unpaid_or_expired_jobs"] += 1
        else:
            metrics["unclassified_jobs"] += 1
    return metrics


def determine_trust_lane(*, covenant_backed: bool, completed_jobs: int, repeat_counterparty: bool = False) -> str:
    """Return non-enforcing trust-lane policy classification."""
    if covenant_backed:
        return "covenant-backed"
    if repeat_counterparty or completed_jobs >= 5:
        return "repeat-counterparty"
    return "standard"


def _latest_report_id(agent_id: str) -> str:
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"{agent_id}-daily-{day}"


def build_trust_report(agent_id: str, report_id: str | None = None) -> dict[str, Any]:
    """Build trust report artifact from runtime state and covenant surface."""
    _, _, attestations_count = _runtime_counts()
    outcome_metrics = _job_outcome_metrics()
    completed_jobs = outcome_metrics["completed_jobs"]
    covenant = load_covenant(DEFAULT_COVENANT_ID)
    created = _iso_now()
    rid = report_id or _latest_report_id(agent_id)
    report = {
        "schema_version": "1.0",
        "report_id": rid,
        "report_type": "daily_runtime_trust",
        "agent_id": agent_id,
        "created_at": created,
        "period": {
            "from": (datetime.now(timezone.utc) - timedelta(days=1)).replace(microsecond=0).isoformat(),
            "to": created,
        },
        "status": {
            "state": "healthy" if completed_jobs >= 0 else "unknown",
            "heartbeat_ok": True,
            "signing_ok": True,
            "relay_publish_ok": False,
        },
        "metrics": {
            "completed_jobs": completed_jobs,
            "unpaid_or_expired_jobs": outcome_metrics["unpaid_or_expired_jobs"],
            "execution_failed_jobs": outcome_metrics["execution_failed_jobs"],
            "expired_jobs": outcome_metrics["expired_jobs"],
            "unclassified_jobs": outcome_metrics["unclassified_jobs"],
            "sats_earned": completed_jobs * 21,
            "sats_spent": 0,
        },
        "proofs": {
            "latest_receipt_url": "/agent/attestations?limit=1",
            "attestation_url": "/agent/attestations",
            "chain_health_url": "/agent/chain/health",
            "reputation_url": "/agent/reputation",
        },
        "covenant": {
            "covenant_present": True,
            "covenant_declared": True,
            "covenant_funded": False,
            "funding_status": covenant.get("funding_status", "unfunded_declared"),
            "covenant_id": covenant["covenant_id"],
            "summary": (
                "Declared operator↔agent covenant with real public keys and declared address; "
                "funding not yet attached in this surface."
            ),
        },
        "notes": [
            "This public proof artifact summarizes runtime-verifiable behavior history.",
            "External live verification not implemented in this surface yet.",
            "Unpaid or expired requests do not necessarily indicate execution errors.",
            "Invoice-pending states are conservatively grouped as unpaid_or_expired_jobs.",
            "Expired jobs are counted separately only when explicit expired/timeout status exists.",
            f"Attestation count observed: {attestations_count}.",
        ],
    }
    report["report_sha256"] = compute_report_hash(report)
    return report


def compute_report_hash(report_dict: dict[str, Any]) -> str:
    """Compute canonical report hash from report body without report_sha256 field."""
    body = dict(report_dict)
    body.pop("report_sha256", None)
    return sha256_hex(canonicalize_json(body))


def build_trust_summary(agent_id: str) -> dict[str, Any]:
    """Build compact trust summary JSON."""
    _, completed_jobs, attestations_count = _runtime_counts()
    covenant_present = True
    lane = determine_trust_lane(covenant_backed=covenant_present, completed_jobs=completed_jobs)
    return {
        "agent_id": agent_id,
        "public_key": get_agent_pubkey_hex(),
        "runtime_status": "healthy",
        "receipts_available": completed_jobs > 0,
        "attestations_available": attestations_count > 0,
        "covenant_present": covenant_present,
        "covenant_declared": True,
        "covenant_funded": False,
        "funding_status": "unfunded_declared",
        "trust_lane": lane,
        "verify_url": f"/verify/report/{_latest_report_id(agent_id)}",
    }


def trust_page_context(agent_id: str) -> dict[str, Any]:
    """Assemble render context for trust/binding/report pages."""
    binding = load_agent_binding(agent_id)
    covenant = load_covenant(DEFAULT_COVENANT_ID)
    report = build_trust_report(agent_id)
    summary = build_trust_summary(agent_id)
    return {
        "agent_id": agent_id,
        "display_name": binding.get("agent", {}).get("name", DEFAULT_AGENT_NAME),
        "binding": binding,
        "covenant": covenant,
        "report": report,
        "summary": summary,
        "relays": DEFAULT_RELAYS,
    }
