"""Trust surface helpers for public agent trust artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

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
DAILY_TRUST_REPORT_SCHEMA = "hodlxxi.daily_trust_report.v1"
DAILY_REPORT_ID_RE = re.compile(r"^(?P<agent_id>[A-Za-z0-9][A-Za-z0-9_-]{0,126})-daily-(?P<period_end>[0-9]{8})$")


def canonicalize_json(data: dict[str, Any]) -> str:
    """Return canonical JSON text used for deterministic hashing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str | bytes) -> str:
    """Return sha256 hex digest for str/bytes payload."""
    payload = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(payload).hexdigest()


def _iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _as_utc(value: datetime) -> datetime:
    """Return a UTC-aware datetime, treating persisted naive values as UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _utc_iso(value: datetime) -> str:
    """Return a stable second-precision UTC timestamp with a Z suffix."""
    return _as_utc(value).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _database_utc(value: datetime) -> datetime:
    """Return naive UTC for the existing timezone-naive SQLAlchemy columns."""
    return _as_utc(value).replace(tzinfo=None)


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


def classify_job_outcomes(statuses: list[object]) -> dict[str, int]:
    """Categorize persisted job statuses without implying execution failure."""
    metrics = {
        "completed_jobs": 0,
        "unpaid_or_expired_jobs": 0,
        "execution_failed_jobs": 0,
        "expired_jobs": 0,
        "unclassified_jobs": 0,
    }

    for raw_status in statuses:
        status = str(raw_status or "").strip().lower()
        if status == "done":
            metrics["completed_jobs"] += 1
        elif status in EXECUTION_FAILED_STATUSES:
            metrics["execution_failed_jobs"] += 1
        elif status in EXPIRED_STATUSES:
            metrics["expired_jobs"] += 1
        elif status in INVOICE_PENDING_STATUSES:
            # Persisted state alone does not prove whether an invoice remains
            # payable or has expired without a live payment-backend lookup.
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


def _latest_report_id(agent_id: str, *, now: datetime | None = None) -> str:
    day = _as_utc(now or datetime.now(timezone.utc)).strftime("%Y%m%d")
    return f"{agent_id}-daily-{day}"


def parse_daily_report_id(
    report_id: str,
    *,
    expected_agent_id: str | None = None,
    now: datetime | None = None,
) -> tuple[str, datetime] | None:
    """Parse a supported daily report ID and reject malformed or future cutoffs."""
    if not isinstance(report_id, str) or len(report_id) > 160:
        return None

    match = DAILY_REPORT_ID_RE.fullmatch(report_id)
    if match is None:
        return None

    agent_id = match.group("agent_id")
    if expected_agent_id is not None and agent_id != expected_agent_id:
        return None

    try:
        period_end = datetime.strptime(match.group("period_end"), "%Y%m%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None

    current_utc_date = _as_utc(now or datetime.now(timezone.utc)).date()
    if period_end.date() > current_utc_date:
        return None
    return agent_id, period_end


def daily_report_period(period_end: datetime) -> tuple[datetime, datetime]:
    """Return the fixed UTC day immediately preceding an exclusive cutoff."""
    normalized_end = _as_utc(period_end)
    if normalized_end != normalized_end.replace(hour=0, minute=0, second=0, microsecond=0):
        raise ValueError("daily report period end must be UTC midnight")
    return normalized_end - timedelta(days=1), normalized_end


def _evidenced_job_metrics(session: Session, *event_filters: Any) -> tuple[int, int]:
    evidenced_job_ids = session.query(AgentEvent.job_id).filter(*event_filters).distinct().subquery()
    jobs = (
        session.query(AgentJob.id, AgentJob.sats)
        .join(evidenced_job_ids, AgentJob.id == evidenced_job_ids.c.job_id)
        .order_by(AgentJob.id.asc())
        .all()
    )
    return len(jobs), sum(int(sats) for _, sats in jobs)


def query_period_metrics(session: Session, period_from: datetime, period_to: datetime) -> dict[str, int]:
    """Query facts whose source timestamps fall within [period_from, period_to)."""
    database_from = _database_utc(period_from)
    database_to = _database_utc(period_to)
    event_filters = (
        AgentEvent.created_at >= database_from,
        AgentEvent.created_at < database_to,
    )
    evidenced_jobs, sats_evidenced = _evidenced_job_metrics(session, *event_filters)
    return {
        "persisted_job_requests": (
            session.query(AgentJob)
            .filter(AgentJob.created_at >= database_from, AgentJob.created_at < database_to)
            .count()
        ),
        "evidenced_completed_jobs": evidenced_jobs,
        # Compatibility alias with explicit period-evidence semantics.
        "completed_jobs": evidenced_jobs,
        "attestations_created": session.query(AgentEvent).filter(*event_filters).count(),
        "sats_evidenced": sats_evidenced,
    }


def query_lifetime_snapshot(session: Session, period_to: datetime) -> dict[str, Any]:
    """Query lifetime facts bounded by the exclusive report cutoff."""
    database_to = _database_utc(period_to)
    event_filter = AgentEvent.created_at < database_to
    evidenced_jobs, sats_evidenced = _evidenced_job_metrics(session, event_filter)
    latest_event = (
        session.query(AgentEvent)
        .filter(event_filter)
        .order_by(AgentEvent.created_at.desc(), AgentEvent.id.desc(), AgentEvent.event_hash.desc())
        .first()
    )
    return {
        "scope": "lifetime_before_cutoff",
        "as_of": _utc_iso(period_to),
        "persisted_job_requests": session.query(AgentJob).filter(AgentJob.created_at < database_to).count(),
        "evidenced_completed_jobs": evidenced_jobs,
        "attestations_count": session.query(AgentEvent).filter(event_filter).count(),
        "sats_evidenced": sats_evidenced,
        "latest_event_timestamp": _utc_iso(latest_event.created_at) if latest_event is not None else None,
        "latest_event_hash": latest_event.event_hash if latest_event is not None else None,
    }


def build_trust_report(
    agent_id: str,
    report_id: str | None = None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Reconstruct a deterministic daily trust report from bounded history."""
    validation_time = _as_utc(now or datetime.now(timezone.utc))
    rid = report_id or _latest_report_id(agent_id, now=validation_time)
    parsed = parse_daily_report_id(rid, expected_agent_id=agent_id, now=validation_time)
    if parsed is None:
        raise ValueError("unsupported daily trust report ID")

    _, period_end = parsed
    period_from, period_to = daily_report_period(period_end)
    with session_scope() as session:
        period_metrics = query_period_metrics(session, period_from, period_to)
        lifetime_snapshot = query_lifetime_snapshot(session, period_to)

    covenant = load_covenant(DEFAULT_COVENANT_ID)
    report = {
        "schema": DAILY_TRUST_REPORT_SCHEMA,
        "schema_version": "1.1",
        "report_id": rid,
        "report_type": "daily_runtime_trust",
        "agent_id": agent_id,
        "created_at": _utc_iso(period_to),
        "period": {
            "type": "closed_utc_day",
            "from": _utc_iso(period_from),
            "to": _utc_iso(period_to),
            "from_inclusive": True,
            "to_exclusive": True,
        },
        "status": {
            "state": "closed_period",
            "period_closed": True,
        },
        "metrics_scope": "closed_utc_period",
        "metrics": period_metrics,
        "metric_definitions": {
            "completed_jobs": {
                "scope": "closed_utc_period",
                "semantics": "period_evidenced_completed_jobs",
                "compatibility_alias_of": "metrics.evidenced_completed_jobs",
            }
        },
        "lifetime_snapshot": lifetime_snapshot,
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
            "Period metrics contain only source records timestamped within the fixed UTC period.",
            "The lifetime snapshot is bounded by its as_of cutoff.",
            "Current job-outcome classifications are available at proofs.reputation_url, not as historical period facts.",
            "External live verification not implemented in this surface yet.",
        ],
    }
    report["report_sha256"] = compute_report_hash(report)
    return report


def resolve_trust_report(
    report_id: str,
    *,
    agent_id: str = DEFAULT_AGENT_ID,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    """Resolve only supported daily trust-report IDs without synthesizing arbitrary reports."""
    if parse_daily_report_id(report_id, expected_agent_id=agent_id, now=now) is None:
        return None
    return build_trust_report(agent_id, report_id=report_id, now=now)


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
