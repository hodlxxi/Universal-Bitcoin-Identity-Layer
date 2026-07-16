"""Nostr report payload builders for HODLXXI trust artifacts."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def build_heartbeat_note(report: dict[str, Any]) -> str:
    """Return concise heartbeat note content for Nostr kind 1."""
    status = report.get("status", {}).get("state", "unknown")
    report_id = report.get("report_id", "unknown")
    agent_id = report.get("agent_id", "unknown")
    return f"HODLXXI heartbeat | agent={agent_id} | state={status} | report={report_id}"


def build_execution_summary_note(receipt: dict[str, Any]) -> str:
    """Return concise execution summary note content for Nostr kind 1."""
    job_id = receipt.get("job_id", "unknown")
    job_type = receipt.get("job_type") or receipt.get("event_type", "unknown")
    ts = receipt.get("timestamp", "unknown")
    return f"Execution summary | job={job_id} | type={job_type} | timestamp={ts}"


def build_trust_signal_note(trust: dict[str, Any]) -> str:
    """Return concise trust surface note for Nostr kind 1."""
    agent_id = trust.get("agent_id", "unknown")
    funding_status = trust.get("funding_status", "unknown")
    return (
        f"Trust surface update | agent={agent_id} | declared covenant policy signal | "
        f"funding_status={funding_status} | does not establish on-chain capital proof."
    )


def build_daily_longform_report(report: dict[str, Any]) -> dict[str, str | int]:
    """Return longform content payload intended for Nostr kind 30023."""
    title = f"HODLXXI Herald Daily Trust Report {report.get('report_id', '')}"
    period = report.get("period", {})
    metrics = report.get("metrics", {})
    lifetime = report.get("lifetime_snapshot", {})
    covenant = report.get("covenant", {})
    body = (
        f"# {title}\n\n"
        f"- Agent ID: `{report.get('agent_id', 'unknown')}`\n"
        f"- State: `{report.get('status', {}).get('state', 'unknown')}`\n"
        f"- Fixed UTC period: `[{period.get('from', 'unknown')}, {period.get('to', 'unknown')})`\n"
        f"- Period evidenced completed jobs: `{metrics.get('evidenced_completed_jobs', 0)}`\n"
        f"- Period sats evidenced: `{metrics.get('sats_evidenced', 0)}`\n"
        f"- Lifetime snapshot as of: `{lifetime.get('as_of', 'unknown')}`\n"
        f"- Declared covenant funding status: `{covenant.get('funding_status', 'unknown')}`\n"
        "\n"
        "This longform note summarizes cutoff-bounded runtime evidence and a declared operator↔agent covenant policy "
        "signal. The covenant is not presented as funded on-chain capital proof. It does not by itself prove uptime, "
        "execution quality, or full autonomy."
    )
    return {"kind": 30023, "title": title, "content": body}


def build_relay_list_event(relays: list[str]) -> dict[str, Any]:
    """Return Nostr kind 10002 relay list event structure."""
    tags = [["r", relay] for relay in relays if relay]
    return {
        "kind": 10002,
        "created_at": int(datetime.now(timezone.utc).timestamp()),
        "content": "",
        "tags": tags,
    }


def publish_nostr_event(event: dict[str, Any], *, dry_run: bool = True) -> dict[str, Any]:
    """Publish abstraction for Nostr events.

    TODO: wire this to real signing and relay transport when Nostr integration is available.
    """
    if dry_run:
        return {
            "status": "dry_run",
            "published": False,
            "event": event,
            "message": "Live relay publishing is not implemented in this trust surface yet.",
        }
    raise NotImplementedError("Live Nostr publish transport/signing is not implemented yet")


def configured_relays_from_env(env_value: str | None) -> list[str]:
    """Parse NOSTR_RELAYS-style comma-separated relay URLs."""
    if not env_value:
        return []
    return [item.strip() for item in env_value.split(",") if item and item.strip()]
