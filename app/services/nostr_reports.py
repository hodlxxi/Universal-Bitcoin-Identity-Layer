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
    lane = trust.get("trust_lane", "standard")
    agent_id = trust.get("agent_id", "unknown")
    return (
        f"Trust surface update | agent={agent_id} | lane={lane} | "
        "Bitcoin-anchored operator↔agent covenant is an alignment signal, not an uptime guarantee."
    )


def build_daily_longform_report(report: dict[str, Any]) -> dict[str, str | int]:
    """Return longform content payload intended for Nostr kind 30023."""
    title = f"HODLXXI Herald Daily Trust Report {report.get('report_id', '')}"
    body = (
        f"# {title}\n\n"
        f"- Agent ID: `{report.get('agent_id', 'unknown')}`\n"
        f"- State: `{report.get('status', {}).get('state', 'unknown')}`\n"
        f"- Completed jobs: `{report.get('metrics', {}).get('completed_jobs', 0)}`\n"
        f"- Covenant-backed alignment signal: `{report.get('covenant', {}).get('covenant_backed', False)}`\n"
        "\n"
        "This longform note summarizes runtime-verifiable behavior history and a Bitcoin-anchored "
        "operator↔agent covenant alignment signal. It does not by itself prove uptime, execution quality, or full autonomy."
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
