#!/usr/bin/env python3
"""Record a local manual outreach receipt for one exported Herald queue item."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

RECEIPT_SCHEMA = "hodlxxi.herald.manual_outreach_receipt.v1"
ACTION_TAKEN_NONE = "none"

SAFETY_NON_GOALS = [
    "no_live_zaps",
    "no_outbound_payments",
    "no_nwc",
    "no_nip47",
    "no_lnd_calls",
    "no_relay_publishing",
    "no_nostr_signing",
    "no_direct_messages",
    "no_key_material_handling",
    "manual_receipt_recording_only",
]

OUTCOME_MAP = {
    "completed": "manually_completed",
    "skipped": "manually_skipped",
    "failed": "manually_failed",
}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, type=Path, help="Input manual-send package JSON path.")
    parser.add_argument("--output", required=True, type=Path, help="Output manual outreach receipt JSON path.")
    parser.add_argument("--queue-id", required=True, help="Queue item ID to record a manual outcome for.")
    parser.add_argument("--completed", action="store_true", help="Record a manually completed outcome.")
    parser.add_argument("--skipped", action="store_true", help="Record a manually skipped outcome.")
    parser.add_argument("--failed", action="store_true", help="Record a manually failed outcome.")
    parser.add_argument("--operator", default="operator", help='Operator label. Default: "operator".')
    parser.add_argument("--note", help="Optional operator note.")
    parser.add_argument("--external-reference", help="Optional public/manual reference (for example ID or URL).")
    return parser.parse_args()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_package(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("package JSON must be an object")
    return payload


def _resolve_outcome(args: argparse.Namespace) -> str:
    selected = [
        key
        for key, enabled in {
            "completed": args.completed,
            "skipped": args.skipped,
            "failed": args.failed,
        }.items()
        if enabled
    ]
    if len(selected) != 1:
        raise ValueError("exactly one outcome flag is required: --completed, --skipped, or --failed")
    return OUTCOME_MAP[selected[0]]


def _find_item(package: dict[str, object], queue_id: str) -> dict[str, object]:
    items = package.get("items")
    if not isinstance(items, list):
        raise ValueError("package must contain an items list")
    for item in items:
        if isinstance(item, dict) and item.get("queue_id") == queue_id:
            return item
    raise ValueError(f"queue_id not found in package: {queue_id}")


def _build_receipt(
    args: argparse.Namespace, package: dict[str, object], item: dict[str, object], outcome: str
) -> dict[str, object]:
    return {
        "receipt_schema": RECEIPT_SCHEMA,
        "created_at": _now_iso(),
        "source_package": str(args.package),
        "queue_id": item.get("queue_id"),
        "candidate_event_id": item.get("candidate_event_id"),
        "candidate_author_pubkey": item.get("candidate_author_pubkey"),
        "suggested_zap_amount_sats": item.get("suggested_zap_amount_sats"),
        "suggested_comment": item.get("suggested_comment"),
        "proposed_action": item.get("proposed_action"),
        "outcome": outcome,
        "operator": args.operator,
        "note": args.note,
        "external_reference": args.external_reference,
        "action_taken": ACTION_TAKEN_NONE,
        "software_executed_action": False,
        "safety_non_goals": SAFETY_NON_GOALS,
    }


def main() -> int:
    try:
        args = _parse_args()
        package = _read_package(args.package)
        outcome = _resolve_outcome(args)
        item = _find_item(package, args.queue_id)
        receipt = _build_receipt(args, package, item, outcome)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "source_package": str(args.package),
                "output_receipt": str(args.output),
                "queue_id": args.queue_id,
                "outcome": outcome,
                "action_taken": ACTION_TAKEN_NONE,
                "software_executed_action": False,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
