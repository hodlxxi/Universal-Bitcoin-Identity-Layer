#!/usr/bin/env python3
"""Review a local Herald outreach queue and write a reviewed local JSON file."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

ACTION_TAKEN_NONE = "none"
STATUS_APPROVED = "approved_by_operator"
STATUS_REJECTED = "rejected_by_operator"

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
    "local_review_only",
]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, required=True, help="Input outreach queue JSON path.")
    parser.add_argument("--output", type=Path, required=True, help="Output reviewed queue JSON path.")
    parser.add_argument("--approve", action="append", default=[], help="Queue ID to approve (repeatable).")
    parser.add_argument("--reject", action="append", default=[], help="Queue ID to reject (repeatable).")
    parser.add_argument("--reviewer", default="operator", help="Reviewer identity label.")
    parser.add_argument("--reason", default=None, help="Optional review reason.")
    return parser.parse_args()


def _fail(message: str) -> int:
    print(json.dumps({"error": message}, indent=2))
    return 1


def _read_queue(path: Path) -> list[dict[str, object]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("queue JSON must be a list")
    for idx, row in enumerate(payload):
        if not isinstance(row, dict):
            raise ValueError(f"queue item at index {idx} must be an object")
    return payload


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    args = _parse_args()
    approve_ids = set(args.approve or [])
    reject_ids = set(args.reject or [])

    if not approve_ids and not reject_ids:
        return _fail("at least one --approve or --reject queue_id is required")

    both = approve_ids & reject_ids
    if both:
        return _fail(f"queue_id cannot be both approved and rejected: {sorted(both)}")

    queue_items = _read_queue(args.queue)
    queue_ids = {str(item.get("queue_id", "")) for item in queue_items}

    requested = approve_ids | reject_ids
    unknown = sorted(qid for qid in requested if qid not in queue_ids)
    if unknown:
        return _fail(f"unknown queue_id(s): {unknown}")

    reviewed_items: list[dict[str, object]] = []
    approved_count = 0
    rejected_count = 0
    now = _now_iso()

    for item in queue_items:
        current = dict(item)
        queue_id = str(current.get("queue_id", ""))
        if queue_id in approve_ids:
            current["status"] = STATUS_APPROVED
            current["approval_required"] = True
            current["action_taken"] = ACTION_TAKEN_NONE
            current["approved_at"] = now
            current.pop("rejected_at", None)
            current["reviewed_by"] = args.reviewer
            if args.reason:
                current["review_reason"] = args.reason
            approved_count += 1
        elif queue_id in reject_ids:
            current["status"] = STATUS_REJECTED
            current["approval_required"] = True
            current["action_taken"] = ACTION_TAKEN_NONE
            current["rejected_at"] = now
            current.pop("approved_at", None)
            current["reviewed_by"] = args.reviewer
            if args.reason:
                current["review_reason"] = args.reason
            rejected_count += 1

        reviewed_items.append(current)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(reviewed_items, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    total_count = len(reviewed_items)
    print(
        json.dumps(
            {
                "input_queue": str(args.queue),
                "output_queue": str(args.output),
                "approved_count": approved_count,
                "rejected_count": rejected_count,
                "unchanged_count": total_count - approved_count - rejected_count,
                "total_count": total_count,
                "action_taken": ACTION_TAKEN_NONE,
                "safety_non_goals": SAFETY_NON_GOALS,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
