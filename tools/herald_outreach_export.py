#!/usr/bin/env python3
"""Export approved Herald outreach items into a local manual-send package."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

ACTION_TAKEN_NONE = "none"
STATUS_APPROVED = "approved_by_operator"
MANUAL_STATUS_READY = "ready_for_human_manual_action"
PACKAGE_SCHEMA = "hodlxxi.herald.manual_outreach_package.v1"

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
    "manual_send_packaging_only",
]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reviewed-queue", type=Path, required=True, help="Input reviewed queue JSON path.")
    parser.add_argument("--json-output", type=Path, required=True, help="Output manual-send package JSON path.")
    parser.add_argument("--markdown-output", type=Path, required=True, help="Output manual-send package markdown path.")
    return parser.parse_args()


def _read_reviewed_queue(path: Path) -> list[dict[str, object]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("reviewed queue JSON must be a list")
    for idx, row in enumerate(payload):
        if not isinstance(row, dict):
            raise ValueError(f"reviewed queue item at index {idx} must be an object")
    return payload


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _approved_items(queue_items: list[dict[str, object]]) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for item in queue_items:
        if item.get("status") != STATUS_APPROVED:
            continue
        if item.get("action_taken") != ACTION_TAKEN_NONE:
            continue
        out.append(
            {
                "queue_id": item.get("queue_id"),
                "candidate_event_id": item.get("candidate_event_id"),
                "candidate_author_pubkey": item.get("candidate_author_pubkey"),
                "suggested_zap_amount_sats": item.get("suggested_zap_amount_sats"),
                "suggested_comment": item.get("suggested_comment"),
                "proposed_action": item.get("proposed_action"),
                "reasons": item.get("reasons"),
                "reviewed_by": item.get("reviewed_by"),
                "review_reason": item.get("review_reason"),
                "manual_status": MANUAL_STATUS_READY,
                "action_taken": ACTION_TAKEN_NONE,
                "safety_non_goals": SAFETY_NON_GOALS,
            }
        )
    return out


def _build_markdown(source_queue_path: Path, items: list[dict[str, object]]) -> str:
    lines = [
        "# Herald Manual Outreach Send Package",
        "",
        f"Source reviewed queue: `{source_queue_path}`",
        f"Approved count: **{len(items)}**",
        "",
        "⚠️ Safety warning: this package is manual-send planning only. Nothing has been sent, signed, published, or paid.",
        "",
    ]

    if not items:
        lines.extend(
            [
                "No approved items were eligible for manual-send packaging.",
                "",
                "## Manual next steps",
                "- Re-run review when items become approved_by_operator with action_taken=none.",
                "",
            ]
        )
        return "\n".join(lines)

    for idx, item in enumerate(items, start=1):
        reasons = item.get("reasons") or []
        if isinstance(reasons, list):
            reason_lines = [f"  - {entry}" for entry in reasons]
        else:
            reason_lines = [f"  - {reasons}"]

        lines.extend(
            [
                f"## Item {idx}: {item.get('queue_id')}",
                f"- Author pubkey: `{item.get('candidate_author_pubkey')}`",
                f"- Event ID: `{item.get('candidate_event_id')}`",
                f"- Suggested sats: `{item.get('suggested_zap_amount_sats')}`",
                f"- Suggested comment: {item.get('suggested_comment')}",
                f"- Reviewed by: `{item.get('reviewed_by')}`",
                f"- Review reason: {item.get('review_reason')}",
                "- Reasons:",
                *reason_lines,
                "- Manual next steps: [operator fills in channel/process for human send action]",
                "",
            ]
        )

    return "\n".join(lines)


def main() -> int:
    args = _parse_args()
    queue_items = _read_reviewed_queue(args.reviewed_queue)
    exported_items = _approved_items(queue_items)

    package = {
        "package_schema": PACKAGE_SCHEMA,
        "created_at": _now_iso(),
        "source_reviewed_queue": str(args.reviewed_queue),
        "approved_count": len(exported_items),
        "action_taken": ACTION_TAKEN_NONE,
        "safety_non_goals": SAFETY_NON_GOALS,
        "items": exported_items,
    }

    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(package, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.markdown_output.write_text(_build_markdown(args.reviewed_queue, exported_items), encoding="utf-8")

    print(
        json.dumps(
            {
                "reviewed_queue": str(args.reviewed_queue),
                "json_output": str(args.json_output),
                "markdown_output": str(args.markdown_output),
                "approved_count": len(exported_items),
                "action_taken": ACTION_TAKEN_NONE,
                "safety_non_goals": SAFETY_NON_GOALS,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
