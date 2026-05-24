"""Herald operator-approved outreach queue.

This module converts Herald dry-run candidate assessments into local JSON queue
items. It never sends messages, publishes relay events, signs Nostr events, or
executes payments. Every queue item requires explicit operator approval.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

QUEUE_SCHEMA = "hodlxxi.herald.operator_approval_queue.v1"
QUEUE_STATUS_PENDING = "pending_operator_approval"
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
    "no_background_daemon",
    "operator_approval_required",
]


@dataclass(frozen=True)
class OutreachQueueItem:
    queue_schema: str
    queue_id: str
    created_at: str
    status: str
    source_mode: str
    candidate_event_id: str
    candidate_author_pubkey: str
    score: float
    reasons: list[str]
    suggested_zap_amount_sats: int
    suggested_comment: str
    proposed_action: str
    approval_required: bool
    action_taken: str
    safety: dict[str, object]


def make_queue_id(
    *,
    candidate_event_id: str,
    candidate_author_pubkey: str,
    proposed_action: str,
    suggested_zap_amount_sats: int,
) -> str:
    material = "|".join(
        [
            candidate_event_id,
            candidate_author_pubkey,
            proposed_action,
            str(int(suggested_zap_amount_sats)),
        ]
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"heraldq_{digest[:24]}"


def proposed_action_for_amount(suggested_zap_amount_sats: int) -> str:
    """Return a proposal label only; no action is executed."""
    return "zap_invite" if int(suggested_zap_amount_sats) > 0 else "invite_only"


def build_queue_item(
    *,
    candidate,
    source_mode: str,
    created_at: str | None = None,
) -> OutreachQueueItem:
    proposed_action = proposed_action_for_amount(candidate.suggested_zap_amount_sats)
    created = created_at or datetime.now(timezone.utc).isoformat()

    queue_id = make_queue_id(
        candidate_event_id=candidate.event_id,
        candidate_author_pubkey=candidate.author_pubkey,
        proposed_action=proposed_action,
        suggested_zap_amount_sats=candidate.suggested_zap_amount_sats,
    )

    return OutreachQueueItem(
        queue_schema=QUEUE_SCHEMA,
        queue_id=queue_id,
        created_at=created,
        status=QUEUE_STATUS_PENDING,
        source_mode=source_mode,
        candidate_event_id=candidate.event_id,
        candidate_author_pubkey=candidate.author_pubkey,
        score=float(candidate.score),
        reasons=list(candidate.reasons),
        suggested_zap_amount_sats=int(candidate.suggested_zap_amount_sats),
        suggested_comment=str(candidate.suggested_comment),
        proposed_action=proposed_action,
        approval_required=True,
        action_taken=ACTION_TAKEN_NONE,
        safety={
            "non_goals": list(SAFETY_NON_GOALS),
            "requires_operator_approval": True,
        },
    )


def build_outreach_queue(
    *,
    candidates: Sequence,
    source_mode: str,
    max_items: int = 10,
    created_at: str | None = None,
) -> list[dict[str, object]]:
    limit = max(0, int(max_items))
    queue: list[dict[str, object]] = []

    for candidate in candidates:
        if len(queue) >= limit:
            break
        if getattr(candidate, "action_taken", None) != "dry_run_candidate":
            continue

        item = build_queue_item(
            candidate=candidate,
            source_mode=source_mode,
            created_at=created_at,
        )
        queue.append(asdict(item))

    return queue


def write_outreach_queue(path: str | Path, items: Iterable[dict[str, object]]) -> Path:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = list(items)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output_path
