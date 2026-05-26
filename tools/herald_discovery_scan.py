#!/usr/bin/env python3
"""Run a Herald Nostr discovery dry-run scan and print shortlist."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.services.herald_discovery_profiles import (
    available_target_profiles,
    list_target_profiles,
    resolve_target_profiles,
)
from app.services.herald_nostr_discovery import HeraldNostrDiscoveryEngine, HeraldRelayReadonlyClient
from app.services.herald_outreach_queue import build_outreach_queue, write_outreach_queue

COOLDOWN_SCHEMA = "hodlxxi.herald.live_queue_cooldown.v1"


class FixtureRelayDiscoveryClient:
    """Relay client that serves local fixture events only."""

    def __init__(self, events: list[dict[str, Any]]):
        self._events = events

    def search_recent_notes(self, **kwargs) -> list[dict[str, Any]]:
        return self._events


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixture", type=Path, default=None, help="Load discovery events from a local JSON fixture file."
    )
    parser.add_argument(
        "--live-relay-readonly",
        action="store_true",
        help="Read public kind-1 notes from configured relays using read-only mode.",
    )
    parser.add_argument(
        "--relay", action="append", default=None, help="Relay URL (repeatable) for live read-only mode."
    )
    parser.add_argument("--limit", type=int, default=100, help="Max events to read in live read-only mode.")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-recv timeout seconds in live read-only mode.")
    parser.add_argument(
        "--disable-relay-keyword-prefilter",
        action="store_true",
        help="Disable relay keyword prefilter in live read-only mode.",
    )
    parser.add_argument(
        "--raw-sample-size",
        type=int,
        default=5,
        help="Max number of raw relay event samples to include in diagnostics.",
    )
    parser.add_argument(
        "--target-profile",
        action="append",
        default=None,
        choices=available_target_profiles(),
        help="Named targeted discovery profile to merge into this run (repeatable).",
    )
    parser.add_argument(
        "--list-target-profiles",
        action="store_true",
        help="Print available targeted discovery profiles as JSON and exit.",
    )
    parser.add_argument(
        "--search-mode",
        action="append",
        default=None,
        choices=["keyword", "hashtag", "mixed"],
        help="Descriptive search mode label for operator visibility (repeatable).",
    )
    parser.add_argument("--keyword", action="append", default=None, help="Override alignment keyword (repeatable).")
    parser.add_argument("--hashtag", action="append", default=None, help="Override alignment hashtag (repeatable).")
    parser.add_argument(
        "--since-hours", type=int, default=None, help="Override discovery search window hours for this run."
    )
    parser.add_argument(
        "--max-live-events", type=int, default=None, help="Safety cap for live events considered (<= --limit)."
    )
    parser.add_argument("--min-score", type=float, default=None, help="Minimum candidate score to enter queue.")
    parser.add_argument(
        "--dedupe-authors", action="store_true", help="Keep highest-scoring candidate per author_pubkey."
    )
    parser.add_argument("--cooldown-state", type=Path, default=None, help="Optional local JSON cooldown state path.")
    parser.add_argument("--cooldown-hours", type=int, default=24, help="Cooldown lookback window in hours.")
    parser.add_argument(
        "--write-outreach-queue",
        type=Path,
        default=None,
        help="Write local operator-approval outreach queue JSON to this path.",
    )
    parser.add_argument(
        "--max-queue-items",
        type=int,
        default=10,
        help="Maximum dry-run candidates to include in the outreach queue.",
    )
    return parser.parse_args()


def _load_fixture_events(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("fixture JSON must be a list of event objects")
    for idx, row in enumerate(payload):
        if not isinstance(row, dict):
            raise ValueError(f"fixture event at index {idx} must be an object")
    return payload


def _load_cooldown_entries(path: Path, cooldown_hours: int, now: datetime) -> list[dict[str, str]]:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict) or payload.get("schema") != COOLDOWN_SCHEMA:
        return []
    cutoff = now - timedelta(hours=max(0, int(cooldown_hours)))
    entries = payload.get("entries", [])
    kept: list[dict[str, str]] = []
    for row in entries:
        if not isinstance(row, dict):
            continue
        queued_at = row.get("queued_at")
        if not isinstance(queued_at, str):
            continue
        try:
            queued_dt = datetime.fromisoformat(queued_at.replace("Z", "+00:00"))
        except ValueError:
            continue
        if queued_dt.tzinfo is None:
            queued_dt = queued_dt.replace(tzinfo=timezone.utc)
        if queued_dt >= cutoff:
            kept.append(row)
    return kept


def _write_cooldown_state(path: Path, entries: list[dict[str, str]], now: datetime) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": COOLDOWN_SCHEMA,
        "updated_at": now.isoformat(),
        "entries": entries,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _clean_keywords(values: list[str] | None) -> list[str]:
    return [str(value).strip() for value in values or [] if str(value).strip()]


def _clean_hashtags(values: list[str] | None) -> list[str]:
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw_value in values or []:
        value = str(raw_value).strip().lower().lstrip("#")
        if not value or value in seen:
            continue
        cleaned.append(value)
        seen.add(value)
    return cleaned


def _dedupe_strings(values: list[str] | None) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for raw_value in values or []:
        value = str(raw_value).strip()
        if not value or value in seen:
            continue
        ordered.append(value)
        seen.add(value)
    return ordered


def main() -> int:
    args = _parse_args()
    if args.list_target_profiles:
        print(json.dumps(list_target_profiles(), indent=2))
        return 0

    resolved_max_live_events = max(1, int(args.limit))
    if args.max_live_events is not None:
        resolved_max_live_events = min(resolved_max_live_events, max(1, int(args.max_live_events)))

    relay_client = None
    source_mode = "noop"
    if args.fixture is not None:
        fixture_events = _load_fixture_events(args.fixture)
        relay_client = FixtureRelayDiscoveryClient(fixture_events)
        source_mode = "fixture"
    elif args.live_relay_readonly:
        relay_client = HeraldRelayReadonlyClient(
            relays=args.relay,
            max_events=resolved_max_live_events,
            timeout_seconds=max(0.5, float(args.timeout)),
            disable_keyword_prefilter=bool(args.disable_relay_keyword_prefilter),
            raw_sample_size=max(0, int(args.raw_sample_size)),
        )
        source_mode = "live_relay_readonly"

    engine = HeraldNostrDiscoveryEngine(relay_client=relay_client)
    target_profiles = _dedupe_strings(args.target_profile)
    search_modes = _dedupe_strings(args.search_mode)
    explicit_keywords = _clean_keywords(args.keyword)
    explicit_hashtags = _clean_hashtags(args.hashtag)

    recommended_profile_min_score = 0.0
    if target_profiles:
        resolved_profiles = resolve_target_profiles(
            target_profiles,
            extra_keywords=explicit_keywords,
            extra_hashtags=explicit_hashtags,
        )
        engine.config.alignment_keywords = list(resolved_profiles.keywords)
        engine.config.alignment_hashtags = list(resolved_profiles.hashtags)
        recommended_profile_min_score = float(resolved_profiles.min_score)
    else:
        if args.keyword is not None:
            engine.config.alignment_keywords = explicit_keywords
        if args.hashtag is not None:
            engine.config.alignment_hashtags = explicit_hashtags

    if args.since_hours is not None:
        engine.config.search_window_hours = max(0, int(args.since_hours))

    resolved_min_score = 0.0
    if args.min_score is not None:
        resolved_min_score = float(args.min_score)
    elif target_profiles:
        resolved_min_score = recommended_profile_min_score

    rows = engine.discover_and_evaluate()
    output_relays = getattr(relay_client, "relays", None) or engine.config.relay_urls

    outreach_queue_written = None
    outreach_queue_count = 0
    skipped_by_score_count = 0
    skipped_by_dedupe_count = 0
    skipped_by_cooldown_count = 0

    if args.write_outreach_queue is not None:
        candidates = [r for r in rows if getattr(r, "action_taken", None) == "dry_run_candidate"]
        score_filtered = [r for r in candidates if float(getattr(r, "score", 0.0)) >= resolved_min_score]
        skipped_by_score_count = len(candidates) - len(score_filtered)

        deduped = score_filtered
        if args.dedupe_authors:
            best_by_author: dict[str, Any] = {}
            for row in score_filtered:
                author = str(getattr(row, "author_pubkey", ""))
                prev = best_by_author.get(author)
                if prev is None or float(getattr(row, "score", 0.0)) > float(getattr(prev, "score", 0.0)):
                    best_by_author[author] = row
            deduped = sorted(best_by_author.values(), key=lambda r: float(getattr(r, "score", 0.0)), reverse=True)
            skipped_by_dedupe_count = len(score_filtered) - len(deduped)

        now = datetime.now(timezone.utc)
        cooldown_entries: list[dict[str, str]] = []
        seen_authors: set[str] = set()
        seen_events: set[str] = set()
        if args.cooldown_state is not None:
            cooldown_entries = _load_cooldown_entries(args.cooldown_state, args.cooldown_hours, now)
            seen_authors = {str(e.get("candidate_author_pubkey", "")) for e in cooldown_entries}
            seen_events = {str(e.get("candidate_event_id", "")) for e in cooldown_entries}

        post_cooldown: list[Any] = []
        for row in deduped:
            author = str(getattr(row, "author_pubkey", ""))
            event_id = str(getattr(row, "event_id", ""))
            if args.cooldown_state is not None and (author in seen_authors or event_id in seen_events):
                continue
            post_cooldown.append(row)
        skipped_by_cooldown_count = len(deduped) - len(post_cooldown)

        queue_items = build_outreach_queue(
            candidates=post_cooldown, source_mode=source_mode, max_items=args.max_queue_items
        )
        write_outreach_queue(args.write_outreach_queue, queue_items)
        outreach_queue_written = str(args.write_outreach_queue)
        outreach_queue_count = len(queue_items)

        if args.cooldown_state is not None:
            new_entries = list(cooldown_entries)
            for item in queue_items:
                new_entries.append(
                    {
                        "candidate_author_pubkey": str(item.get("candidate_author_pubkey", "")),
                        "candidate_event_id": str(item.get("candidate_event_id", "")),
                        "queued_at": now.isoformat(),
                    }
                )
            _write_cooldown_state(args.cooldown_state, new_entries, now)

    print(
        json.dumps(
            {
                "declared_herald_pubkey": engine.config.declared_herald_pubkey,
                "source_mode": source_mode,
                "zap_mode": engine.config.zap_mode,
                "relay_urls": output_relays,
                "target_profiles": target_profiles,
                "search_modes": search_modes,
                "effective_keywords": list(engine.config.alignment_keywords),
                "effective_hashtags": list(engine.config.alignment_hashtags),
                "candidates_found": len(rows),
                "relay_warnings": getattr(relay_client, "warnings", []),
                "relay_diagnostics": getattr(
                    relay_client,
                    "diagnostics",
                    lambda: {
                        "raw_events_seen": 0,
                        "raw_events_by_relay": {},
                        "keyword_prefilter_matched": 0,
                        "keyword_prefilter_skipped": 0,
                        "invalid_event_count": 0,
                        "relay_errors": [],
                        "raw_samples": [],
                    },
                )(),
                "live_safety": {
                    "max_live_events": resolved_max_live_events,
                    "min_score": resolved_min_score,
                    "dedupe_authors": bool(args.dedupe_authors),
                    "cooldown_state": str(args.cooldown_state) if args.cooldown_state is not None else None,
                    "cooldown_hours": max(0, int(args.cooldown_hours)),
                    "search_window_hours": int(engine.config.search_window_hours),
                    "disable_relay_keyword_prefilter": bool(args.disable_relay_keyword_prefilter),
                },
                "outreach_queue_written": outreach_queue_written,
                "outreach_queue_count": outreach_queue_count,
                "skipped_by_score_count": skipped_by_score_count,
                "skipped_by_dedupe_count": skipped_by_dedupe_count,
                "skipped_by_cooldown_count": skipped_by_cooldown_count,
                "top_candidates": [
                    {
                        "event_id": item.event_id,
                        "author_pubkey": item.author_pubkey,
                        "score": item.score,
                        "zap_eligible": item.zap_eligible,
                        "suggested_zap_amount_sats": item.suggested_zap_amount_sats,
                        "suggested_comment": item.suggested_comment,
                        "action_taken": item.action_taken,
                        "action_reason": item.action_reason,
                        "reasons": item.reasons,
                    }
                    for item in rows[:20]
                ],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
