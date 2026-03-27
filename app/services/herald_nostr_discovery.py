"""Herald Nostr discovery + alignment zap policy engine (dry-run first).

This module intentionally operates from the declared public Herald identity and
never touches operator personal keys. Live zap execution is scaffolded but
disabled by default.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger(__name__)

DECLARED_HERALD_PUBKEY = "02019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92"

DEFAULT_RELAYS = ["wss://relay.damus.io", "wss://nos.lol"]
DEFAULT_HASHTAGS = [
    "bitcoin",
    "lightning",
    "nostr",
    "ai",
    "agents",
    "identity",
    "sovereignidentity",
    "machinepayments",
]
DEFAULT_KEYWORDS = [
    "bitcoin agent",
    "lightning agent",
    "machine payments",
    "agent identity",
    "key-based identity",
    "signed receipts",
    "attestations",
    "verifiable agent",
    "nostr agent",
    "bitcoin-native identity",
    "universal bitcoin identity",
    "ubid",
    "hodlxxi",
]
DEFAULT_SPAM_TERMS = [
    "giveaway",
    "casino",
    "100x",
    "pump",
    "moon",
    "airdrop",
    "betting",
    "sportsbook",
]


class RelayDiscoveryClient(Protocol):
    """Abstract relay client for note discovery."""

    def search_recent_notes(
        self,
        *,
        relays: list[str],
        hashtags: list[str],
        keywords: list[str],
        since: datetime,
    ) -> list[dict[str, Any]]:
        """Return recent kind-1-like events from relays."""


class MetadataResolver(Protocol):
    """Abstract author metadata resolver for zap capability signals."""

    def resolve_author_metadata(self, pubkey: str) -> dict[str, Any] | None:
        """Return metadata dictionary when available."""


class NoopRelayDiscoveryClient:
    """Conservative relay client used for dry-run scaffolding.

    Real relay websocket discovery can be wired later without changing policy
    logic. For now this keeps behavior explicit and non-deceptive.
    """

    def search_recent_notes(
        self,
        *,
        relays: list[str],
        hashtags: list[str],
        keywords: list[str],
        since: datetime,
    ) -> list[dict[str, Any]]:
        logger.info(
            "Nostr discovery relay transport not wired; returning no events (relays=%s, since=%s)",
            relays,
            since.isoformat(),
        )
        return []


class NoopMetadataResolver:
    """Resolver that marks zap capability as unknown when metadata is unavailable."""

    def resolve_author_metadata(self, pubkey: str) -> dict[str, Any] | None:
        return None


@dataclass
class HeraldDiscoveryConfig:
    """Runtime configuration for discovery and zap suggestion policy."""

    declared_herald_pubkey: str = DECLARED_HERALD_PUBKEY
    zap_mode: str = "dry_run"
    relay_urls: list[str] = field(default_factory=lambda: list(DEFAULT_RELAYS))
    alignment_hashtags: list[str] = field(default_factory=lambda: list(DEFAULT_HASHTAGS))
    alignment_keywords: list[str] = field(default_factory=lambda: list(DEFAULT_KEYWORDS))
    spam_terms: list[str] = field(default_factory=lambda: list(DEFAULT_SPAM_TERMS))
    search_window_hours: int = 72
    min_alignment_score: float = 2.0
    zap_daily_budget_sats: int = 500
    zap_max_per_day: int = 3
    zap_max_per_author_window_hours: int = 24
    weak_zap_sats: int = 21
    strong_zap_sats: int = 69
    direct_zap_sats: int = 210
    zap_comments: list[str] = field(
        default_factory=lambda: [
            "Signal boost for Bitcoin-native agent identity.",
            "Aligned with machine-native Bitcoin identity and execution.",
            "Useful work for the Bitcoin agent stack.",
        ]
    )
    state_file: Path = Path("data/herald_nostr_discovery_state.json")

    @classmethod
    def from_env(cls) -> "HeraldDiscoveryConfig":
        return cls(
            zap_mode=os.getenv("HERALD_ZAP_MODE", "dry_run").strip().lower(),
            relay_urls=_csv_env("HERALD_RELAY_URLS", DEFAULT_RELAYS),
            alignment_hashtags=_csv_env("HERALD_ALIGNMENT_HASHTAGS", DEFAULT_HASHTAGS),
            alignment_keywords=_csv_env("HERALD_ALIGNMENT_KEYWORDS", DEFAULT_KEYWORDS),
            spam_terms=_csv_env("HERALD_SPAM_TERMS", DEFAULT_SPAM_TERMS),
            search_window_hours=_int_env("HERALD_SEARCH_WINDOW_HOURS", 72),
            zap_daily_budget_sats=_int_env("HERALD_ZAP_DAILY_BUDGET_SATS", 500),
            zap_max_per_day=_int_env("HERALD_ZAP_MAX_PER_DAY", 3),
            zap_max_per_author_window_hours=_int_env("HERALD_ZAP_MAX_PER_AUTHOR_WINDOW_HOURS", 24),
            state_file=Path(os.getenv("HERALD_DISCOVERY_STATE_FILE", "data/herald_nostr_discovery_state.json")),
            weak_zap_sats=_int_env("HERALD_ZAP_WEAK_SATS", 21),
            strong_zap_sats=_int_env("HERALD_ZAP_STRONG_SATS", 69),
            direct_zap_sats=_int_env("HERALD_ZAP_DIRECT_SATS", 210),
        )


@dataclass
class CandidateAssessment:
    event_id: str
    author_pubkey: str
    event_created_at: str
    matched_hashtags: list[str]
    matched_keywords: list[str]
    score: float
    reasons: list[str]
    zap_eligible: str
    suggested_zap_amount_sats: int
    suggested_comment: str
    action_taken: str
    action_reason: str
    discovered_at: str
    last_evaluated_at: str


class DiscoveryStateStore:
    """JSON-backed deduplicated audit log for discovery decisions."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"events": {}, "zaps": [], "meta": {"created_at": _utc_now_iso()}}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            logger.warning("Invalid discovery state JSON at %s, resetting", self.path)
            return {"events": {}, "zaps": [], "meta": {"created_at": _utc_now_iso()}}

    def save(self, state: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")

    def has_seen_event(self, event_id: str) -> bool:
        return event_id in self.load().get("events", {})

    def upsert_assessment(self, assessment: CandidateAssessment) -> None:
        state = self.load()
        events = state.setdefault("events", {})
        events[assessment.event_id] = asdict(assessment)
        self.save(state)

    def recent_assessments(self, limit: int = 25) -> list[dict[str, Any]]:
        events = list(self.load().get("events", {}).values())
        events.sort(key=lambda row: row.get("last_evaluated_at", ""), reverse=True)
        return events[:limit]

    def count_real_zaps_today(self) -> int:
        today = datetime.now(timezone.utc).date().isoformat()
        return sum(
            1
            for row in self.load().get("events", {}).values()
            if row.get("action_taken") == "zap_sent" and str(row.get("last_evaluated_at", "")).startswith(today)
        )

    def author_zapped_within_window(self, author_pubkey: str, hours: int) -> bool:
        threshold = datetime.now(timezone.utc) - timedelta(hours=hours)
        for row in self.load().get("events", {}).values():
            if row.get("author_pubkey") != author_pubkey:
                continue
            if row.get("action_taken") != "zap_sent":
                continue
            evaluated_at = _parse_iso(row.get("last_evaluated_at"))
            if evaluated_at and evaluated_at >= threshold:
                return True
        return False


class HeraldNostrDiscoveryEngine:
    """Discovery and conservative zap suggestion engine for Herald."""

    def __init__(
        self,
        config: HeraldDiscoveryConfig | None = None,
        relay_client: RelayDiscoveryClient | None = None,
        metadata_resolver: MetadataResolver | None = None,
        store: DiscoveryStateStore | None = None,
    ):
        self.config = config or HeraldDiscoveryConfig.from_env()
        self.relay_client = relay_client or NoopRelayDiscoveryClient()
        self.metadata_resolver = metadata_resolver or NoopMetadataResolver()
        self.store = store or DiscoveryStateStore(self.config.state_file)

    def discover_and_evaluate(self) -> list[CandidateAssessment]:
        now = datetime.now(timezone.utc)
        since = now - timedelta(hours=self.config.search_window_hours)
        events = self.relay_client.search_recent_notes(
            relays=self.config.relay_urls,
            hashtags=self.config.alignment_hashtags,
            keywords=self.config.alignment_keywords,
            since=since,
        )

        assessed: list[CandidateAssessment] = []
        for event in events:
            row = self._evaluate_event(event, now=now, since=since)
            if row is None:
                continue
            self.store.upsert_assessment(row)
            assessed.append(row)

        assessed.sort(key=lambda item: item.score, reverse=True)
        return assessed

    def _evaluate_event(self, event: dict[str, Any], *, now: datetime, since: datetime) -> CandidateAssessment | None:
        event_id = str(event.get("id") or "").strip()
        if not event_id:
            return None

        created_at = _coerce_timestamp(event.get("created_at"))
        if not created_at or created_at < since:
            return None

        if self.store.has_seen_event(event_id):
            return None

        author_pubkey = str(event.get("pubkey") or "").strip().lower()
        content = str(event.get("content") or "")
        tags = event.get("tags") or []

        score_result = score_alignment(
            content=content,
            tags=tags,
            alignment_hashtags=self.config.alignment_hashtags,
            alignment_keywords=self.config.alignment_keywords,
            spam_terms=self.config.spam_terms,
        )

        if score_result["score"] < self.config.min_alignment_score:
            return None

        zap_eligible = assess_zap_eligibility(author_pubkey, self.metadata_resolver)
        suggested = suggest_zap_policy(
            score=score_result["score"],
            zap_eligible=zap_eligible,
            cfg=self.config,
        )
        action_taken, action_reason = self._decide_action(
            event_id=event_id,
            author_pubkey=author_pubkey,
            zap_eligible=zap_eligible,
            suggested_sats=suggested["suggested_zap_amount_sats"],
        )

        return CandidateAssessment(
            event_id=event_id,
            author_pubkey=author_pubkey,
            event_created_at=created_at.isoformat(),
            matched_hashtags=score_result["matched_hashtags"],
            matched_keywords=score_result["matched_keywords"],
            score=score_result["score"],
            reasons=score_result["reasons"],
            zap_eligible=zap_eligible,
            suggested_zap_amount_sats=suggested["suggested_zap_amount_sats"],
            suggested_comment=suggested["suggested_comment"],
            action_taken=action_taken,
            action_reason=action_reason,
            discovered_at=now.isoformat(),
            last_evaluated_at=now.isoformat(),
        )

    def _decide_action(self, *, event_id: str, author_pubkey: str, zap_eligible: str, suggested_sats: int) -> tuple[str, str]:
        if self.config.zap_mode in {"off", "dry_run"}:
            return "dry_run_candidate", f"zap_mode={self.config.zap_mode}"

        if self.config.zap_mode != "live":
            return "skipped", "invalid_zap_mode"

        if zap_eligible != "true":
            return "skipped", "zap_not_eligible"

        if self.store.count_real_zaps_today() >= self.config.zap_max_per_day:
            return "skipped", "daily_zap_limit_reached"

        if self.store.author_zapped_within_window(author_pubkey, self.config.zap_max_per_author_window_hours):
            return "skipped", "author_recently_zapped"

        if suggested_sats > self.config.zap_daily_budget_sats:
            return "skipped", "daily_budget_too_low_for_suggestion"

        # Phase 2 scaffold only: no live payment transport/signing wired yet.
        return "skipped", "live_zap_transport_not_implemented"

    def prepare_zap_request(self, assessment: CandidateAssessment) -> dict[str, Any]:
        return {
            "status": "prepared",
            "mode": self.config.zap_mode,
            "declared_herald_pubkey": self.config.declared_herald_pubkey,
            "event_id": assessment.event_id,
            "author_pubkey": assessment.author_pubkey,
            "amount_sats": assessment.suggested_zap_amount_sats,
            "comment": assessment.suggested_comment,
            "ready_for_execution": False,
            "reason": "Phase 2 signer/wallet transport not wired",
        }

    def execute_zap(self, assessment: CandidateAssessment) -> dict[str, Any]:
        return {
            "status": "not_executed",
            "mode": self.config.zap_mode,
            "event_id": assessment.event_id,
            "declared_herald_pubkey": self.config.declared_herald_pubkey,
            "payment_sent": False,
            "reason": "dry_run_only_or_not_implemented",
        }


def score_alignment(
    *,
    content: str,
    tags: list[Any],
    alignment_hashtags: list[str],
    alignment_keywords: list[str],
    spam_terms: list[str],
) -> dict[str, Any]:
    """Conservative post relevance scoring for aligned posts."""

    text = (content or "").strip().lower()
    matched_hashtags: list[str] = []
    matched_keywords: list[str] = []
    reasons: list[str] = []
    score = 0.0

    extracted_hashtags = set(_extract_hashtags(text))
    extracted_hashtags.update(_extract_tag_hashtags(tags))

    for hashtag in alignment_hashtags:
        tag = hashtag.strip().lower().lstrip("#")
        if tag and tag in extracted_hashtags:
            matched_hashtags.append(tag)
            reasons.append(f"hashtag:{tag}")
            score += 0.8

    for keyword in alignment_keywords:
        kw = keyword.strip().lower()
        if kw and kw in text:
            matched_keywords.append(keyword)
            reasons.append(f"keyword:{keyword}")
            score += 1.4

    if "hodlxxi" in text or "ubid" in text:
        score += 3.0
        reasons.append("direct_alignment:hodlxxi_or_ubid")

    if "bitcoin" in text and "agent" in text:
        score += 1.2
        reasons.append("compound:bitcoin+agent")
    if "lightning" in text and "identity" in text:
        score += 1.0
        reasons.append("compound:lightning+identity")
    if "nostr" in text and "agent" in text:
        score += 1.0
        reasons.append("compound:nostr+agent")

    if any(term.lower() in text for term in spam_terms):
        score -= 5.0
        reasons.append("negative:spam_term")

    if len(re.findall(r"\w+", text)) < 4:
        score -= 1.5
        reasons.append("negative:low_information")

    return {
        "score": round(score, 2),
        "matched_hashtags": sorted(set(matched_hashtags)),
        "matched_keywords": sorted(set(matched_keywords)),
        "reasons": reasons,
    }


def assess_zap_eligibility(author_pubkey: str, resolver: MetadataResolver) -> str:
    """Return true/false/unknown based on conservative metadata evidence."""

    metadata = resolver.resolve_author_metadata(author_pubkey)
    if not metadata:
        return "unknown"

    lud16 = str(metadata.get("lud16") or "").strip()
    lud06 = str(metadata.get("lud06") or "").strip()
    lnurl_pay = metadata.get("lnurl_pay")

    if lud16 or lud06 or lnurl_pay:
        return "true"

    if metadata:
        return "false"

    return "unknown"


def suggest_zap_policy(*, score: float, zap_eligible: str, cfg: HeraldDiscoveryConfig) -> dict[str, Any]:
    """Tiered suggested zap amounts with dry-run-safe rationale."""

    if score >= 7.0:
        amount = cfg.direct_zap_sats
        rationale = "direct_alignment"
    elif score >= 4.0:
        amount = cfg.strong_zap_sats
        rationale = "strong_alignment"
    else:
        amount = cfg.weak_zap_sats
        rationale = "weak_alignment"

    comment = cfg.zap_comments[0]
    if rationale == "strong_alignment" and len(cfg.zap_comments) > 1:
        comment = cfg.zap_comments[1]
    elif rationale == "direct_alignment" and len(cfg.zap_comments) > 2:
        comment = cfg.zap_comments[2]

    confidence = "medium"
    if score >= 7.0 and zap_eligible == "true":
        confidence = "high"
    elif score < 4.0 or zap_eligible == "unknown":
        confidence = "low"

    return {
        "suggested_zap_amount_sats": amount,
        "suggested_comment": comment,
        "confidence": confidence,
        "rationale": rationale,
    }


def _extract_hashtags(text: str) -> list[str]:
    return [match.group(1).lower() for match in re.finditer(r"#([a-zA-Z0-9_]+)", text or "")]


def _extract_tag_hashtags(tags: list[Any]) -> list[str]:
    found: list[str] = []
    for tag in tags:
        if not isinstance(tag, list) or len(tag) < 2:
            continue
        if str(tag[0]).lower() == "t":
            found.append(str(tag[1]).strip().lower())
    return found


def _csv_env(name: str, default: list[str]) -> list[str]:
    raw = os.getenv(name, "")
    if not raw.strip():
        return list(default)
    values = [item.strip() for item in raw.split(",") if item.strip()]
    return values or list(default)


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name, "")
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be integer (got {raw!r})") from exc


def _coerce_timestamp(value: Any) -> datetime | None:
    try:
        if isinstance(value, datetime):
            dt = value
        else:
            dt = datetime.fromtimestamp(int(value), tz=timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (TypeError, ValueError, OSError):
        return None


def _parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
