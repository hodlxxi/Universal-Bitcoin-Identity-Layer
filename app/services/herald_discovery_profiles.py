"""Targeted Herald discovery profiles for read-only candidate scans."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class HeraldDiscoveryProfile:
    """Static profile used to focus discovery on aligned content."""

    keywords: tuple[str, ...]
    hashtags: tuple[str, ...]
    min_score: float
    description: str

    def as_dict(self) -> dict[str, object]:
        return {
            "keywords": list(self.keywords),
            "hashtags": list(self.hashtags),
            "min_score": float(self.min_score),
            "description": self.description,
        }


@dataclass(frozen=True)
class ResolvedDiscoveryProfiles:
    """Resolved multi-profile selection with merged effective filters."""

    target_profiles: list[str]
    keywords: list[str]
    hashtags: list[str]
    min_score: float


PROFILE_DEFINITIONS: dict[str, HeraldDiscoveryProfile] = {
    "bitcoin-agents": HeraldDiscoveryProfile(
        keywords=(
            "bitcoin agent",
            "lightning agent",
            "autonomous agent",
            "machine payments",
            "signed receipts",
            "zap",
            "lnurl",
            "nostr agent",
        ),
        hashtags=("bitcoin", "nostr", "lightning", "agents", "ai"),
        min_score=2.0,
        description="Bitcoin-native agents, machine payments, and zap-adjacent note discovery.",
    ),
    "identity": HeraldDiscoveryProfile(
        keywords=(
            "key-based identity",
            "sovereign identity",
            "nostr identity",
            "pubkey identity",
            "attestations",
            "reputation",
            "verifiable agent",
            "oidc",
            "oauth",
        ),
        hashtags=("identity", "nostr", "bitcoin", "reputation"),
        min_score=2.0,
        description="Sovereign and pubkey-based identity discussions relevant to agent trust.",
    ),
    "lightning": HeraldDiscoveryProfile(
        keywords=(
            "lightning",
            "lightning payments",
            "lnurl",
            "zaps",
            "zap receipt",
            "bolt11",
            "lnd",
            "machine payments",
        ),
        hashtags=("lightning", "bitcoin", "zaps", "lnurl"),
        min_score=2.0,
        description="Lightning, LNURL, and zap-adjacent payment conversations.",
    ),
    "ai-agents": HeraldDiscoveryProfile(
        keywords=(
            "autonomous AI",
            "AI agent",
            "agent payments",
            "agent identity",
            "machine customer",
            "tool calling",
            "signed receipt",
        ),
        hashtags=("ai", "agents", "bitcoin", "nostr"),
        min_score=2.0,
        description="AI agent execution, payments, and identity conversations.",
    ),
    "nostr-dev": HeraldDiscoveryProfile(
        keywords=(
            "nostr relay",
            "nostr client",
            "nip",
            "zaps",
            "pubkey",
            "npub",
            "nprofile",
            "nostr dev",
        ),
        hashtags=("nostr", "nostrdev", "bitcoin", "zaps"),
        min_score=2.0,
        description="Nostr protocol, relay, client, and developer ecosystem discussions.",
    ),
    "volya": HeraldDiscoveryProfile(
        keywords=(
            "universal bitcoin identity",
            "bitcoin-native identity",
            "volya",
            "volya.id",
            "hodlxxi",
            "ubid",
            "no kyc identity",
            "my key is my id",
        ),
        hashtags=("bitcoin", "identity", "nostr", "cypherpunk"),
        min_score=1.0,
        description="Volya.ID, HODLXXI, UBID, and Bitcoin-native identity alignment.",
    ),
}


def available_target_profiles() -> list[str]:
    return list(PROFILE_DEFINITIONS.keys())


def list_target_profiles() -> dict[str, dict[str, object]]:
    return {name: profile.as_dict() for name, profile in PROFILE_DEFINITIONS.items()}


def resolve_target_profiles(
    profile_names: Iterable[str],
    *,
    extra_keywords: Iterable[str] | None = None,
    extra_hashtags: Iterable[str] | None = None,
) -> ResolvedDiscoveryProfiles:
    selected_profiles = _dedupe_profile_names(profile_names)
    keywords: list[str] = []
    hashtags: list[str] = []
    min_scores: list[float] = []

    for profile_name in selected_profiles:
        profile = PROFILE_DEFINITIONS[profile_name]
        _extend_unique(keywords, profile.keywords, key=lambda value: value.strip().lower())
        _extend_unique(hashtags, profile.hashtags, key=_normalize_hashtag)
        min_scores.append(float(profile.min_score))

    if extra_keywords is not None:
        _extend_unique(keywords, extra_keywords, key=lambda value: value.strip().lower())
    if extra_hashtags is not None:
        _extend_unique(hashtags, extra_hashtags, key=_normalize_hashtag, transform=_normalize_hashtag)

    return ResolvedDiscoveryProfiles(
        target_profiles=selected_profiles,
        keywords=keywords,
        hashtags=hashtags,
        min_score=min(min_scores) if min_scores else 0.0,
    )


def _dedupe_profile_names(profile_names: Iterable[str]) -> list[str]:
    selected: list[str] = []
    seen: set[str] = set()
    for raw_name in profile_names:
        name = str(raw_name).strip()
        if not name or name in seen:
            continue
        if name not in PROFILE_DEFINITIONS:
            raise KeyError(name)
        selected.append(name)
        seen.add(name)
    return selected


def _extend_unique(
    target: list[str],
    values: Iterable[str],
    *,
    key,
    transform=None,
) -> None:
    seen = {key(item) for item in target}
    for raw_value in values:
        value = str(raw_value).strip()
        if not value:
            continue
        normalized = key(value)
        if not normalized or normalized in seen:
            continue
        target.append(transform(value) if transform is not None else value)
        seen.add(normalized)


def _normalize_hashtag(value: str) -> str:
    return str(value).strip().lower().lstrip("#")
