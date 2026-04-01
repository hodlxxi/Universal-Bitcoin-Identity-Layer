"""Runtime state + helpers for presence and chat."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Set

EXPIRY_SECONDS = 45

ACTIVE_SOCKETS: Dict[str, str] = {}
ONLINE_USERS: Set[str] = set()
ONLINE_META: Dict[str, str] = {}
ONLINE_USER_META: Dict[str, Dict[str, Any]] = {}
CHAT_HISTORY: List[Dict[str, Any]] = []


def classify_presence(pubkey: str | None, access_level: str | None, pin_map: Dict[str, Any] | None = None) -> str:
    """
    Decide chip color role for a user:
      full    -> Orange
      limited -> Green
      pin     -> White (PIN guest)
      random  -> Red   (anonymous guest like 'guest-xxxx')
    """
    pk = (pubkey or "").strip()
    lvl = (access_level or "").strip().lower()

    if not pk:
        return "limited"

    if pk.startswith("guest-"):
        return "random"

    if pk.isdigit():
        return "pin"

    if pin_map and pk in pin_map:
        return "pin"

    if lvl == "full":
        return "full"
    if lvl == "limited":
        return "limited"

    return "limited"


def build_online_list_payload(
    online_users: Set[str],
    online_meta: Dict[str, str],
    online_user_meta: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = [{"pubkey": pk, "role": online_meta.get(pk, "limited")} for pk in online_users]
    for it in items:
        if isinstance(it, dict) and "pubkey" in it and "label" not in it:
            meta = online_user_meta.get(it["pubkey"], {})
            it["label"] = meta.get("label")
    return items


def normalize_chat_text(data: Any) -> str:
    if isinstance(data, dict):
        return (data.get("text") or "").strip()
    return str(data or "").strip()


def format_chat_message(pubkey: str, text: str) -> Dict[str, Any]:
    return {"pubkey": pubkey, "text": str(text), "ts": time.time()}


def purge_old_messages() -> None:
    """Keep only messages newer than EXPIRY_SECONDS."""
    now = time.time()

    def is_fresh(m: Any) -> bool:
        ts = m.get("ts") if isinstance(m, dict) else None
        return ts is not None and (now - ts) <= EXPIRY_SECONDS

    CHAT_HISTORY[:] = [m for m in CHAT_HISTORY if is_fresh(m)]
