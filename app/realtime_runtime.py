"""Shared runtime services for realtime chat/presence/socket surfaces.

This module provides runtime-owned helpers/state that were previously sourced
from app.app at import time.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict

from app.socket_state import CHAT_HISTORY

logger = logging.getLogger(__name__)

EXPIRY_SECONDS = int(os.getenv("CHAT_EXPIRY_SECONDS", "45"))

# Room management: room_id -> {pubkeys: set, created_at: timestamp}
CALL_ROOMS: Dict[str, Dict[str, Any]] = {}
MAX_ROOM_SIZE = 4

_socketio = None


def set_socketio(socketio) -> None:
    """Store the runtime Socket.IO instance for helper-level broadcasts."""
    global _socketio
    _socketio = socketio


def get_socketio():
    """Get the runtime Socket.IO instance."""
    return _socketio


def cleanup_old_rooms() -> None:
    """Remove rooms older than 1 hour with no participants."""
    now = time.time()
    to_remove = []
    for room_id, room_data in list(CALL_ROOMS.items()):
        age = now - room_data.get("created_at", now)
        if age > 3600 and len(room_data.get("pubkeys", set())) == 0:
            to_remove.append(room_id)
    for room_id in to_remove:
        CALL_ROOMS.pop(room_id, None)
    if to_remove:
        logger.info("Cleaned up %s old empty rooms", len(to_remove))


def truncate_key(key: str, head: int = 6, tail: int = 4) -> str:
    if len(key) <= head + tail:
        return key
    return f"{key[:head]}…{key[-tail:]}"


def classify_presence(pubkey: str | None, access_level: str | None) -> str:
    """Return role bucket for presence chips."""
    pk = (pubkey or "").strip()
    lvl = (access_level or "").strip().lower()

    if not pk:
        return "limited"

    if pk.startswith("guest-"):
        return "random"

    if pk.isdigit():
        return "pin"

    if lvl == "full":
        return "full"
    if lvl == "limited":
        return "limited"

    return "limited"


def purge_old_messages() -> None:
    """Keep only messages newer than EXPIRY_SECONDS."""
    now = time.time()

    def is_fresh(msg):
        ts = msg.get("ts") if isinstance(msg, dict) else None
        return ts is not None and (now - ts) <= EXPIRY_SECONDS

    CHAT_HISTORY[:] = [msg for msg in CHAT_HISTORY if is_fresh(msg)]
