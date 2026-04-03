"""Shared mutable Socket.IO/chat presence state.

This module owns runtime in-memory state containers used by app.app and
app.socket_handlers.
"""

from typing import Any, Dict, List, Set

ACTIVE_SOCKETS: Dict[str, str] = {}
ONLINE_USERS: Set[str] = set()
ONLINE_META: Dict[str, str] = {}
ONLINE_USER_META: Dict[str, Dict[str, Any]] = {}
CHAT_HISTORY: List[Dict[str, Any]] = []
