from typing import Any, Dict, List, Set

ACTIVE_SOCKETS: Dict[str, str] = {}
ONLINE_USERS: Set[str] = set()
ONLINE_META: Dict[str, str] = {}
ONLINE_USER_META: Dict[str, Dict[str, str]] = {}
CHAT_HISTORY: List[Dict[str, Any]] = []
