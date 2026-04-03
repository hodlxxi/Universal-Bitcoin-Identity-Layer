"""Socket handler logic module state imports.

This module intentionally remains logic-only; Socket.IO decorator registration
stays in app.app.
"""

from app.socket_state import ACTIVE_SOCKETS, CHAT_HISTORY, ONLINE_META, ONLINE_USER_META, ONLINE_USERS

__all__ = [
    "ACTIVE_SOCKETS",
    "ONLINE_USERS",
    "ONLINE_META",
    "ONLINE_USER_META",
    "CHAT_HISTORY",
]
