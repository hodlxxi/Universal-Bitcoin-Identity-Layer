import time

from flask import request, session
from flask_socketio import emit

from app.app import (
    ACTIVE_SOCKETS,
    CHAT_HISTORY,
    ONLINE_META,
    ONLINE_USER_META,
    ONLINE_USERS,
    classify_presence,
    logger,
    purge_old_messages,
    socketio,
)


def _broadcast_chat_message(text: str):
    """Shared logic to append to history and broadcast to all clients."""
    pk = session.get("logged_in_pubkey")
    if not pk:
        logger.warning("Message received from unauthenticated user")
        return

    m = {"pubkey": pk, "text": str(text), "ts": time.time()}
    CHAT_HISTORY.append(m)
    purge_old_messages()

    # Old clients listen to "message", new UI listens to both
    socketio.emit("message", m)
    socketio.emit("chat:message", m)


def _handle_chat_send(data):
    """
    New handler for our front-end.

    Client sends: socket.emit('chat:send', { text: 'hello' })
    """
    try:
        # data can be dict or string; normalize to text
        if isinstance(data, dict):
            text = (data.get("text") or "").strip()
        else:
            text = str(data or "").strip()

        if not text:
            return

        _broadcast_chat_message(text)
    except Exception as e:
        logger.error(f"Error handling chat:send: {e}", exc_info=True)


def _handle_socket_connect(auth=None):
    pubkey = session.get("logged_in_pubkey", "")
    level = session.get("access_level")
    if not pubkey:
        return False
    role = classify_presence(pubkey, level)

    ACTIVE_SOCKETS[request.sid] = pubkey
    ONLINE_USERS.add(pubkey)
    ONLINE_META[pubkey] = role

    # Use emit() not socketio.emit()
    # PRESENCE_LABEL_BROADCAST_V2: attach label to presence join payload (PIN guests)
    label = None
    try:
        if session.get("login_method") == "pin_guest":
            label = session.get("guest_label")
    except Exception:
        label = None
    try:
        ONLINE_USER_META[pubkey] = {"role": role, "label": label}
    except Exception:
        pass
    emit("user:joined", {"pubkey": pubkey, "role": role, "label": label}, broadcast=True)
    online_list = [{"pubkey": pk, "role": ONLINE_META.get(pk, "limited")} for pk in ONLINE_USERS]
    # PRESENCE_LABEL_BROADCAST_V2: ensure online:list items include label when available
    try:
        for it in online_list:
            if isinstance(it, dict) and "pubkey" in it and "label" not in it:
                meta = ONLINE_USER_META.get(it["pubkey"], {})
                it["label"] = meta.get("label")
    except Exception:
        pass
    emit("online:list", online_list, broadcast=True)


def _handle_socket_disconnect(*args, **kwargs):
    sid = request.sid
    pubkey = ACTIVE_SOCKETS.pop(sid, None)
    if not pubkey:
        return

    if pubkey not in ACTIVE_SOCKETS.values():
        ONLINE_USERS.discard(pubkey)
        ONLINE_META.pop(pubkey, None)

        # Use emit() not socketio.emit()
        emit("user:left", {"pubkey": pubkey}, broadcast=True)

        online_list = [{"pubkey": pk, "role": ONLINE_META.get(pk, "limited")} for pk in ONLINE_USERS]
        # PRESENCE_LABEL_BROADCAST_V2: ensure online:list items include label when available
        try:
            for it in online_list:
                if isinstance(it, dict) and "pubkey" in it and "label" not in it:
                    meta = ONLINE_USER_META.get(it["pubkey"], {})
                    it["label"] = meta.get("label")
        except Exception:
            pass
        emit("online:list", online_list, broadcast=True)
