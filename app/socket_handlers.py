"""Socket.IO handler logic helpers."""

from __future__ import annotations

import time

from flask import request, session
from flask_socketio import emit

from app.realtime_runtime import (
    CALL_ROOMS,
    MAX_ROOM_SIZE,
    classify_presence,
    cleanup_old_rooms,
    get_socketio,
    logger,
    purge_old_messages,
    set_socketio,
    truncate_key,
)
from app.socket_state import ACTIVE_SOCKETS, CHAT_HISTORY, ONLINE_META, ONLINE_USER_META, ONLINE_USERS


def _broadcast_chat_message(text: str):
    """Shared logic to append to history and broadcast to all clients."""
    socketio = get_socketio()
    logger.info(f"CHAT DEBUG: broadcast start sid={getattr(request, 'sid', None)} text={text!r}")

    if socketio is None:
        logger.warning("CHAT DEBUG: SocketIO runtime is not initialized")
        return

    pk = session.get("logged_in_pubkey")
    logger.info(f"CHAT DEBUG: session pubkey={pk!r}")

    if not pk:
        logger.warning("CHAT DEBUG: Message received from unauthenticated user")
        return

    m = {"pubkey": pk, "text": str(text), "ts": time.time()}
    CHAT_HISTORY.append(m)
    purge_old_messages()
    logger.info(f"CHAT DEBUG: appended history len={len(CHAT_HISTORY)} payload={m}")

    # Old clients listen to "message", new UI listens to both
    socketio.emit("message", m)
    socketio.emit("chat:message", m)
    logger.info("CHAT DEBUG: emitted message and chat:message")


def _handle_chat_send(data):
    """
    New handler for our front-end.

    Client sends: socket.emit('chat:send', { text: 'hello' })
    """
    try:
        logger.info(f"CHAT DEBUG: raw incoming data={data!r} sid={getattr(request, 'sid', None)}")
        if isinstance(data, dict):
            text = (data.get("text") or "").strip()
        else:
            text = str(data or "").strip()

        logger.info(f"CHAT DEBUG: normalized text={text!r}")

        if not text:
            logger.warning("CHAT DEBUG: empty text, ignoring")
            return

        _broadcast_chat_message(text)
    except Exception as e:
        logger.error(f"Error handling chat:send: {e}", exc_info=True)


def _build_online_list(online_users, online_meta, online_user_meta):
    online_list = [{"pubkey": pk, "role": online_meta.get(pk, "limited")} for pk in online_users]
    # PRESENCE_LABEL_BROADCAST_V2: ensure online:list items include label when available
    try:
        for it in online_list:
            if isinstance(it, dict) and "pubkey" in it and "label" not in it:
                meta = online_user_meta.get(it["pubkey"], {})
                it["label"] = meta.get("label")
    except Exception:
        pass
    return online_list


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
    emit("online:list", _build_online_list(ONLINE_USERS, ONLINE_META, ONLINE_USER_META), broadcast=True)


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

        emit("online:list", _build_online_list(ONLINE_USERS, ONLINE_META, ONLINE_USER_META), broadcast=True)


def sids_for_pubkey(pk: str):
    """Get all socket IDs for a given pubkey."""
    return [sid for sid, who in ACTIVE_SOCKETS.items() if who == pk]


def register_socket_handlers(socketio):
    set_socketio(socketio)

    @socketio.on("rtc:offer")
    def rtc_offer(data):
        """data = {to: , from: , offer: {...}}"""
        try:
            target = (data or {}).get("to")
            if not target:
                logger.warning("RTC offer received without target")
                return
            for sid in sids_for_pubkey(target):
                socketio.emit("rtc:offer", data, to=sid)
        except Exception as e:
            logger.error(f"Error in rtc_offer: {e}", exc_info=True)

    @socketio.on("rtc:answer")
    def rtc_answer(data):
        """data = {to: , from: , answer: {...}}"""
        try:
            target = (data or {}).get("to")
            if not target:
                logger.warning("RTC answer received without target")
                return
            for sid in sids_for_pubkey(target):
                socketio.emit("rtc:answer", data, to=sid)
        except Exception as e:
            logger.error(f"Error in rtc_answer: {e}", exc_info=True)

    @socketio.on("rtc:ice")
    def rtc_ice(data):
        """data = {to: , from: , candidate: {...}}"""
        try:
            target = (data or {}).get("to")
            if not target:
                logger.warning("RTC ICE candidate received without target")
                return
            for sid in sids_for_pubkey(target):
                socketio.emit("rtc:ice", data, to=sid)
        except Exception as e:
            logger.error(f"Error in rtc_ice: {e}", exc_info=True)

    @socketio.on("rtc:hangup")
    def rtc_hangup(data):
        """data = {to: , from: }"""
        try:
            target = (data or {}).get("to")
            if not target:
                logger.warning("RTC hangup received without target")
                return
            for sid in sids_for_pubkey(target):
                socketio.emit("rtc:hangup", data, to=sid)
        except Exception as e:
            logger.error(f"Error in rtc_hangup: {e}", exc_info=True)

    @socketio.on("rtc:join_room")
    def rtc_join_room(data):
        """
        Join a call room. data = {"room_id": str}
        - Creates the room if needed
        - Enforces MAX_ROOM_SIZE
        - Sends existing peers to the joiner via "rtc:room_peers"
        - Notifies others via "rtc:peer_joined"
        - For direct-* rooms, auto-sends an invite to the other pubkey
        """
        from flask_socketio import emit, join_room as flask_join_room
        from flask import request

        try:
            pubkey = session.get("logged_in_pubkey")
            if not pubkey:
                emit("rtc:error", {"error": "Not authenticated"})
                return

            room_id = (data or {}).get("room_id")
            if not room_id:
                emit("rtc:error", {"error": "No room_id provided"})
                return

            # Create room if needed
            if room_id not in CALL_ROOMS:
                CALL_ROOMS[room_id] = {"pubkeys": set(), "created_at": time.time()}

            room = CALL_ROOMS[room_id]

            # Capacity check
            if len(room["pubkeys"]) >= MAX_ROOM_SIZE and pubkey not in room["pubkeys"]:
                emit("rtc:error", {"error": "Room is full (max 4 participants)"})
                logger.warning(f"Room {room_id} is full, rejected {pubkey[:8]}")
                return

            # Add user to room
            room["pubkeys"].add(pubkey)
            flask_join_room(room_id)

            # Current peers (excluding the joiner)
            current_peers = [p for p in room["pubkeys"] if p != pubkey]

            logger.info(f"User {truncate_key(pubkey)} joined room {room_id}. " f"Participants: {len(room['pubkeys'])}")

            # Send the room peer list ONLY to the joiner
            emit(
                "rtc:room_peers",
                {"room_id": room_id, "peers": current_peers},
                room=request.sid,
            )

            # Notify others that a peer joined
            emit(
                "rtc:peer_joined",
                {"room_id": room_id, "pubkey": pubkey},
                room=room_id,
                include_self=False,
            )

            # Auto-invite for direct-* (2-party) calls
            if room_id.startswith("direct-") and len(room["pubkeys"]) == 1:
                # Look for another online pubkey whose full value is embedded in room_id.
                other_pubkey = None
                for candidate in set(ACTIVE_SOCKETS.values()):
                    if candidate != pubkey and candidate in room_id:
                        other_pubkey = candidate
                        break

                if other_pubkey:
                    logger.info(f"Auto-inviting {truncate_key(other_pubkey)} to join {room_id}")
                    payload = {"room_id": room_id, "from": pubkey}
                    for sid in sids_for_pubkey(other_pubkey):
                        emit("rtc:call_invite", payload, room=sid)

        except Exception as e:
            logger.error(f"Error in rtc_join_room: {e}", exc_info=True)
            emit("rtc:error", {"error": "Failed to join room"})

    @socketio.on("rtc:leave_room")
    def rtc_leave_room(data):
        """Leave a call room. data = {"room_id": str}"""
        from flask_socketio import emit, leave_room as flask_leave_room
        from flask import request

        try:
            pubkey = session.get("logged_in_pubkey")
            if not pubkey:
                return

            room_id = (data or {}).get("room_id")
            if not room_id:
                return

            room = CALL_ROOMS.get(room_id)
            if not room:
                return

            if pubkey in room["pubkeys"]:
                room["pubkeys"].remove(pubkey)

            flask_leave_room(room_id)
            logger.info(f"User {truncate_key(pubkey)} left room {room_id}")

            emit(
                "rtc:peer_left",
                {"room_id": room_id, "pubkey": pubkey},
                room=room_id,
                include_self=False,
            )

            # If room is empty, mark for cleanup
            if not room["pubkeys"]:
                room["created_at"] = time.time()
                cleanup_old_rooms()

        except Exception as e:
            logger.error(f"Error in rtc_leave_room: {e}", exc_info=True)

    @socketio.on("rtc:signal")
    def rtc_signal(data):
        """
        Generic WebRTC signaling for group calls.
        data = {
          "room_id": str,
          "to": remote_pubkey,
          "type": "offer"|"answer"|"ice",
          "payload": {...}
        }
        """
        from flask_socketio import emit

        try:
            pubkey = session.get("logged_in_pubkey")
            if not pubkey:
                emit("rtc:error", {"error": "Not authenticated"})
                return

            room_id = (data or {}).get("room_id")
            target_pubkey = (data or {}).get("to")
            signal_type = (data or {}).get("type")
            payload = (data or {}).get("payload")

            if not room_id or not target_pubkey or not signal_type:
                emit("rtc:error", {"error": "Invalid signal payload"})
                return

            room = CALL_ROOMS.get(room_id)
            if not room or pubkey not in room["pubkeys"]:
                emit("rtc:error", {"error": "Not in this room"})
                return

            if target_pubkey not in room["pubkeys"]:
                emit("rtc:error", {"error": "Target not in this room"})
                return

            outbound = {
                "room_id": room_id,
                "from": pubkey,
                "to": target_pubkey,
                "type": signal_type,
                "payload": payload,
            }

            emit(
                "rtc:signal",
                outbound,
                room=room_id,
                include_self=False,
            )

        except Exception as e:
            logger.error(f"Error in rtc_signal: {e}", exc_info=True)
            emit("rtc:error", {"error": "Signaling failed"})

    @socketio.on("rtc:invite")
    def rtc_invite(data):
        """Forward call invitation to specific user"""
        from flask_socketio import emit

        to_pubkey = data.get("to")
        room_id = data.get("room_id")
        from_pubkey = session.get("logged_in_pubkey")
        if not to_pubkey or not room_id or not from_pubkey:
            return
        # Use sids_for_pubkey like other handlers
        for sid in sids_for_pubkey(to_pubkey):
            emit("rtc:invite", {"room_id": room_id, "from": from_pubkey, "from_name": from_pubkey[-8:]}, room=sid)

    @socketio.on("rtc:call_invite")
    def rtc_call_invite(data):
        """Alias for rtc:invite used by newer browser flows."""
        from flask_socketio import emit

        to_pubkey = data.get("to")
        room_id = data.get("room_id")
        from_pubkey = session.get("logged_in_pubkey")
        if not to_pubkey or not room_id or not from_pubkey:
            return
        for sid in sids_for_pubkey(to_pubkey):
            emit("rtc:call_invite", {"room_id": room_id, "from": from_pubkey, "from_name": from_pubkey[-8:]}, room=sid)

    @socketio.on("message")
    def handle_message(msg_text):
        """Legacy handler for default Socket.IO 'message' event."""
        try:
            _broadcast_chat_message(msg_text)
        except Exception as e:
            logger.error(f"Error handling message: {e}", exc_info=True)

    @socketio.on("chat:send")
    def handle_chat_send(data):
        """Thin decorator wrapper for chat send logic."""
        _handle_chat_send(data)

    @socketio.on("connect")
    def on_connect(auth=None):
        return _handle_socket_connect(auth=auth)

    @socketio.on("disconnect")
    def on_disconnect(*args, **kwargs):
        return _handle_socket_disconnect(*args, **kwargs)
