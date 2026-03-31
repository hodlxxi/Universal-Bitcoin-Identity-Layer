"""Socket.IO handlers registered via dependency injection."""

from __future__ import annotations

import time

from flask import request, session
from flask_socketio import emit, join_room as flask_join_room, leave_room as flask_leave_room


def register_socket_handlers(
    socketio,
    *,
    logger,
    active_sockets,
    online_users,
    online_meta,
    online_user_meta,
    chat_history,
    call_rooms,
    max_room_size,
    classify_presence,
    purge_old_messages,
    cleanup_old_rooms,
    truncate_key,
):
    def sids_for_pubkey(pk: str):
        return [sid for sid, who in active_sockets.items() if who == pk]

    def broadcast_online_list():
        online_list = [{"pubkey": pk, "role": online_meta.get(pk, "limited")} for pk in online_users]
        try:
            for it in online_list:
                if isinstance(it, dict) and "pubkey" in it and "label" not in it:
                    meta = online_user_meta.get(it["pubkey"], {})
                    it["label"] = meta.get("label")
        except Exception:
            pass
        emit("online:list", online_list, broadcast=True)

    def broadcast_chat_message(text: str):
        pk = session.get("logged_in_pubkey")
        if not pk:
            logger.warning("Message received from unauthenticated user")
            return

        m = {"pubkey": pk, "text": str(text), "ts": time.time()}
        chat_history.append(m)
        purge_old_messages()
        socketio.emit("message", m)
        socketio.emit("chat:message", m)

    @socketio.on("rtc:offer")
    def rtc_offer(data):
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
        try:
            pubkey = session.get("logged_in_pubkey")
            if not pubkey:
                emit("rtc:error", {"error": "Not authenticated"})
                return

            room_id = (data or {}).get("room_id")
            if not room_id:
                emit("rtc:error", {"error": "No room_id provided"})
                return

            if room_id not in call_rooms:
                call_rooms[room_id] = {"pubkeys": set(), "created_at": time.time()}

            room = call_rooms[room_id]
            if len(room["pubkeys"]) >= max_room_size and pubkey not in room["pubkeys"]:
                emit("rtc:error", {"error": "Room is full (max 4 participants)"})
                logger.warning(f"Room {room_id} is full, rejected {pubkey[:8]}")
                return

            room["pubkeys"].add(pubkey)
            flask_join_room(room_id)
            current_peers = [p for p in room["pubkeys"] if p != pubkey]

            logger.info(f"User {truncate_key(pubkey)} joined room {room_id}. Participants: {len(room['pubkeys'])}")

            emit("rtc:room_peers", {"room_id": room_id, "peers": current_peers}, room=request.sid)
            emit("rtc:peer_joined", {"room_id": room_id, "pubkey": pubkey}, room=room_id, include_self=False)

            if room_id.startswith("direct-") and len(room["pubkeys"]) == 1:
                other_pubkey = None
                for candidate in set(active_sockets.values()):
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
        try:
            pubkey = session.get("logged_in_pubkey")
            if not pubkey:
                return

            room_id = (data or {}).get("room_id")
            if not room_id:
                return

            room = call_rooms.get(room_id)
            if not room:
                return

            if pubkey in room["pubkeys"]:
                room["pubkeys"].remove(pubkey)

            flask_leave_room(room_id)
            logger.info(f"User {truncate_key(pubkey)} left room {room_id}")
            emit("rtc:peer_left", {"room_id": room_id, "pubkey": pubkey}, room=room_id, include_self=False)

            if not room["pubkeys"]:
                room["created_at"] = time.time()
                cleanup_old_rooms()
        except Exception as e:
            logger.error(f"Error in rtc_leave_room: {e}", exc_info=True)

    @socketio.on("rtc:signal")
    def rtc_signal(data):
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

            room = call_rooms.get(room_id)
            if not room or pubkey not in room["pubkeys"]:
                emit("rtc:error", {"error": "Not in this room"})
                return

            if target_pubkey not in room["pubkeys"]:
                emit("rtc:error", {"error": "Target not in this room"})
                return

            outbound = {"room_id": room_id, "from": pubkey, "type": signal_type, "payload": payload}
            for sid in sids_for_pubkey(target_pubkey):
                emit("rtc:signal", outbound, room=sid)
        except Exception as e:
            logger.error(f"Error in rtc_signal: {e}", exc_info=True)
            emit("rtc:error", {"error": "Signaling failed"})

    @socketio.on("rtc:invite")
    def rtc_invite(data):
        to_pubkey = data.get("to")
        room_id = data.get("room_id")
        from_pubkey = session.get("logged_in_pubkey")
        if not to_pubkey or not room_id or not from_pubkey:
            return
        for sid in sids_for_pubkey(to_pubkey):
            emit("rtc:invite", {"room_id": room_id, "from": from_pubkey, "from_name": from_pubkey[-8:]}, room=sid)

    @socketio.on("message")
    def handle_message(msg_text):
        try:
            broadcast_chat_message(msg_text)
        except Exception as e:
            logger.error(f"Error handling message: {e}", exc_info=True)

    @socketio.on("chat:send")
    def handle_chat_send(data):
        try:
            if isinstance(data, dict):
                text = (data.get("text") or "").strip()
            else:
                text = str(data or "").strip()

            if not text:
                return
            broadcast_chat_message(text)
        except Exception as e:
            logger.error(f"Error handling chat:send: {e}", exc_info=True)

    @socketio.on("connect")
    def on_connect(auth=None):
        pubkey = session.get("logged_in_pubkey", "")
        level = session.get("access_level")
        if not pubkey:
            return False
        role = classify_presence(pubkey, level)

        active_sockets[request.sid] = pubkey
        online_users.add(pubkey)
        online_meta[pubkey] = role

        label = None
        try:
            if session.get("login_method") == "pin_guest":
                label = session.get("guest_label")
        except Exception:
            label = None
        try:
            online_user_meta[pubkey] = {"role": role, "label": label}
        except Exception:
            pass

        emit("user:joined", {"pubkey": pubkey, "role": role, "label": label}, broadcast=True)
        broadcast_online_list()

    @socketio.on("disconnect")
    def on_disconnect(*args, **kwargs):
        sid = request.sid
        pubkey = active_sockets.pop(sid, None)
        if not pubkey:
            return

        if pubkey not in active_sockets.values():
            online_users.discard(pubkey)
            online_meta.pop(pubkey, None)
            emit("user:left", {"pubkey": pubkey}, broadcast=True)
            broadcast_online_list()
