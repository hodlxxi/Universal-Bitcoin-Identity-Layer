import time


def register_socket_handlers(socketio):
    from flask import request, session
    from flask_socketio import emit

    from app import app as app_module

    def sids_for_pubkey(pk: str):
        """Get all socket IDs for a given pubkey"""
        return [sid for sid, who in app_module.ACTIVE_SOCKETS.items() if who == pk]

    @socketio.on("rtc:offer")
    def rtc_offer(data):
        """data = {to: , from: , offer: {...}}"""
        try:
            target = (data or {}).get("to")
            if not target:
                app_module.logger.warning("RTC offer received without target")
                return
            for sid in sids_for_pubkey(target):
                socketio.emit("rtc:offer", data, to=sid)
        except Exception as e:
            app_module.logger.error(f"Error in rtc_offer: {e}", exc_info=True)

    @socketio.on("rtc:answer")
    def rtc_answer(data):
        """data = {to: , from: , answer: {...}}"""
        try:
            target = (data or {}).get("to")
            if not target:
                app_module.logger.warning("RTC answer received without target")
                return
            for sid in sids_for_pubkey(target):
                socketio.emit("rtc:answer", data, to=sid)
        except Exception as e:
            app_module.logger.error(f"Error in rtc_answer: {e}", exc_info=True)

    @socketio.on("rtc:ice")
    def rtc_ice(data):
        """data = {to: , from: , candidate: {...}}"""
        try:
            target = (data or {}).get("to")
            if not target:
                app_module.logger.warning("RTC ICE candidate received without target")
                return
            for sid in sids_for_pubkey(target):
                socketio.emit("rtc:ice", data, to=sid)
        except Exception as e:
            app_module.logger.error(f"Error in rtc_ice: {e}", exc_info=True)

    @socketio.on("rtc:hangup")
    def rtc_hangup(data):
        """data = {to: , from: }"""
        try:
            target = (data or {}).get("to")
            if not target:
                app_module.logger.warning("RTC hangup received without target")
                return
            for sid in sids_for_pubkey(target):
                socketio.emit("rtc:hangup", data, to=sid)
        except Exception as e:
            app_module.logger.error(f"Error in rtc_hangup: {e}", exc_info=True)

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

            if room_id not in app_module.CALL_ROOMS:
                app_module.CALL_ROOMS[room_id] = {"pubkeys": set(), "created_at": time.time()}

            room = app_module.CALL_ROOMS[room_id]

            if len(room["pubkeys"]) >= app_module.MAX_ROOM_SIZE and pubkey not in room["pubkeys"]:
                emit("rtc:error", {"error": "Room is full (max 4 participants)"})
                app_module.logger.warning(f"Room {room_id} is full, rejected {pubkey[:8]}")
                return

            room["pubkeys"].add(pubkey)
            flask_join_room(room_id)

            current_peers = [p for p in room["pubkeys"] if p != pubkey]

            app_module.logger.info(
                f"User {app_module.truncate_key(pubkey)} joined room {room_id}. " f"Participants: {len(room['pubkeys'])}"
            )

            emit(
                "rtc:room_peers",
                {"room_id": room_id, "peers": current_peers},
                room=request.sid,
            )

            emit(
                "rtc:peer_joined",
                {"room_id": room_id, "pubkey": pubkey},
                room=room_id,
                include_self=False,
            )

            if room_id.startswith("direct-") and len(room["pubkeys"]) == 1:
                other_pubkey = None
                for candidate in set(app_module.ACTIVE_SOCKETS.values()):
                    if candidate != pubkey and candidate in room_id:
                        other_pubkey = candidate
                        break

                if other_pubkey:
                    app_module.logger.info(f"Auto-inviting {app_module.truncate_key(other_pubkey)} to join {room_id}")
                    payload = {"room_id": room_id, "from": pubkey}
                    for sid in sids_for_pubkey(other_pubkey):
                        emit("rtc:call_invite", payload, room=sid)

        except Exception as e:
            app_module.logger.error(f"Error in rtc_join_room: {e}", exc_info=True)
            emit("rtc:error", {"error": "Failed to join room"})

    @socketio.on("rtc:leave_room")
    def rtc_leave_room(data):
        """Leave a call room. data = {"room_id": str}"""
        from flask_socketio import emit, leave_room as flask_leave_room

        try:
            pubkey = session.get("logged_in_pubkey")
            if not pubkey:
                return

            room_id = (data or {}).get("room_id")
            if not room_id:
                return

            room = app_module.CALL_ROOMS.get(room_id)
            if not room:
                return

            if pubkey in room["pubkeys"]:
                room["pubkeys"].remove(pubkey)

            flask_leave_room(room_id)
            app_module.logger.info(f"User {app_module.truncate_key(pubkey)} left room {room_id}")

            emit(
                "rtc:peer_left",
                {"room_id": room_id, "pubkey": pubkey},
                room=room_id,
                include_self=False,
            )

            if not room["pubkeys"]:
                room["created_at"] = time.time()
                app_module.cleanup_old_rooms()

        except Exception as e:
            app_module.logger.error(f"Error in rtc_leave_room: {e}", exc_info=True)

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

            room = app_module.CALL_ROOMS.get(room_id)
            if not room or pubkey not in room["pubkeys"]:
                emit("rtc:error", {"error": "Not in this room"})
                return

            if target_pubkey not in room["pubkeys"]:
                emit("rtc:error", {"error": "Target not in this room"})
                return

            outbound = {
                "room_id": room_id,
                "from": pubkey,
                "type": signal_type,
                "payload": payload,
            }

            for sid in sids_for_pubkey(target_pubkey):
                emit("rtc:signal", outbound, room=sid)

        except Exception as e:
            app_module.logger.error(f"Error in rtc_signal: {e}", exc_info=True)
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
        for sid in sids_for_pubkey(to_pubkey):
            emit("rtc:invite", {"room_id": room_id, "from": from_pubkey, "from_name": from_pubkey[-8:]}, room=sid)

    def _broadcast_chat_message(text: str):
        """Shared logic to append to history and broadcast to all clients."""
        pk = session.get("logged_in_pubkey")
        if not pk:
            app_module.logger.warning("Message received from unauthenticated user")
            return

        m = {"pubkey": pk, "text": str(text), "ts": time.time()}
        app_module.CHAT_HISTORY.append(m)
        app_module.purge_old_messages()

        socketio.emit("message", m)
        socketio.emit("chat:message", m)

    @socketio.on("message")
    def handle_message(msg_text):
        """Legacy handler for default Socket.IO 'message' event."""
        try:
            _broadcast_chat_message(msg_text)
        except Exception as e:
            app_module.logger.error(f"Error handling message: {e}", exc_info=True)

    @socketio.on("chat:send")
    def handle_chat_send(data):
        """
        New handler for our front-end.

        Client sends: socket.emit('chat:send', { text: 'hello' })
        """
        try:
            if isinstance(data, dict):
                text = (data.get("text") or "").strip()
            else:
                text = str(data or "").strip()

            if not text:
                return

            _broadcast_chat_message(text)
        except Exception as e:
            app_module.logger.error(f"Error handling chat:send: {e}", exc_info=True)

    @socketio.on("connect")
    def on_connect(auth=None):
        pubkey = session.get("logged_in_pubkey", "")
        level = session.get("access_level")
        if not pubkey:
            return False
        role = app_module.classify_presence(pubkey, level)

        app_module.ACTIVE_SOCKETS[request.sid] = pubkey
        app_module.ONLINE_USERS.add(pubkey)
        app_module.ONLINE_META[pubkey] = role

        label = None
        try:
            if session.get("login_method") == "pin_guest":
                label = session.get("guest_label")
        except Exception:
            label = None
        try:
            app_module.ONLINE_USER_META[pubkey] = {"role": role, "label": label}
        except Exception:
            pass
        emit("user:joined", {"pubkey": pubkey, "role": role, "label": label}, broadcast=True)
        online_list = [{"pubkey": pk, "role": app_module.ONLINE_META.get(pk, "limited")} for pk in app_module.ONLINE_USERS]
        try:
            for it in online_list:
                if isinstance(it, dict) and "pubkey" in it and "label" not in it:
                    meta = app_module.ONLINE_USER_META.get(it["pubkey"], {})
                    it["label"] = meta.get("label")
        except Exception:
            pass
        emit("online:list", online_list, broadcast=True)

    @socketio.on("disconnect")
    def on_disconnect(*args, **kwargs):
        sid = request.sid
        pubkey = app_module.ACTIVE_SOCKETS.pop(sid, None)
        if not pubkey:
            return

        if pubkey not in app_module.ACTIVE_SOCKETS.values():
            app_module.ONLINE_USERS.discard(pubkey)
            app_module.ONLINE_META.pop(pubkey, None)

            emit("user:left", {"pubkey": pubkey}, broadcast=True)

            online_list = [{"pubkey": pk, "role": app_module.ONLINE_META.get(pk, "limited")} for pk in app_module.ONLINE_USERS]
            try:
                for it in online_list:
                    if isinstance(it, dict) and "pubkey" in it and "label" not in it:
                        meta = app_module.ONLINE_USER_META.get(it["pubkey"], {})
                        it["label"] = meta.get("label")
            except Exception:
                pass
            emit("online:list", online_list, broadcast=True)
