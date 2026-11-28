(() => {
  "use strict";

  let invitation = location.pathname === "/invite" ? location.hash.slice(1) : "";
  if (location.hash) history.replaceState(null, "", location.pathname);

  let csrf;
  let signedIn = false;
  let view = {};
  let call;
  let generation = 0;
  let signing = false;
  let acquiring = false;
  let locked = false;
  let inviteRefused = false;
  let notice = "";
  const $ = id => document.getElementById(id);
  const live = new Set(["AUTHORIZED", "CONNECTING", "CONNECTED"]);

  class Denied extends Error {}

  async function rpc(path, data) {
    const request = {cache: "no-store", credentials: "same-origin", redirect: "error"};
    if (data !== undefined) Object.assign(request, {
      method: "POST",
      headers: {"Content-Type": "application/json", "X-IAC-CSRF": csrf},
      body: JSON.stringify(data),
      signal: AbortSignal.timeout(8000),
    });
    const response = await fetch("/iac/" + path, request);
    if (!response.ok) throw new Denied();
    return response.json();
  }

  function render() {
    const state = view.state;
    $("login").hidden = signedIn || inviteRefused;
    $("issue").hidden = !signedIn || inviteRefused || (state !== "IDLE" && (
      !view.host || !["ENDED", "DECLINED", "CANCELLED", "EXPIRED", "FAILED"].includes(state)
    ));
    $("claim").hidden = !signedIn || state !== "READY_TO_CLAIM";
    $("logout").hidden = !signedIn;
    $("invite-link").hidden = state !== "ISSUED" || !$("link").value;
    if (state !== "ISSUED") $("link").value = "";
    $("consent").hidden = state !== "PENDING_CONSENT";
    $("comparison").textContent = state === "PENDING_CONSENT" ? view.comparison : "";
    $("accept").textContent = view.host ? "Code matches — confirm" : "Accept";
    $("accept").disabled = Boolean(view.approved);
    $("cancel").hidden = !["ISSUED", "PENDING_CONSENT"].includes(state);
    $("media").hidden = !live.has(state);
    $("audio").hidden = $("video").hidden = Boolean(call);
    $("audio").disabled = $("video").disabled = acquiring;
    $("mute").hidden = !call?.media.getAudioTracks().length;
    $("camera").hidden = !call?.media.getVideoTracks().length;
    $("status").textContent = notice || ({
      IDLE: "Create a one-time invite.",
      READY_TO_CLAIM: "Claim the one-time invitation.",
      ISSUED: "Waiting for the recipient.",
      PENDING_CONSENT: view.approved ? "Waiting for the other person." : "Both people must confirm.",
      AUTHORIZED: "Both accepted. Choose whether to enable your microphone and camera.",
      CONNECTING: "Connecting through the relay.",
      CONNECTED: "Checking the selected relay path.",
      DECLINED: "Invitation declined.",
      CANCELLED: "Invitation cancelled.",
      ENDED: "Call ended.",
      EXPIRED: "Invitation expired.",
      FAILED: "Call unavailable. Start with a new invitation.",
    })[state] || "Sign in with a dedicated synthetic test signer.";
  }

  function stopMedia() {
    const prior = call;
    call = undefined;
    if (prior) {
      prior.media.getTracks().forEach(track => track.stop());
      prior.pc.close();
    }
    $("local").srcObject = null;
    $("remote").srcObject = null;
    $("mute").textContent = "Mute microphone";
    $("camera").textContent = "Turn camera off";
  }

  async function failCall(message) {
    const room = view.room;
    stopMedia();
    notice = message;
    view = {state: "FAILED"};
    render();
    if (room) {
      try { await rpc("call/hangup", {room, failed: true}); } catch { /* the grant may already have ended */ }
    }
  }

  async function start() {
    const result = await rpc("bootstrap");
    signedIn = result.authenticated;
    csrf = result.csrf;
    if (invitation) {
      let token = invitation;
      invitation = "";
      if (signedIn) {
        inviteRefused = true;
        notice = "Log out and reopen the invitation to use a fresh identity.";
      } else {
        try { await rpc("invite/prepare", {token}); }
        catch {
          inviteRefused = true;
          notice = "Invitation unavailable.";
        }
        token = "";
      }
    }
    if (signedIn) {
      view = await rpc("attempt/status", {});
      if (live.has(view.state) && view.negotiating) {
        await failCall("This call cannot be recovered after reload. Start with a new invitation.");
      }
      schedule();
    }
    render();
  }

  async function login() {
    if (signing || signedIn || inviteRefused) return;
    signing = true;
    $("login").disabled = true;
    try {
      const signer = window.nostr;
      if (!signer) {
        notice = "An external NIP-07 test signer is required for this preview.";
        return;
      }
      const pubkey = await signer.getPublicKey();
      const issued = await rpc("auth/challenge", {pubkey});
      if (issued.url !== location.origin + "/iac/auth/verify" ||
          !/^HODLXXI:IAC:LOGIN:V0:[0-9a-f]{64}$/.test(issued.challenge)) throw new Denied();
      const tags = [["u", issued.url], ["challenge", issued.challenge]];
      const unsigned = {pubkey, created_at: issued.created_at, kind: 22242, tags, content: ""};
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(
        JSON.stringify([0, pubkey, unsigned.created_at, 22242, tags, ""])
      ));
      const id = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
      const proof = await signer.signEvent(unsigned);
      if (proof?.id !== id || proof.pubkey !== pubkey || proof.created_at !== issued.created_at ||
          proof.kind !== 22242 || proof.content !== "" || JSON.stringify(proof.tags) !== JSON.stringify(tags) ||
          !/^[0-9a-f]{128}$/.test(proof.sig)) throw new Denied();
      const result = await rpc("auth/verify", {event: {
        id, pubkey, created_at: issued.created_at, kind: 22242, tags, content: "", sig: proof.sig,
      }});
      signedIn = result.authenticated;
      csrf = result.csrf;
      notice = "";
      view = await rpc("attempt/status", {});
      schedule();
    } catch {
      notice = "Unable to verify the test signer.";
    } finally {
      signing = false;
      $("login").disabled = false;
      render();
    }
  }

  function messageId() {
    return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
      .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  }

  function peerConfig(relay) {
    if (!relay || relay.urls.length !== 1 ||
        !/^turn:127(?:\.[0-9]{1,3}){3}:[0-9]+\?transport=udp$/.test(relay.urls[0])) throw new Denied();
    return {
      iceTransportPolicy: "relay",
      iceServers: [{urls: relay.urls, username: relay.username, credential: relay.credential}],
    };
  }

  async function send(connection, kind, payload) {
    const request = {room: connection.room, message: messageId(), kind, payload};
    try { await rpc("call/signal/send", request); }
    catch (error) {
      if (error instanceof Denied || call !== connection) throw error;
      await rpc("call/signal/send", request);
    }
  }

  async function sendDescription(connection, kind) {
    const pc = connection.pc;
    const description = kind === "offer" ? await pc.createOffer() : await pc.createAnswer();
    await pc.setLocalDescription(description);
    await send(connection, kind, {sdp: description.sdp});
    connection.localSent = true;
    for (const candidate of connection.earlyLocal.splice(0)) queueCandidate(connection, candidate);
  }

  function queueCandidate(connection, candidate) {
    if (connection.pending >= 32) {
      void failCall("Local signaling limit reached. Start with a new invitation.");
      return;
    }
    connection.pending++;
    connection.outbound = connection.outbound.then(async () => {
      if (call === connection) await send(connection, "ice", candidate);
    }).catch(() => {
      if (call === connection) void failCall("Unable to send relay signaling.");
    }).finally(() => { connection.pending--; });
  }

  async function startMedia(video) {
    if (call || acquiring || !live.has(view.state)) return;
    acquiring = true;
    render();
    const room = view.room;
    let media;
    try {
      const relay = await rpc("call/turn", {room});
      const config = peerConfig(relay);
      try { media = await navigator.mediaDevices.getUserMedia({audio: true, video}); }
      catch (error) {
        if (!video) throw error;
        media = await navigator.mediaDevices.getUserMedia({audio: true, video: false});
        notice = "Camera unavailable. Continuing with audio.";
      }
      if (!media.getAudioTracks().length || view.room !== room) throw new Denied();
      const pc = new RTCPeerConnection(config);
      const connection = {
        pc, media, room, ack: 0, localSent: false, earlyLocal: [], earlyRemote: [],
        pending: 0, outbound: Promise.resolve(), connected: false, expires: relay.expires_at, disconnectedAt: null,
      };
      call = connection;
      $("local").srcObject = media;
      media.getTracks().forEach(track => pc.addTrack(track, media));
      pc.ontrack = event => {
        if (call === connection) $("remote").srcObject = event.streams[0] || new MediaStream([event.track]);
      };
      pc.onicecandidate = event => {
        if (call !== connection || !event.candidate || event.candidate.type !== "relay") return;
        const candidate = {
          candidate: event.candidate.candidate.replace(/ raddr \S+ rport \d+/g, ""),
          sdpMid: event.candidate.sdpMid,
          sdpMLineIndex: event.candidate.sdpMLineIndex,
        };
        if (connection.localSent) queueCandidate(connection, candidate);
        else if (connection.earlyLocal.length < 32) connection.earlyLocal.push(candidate);
        else void failCall("Local relay candidate limit reached.");
      };
      await rpc("call/status", {room, phase: "ready"});
    } catch (error) {
      media?.getTracks().forEach(track => track.stop());
      if (call) await failCall("Unable to start audio or relay signaling.");
      else notice = error instanceof Denied ? "The authorized relay is unavailable." : "Microphone access is required to start audio.";
    } finally {
      acquiring = false;
      render();
    }
  }

  async function receive(connection, message) {
    const {pc} = connection;
    if (message.kind === "ice") {
      if (pc.remoteDescription) await pc.addIceCandidate(message.payload);
      else if (connection.earlyRemote.length < 128) connection.earlyRemote.push(message.payload);
      else throw new Denied();
    } else {
      await pc.setRemoteDescription({type: message.kind, sdp: message.payload.sdp});
      for (const candidate of connection.earlyRemote.splice(0)) await pc.addIceCandidate(candidate);
      if (message.kind === "offer") await sendDescription(connection, "answer");
    }
    connection.ack = message.seq;
  }

  async function checkRelay(connection) {
    const report = await connection.pc.getStats();
    const transport = [...report.values()].find(item => item.type === "transport" && item.selectedCandidatePairId);
    if (!transport) return false;
    const pair = report.get(transport.selectedCandidatePairId);
    if (!pair) return false;
    if (report.get(pair.localCandidateId)?.candidateType !== "relay" ||
        report.get(pair.remoteCandidateId)?.candidateType !== "relay") throw new Denied();
    return true;
  }

  async function tick() {
    view = await rpc("attempt/status", {});
    if (!live.has(view.state)) {
      if (call) {
        stopMedia();
        notice = "";
      }
      render();
      return;
    }
    const status = await rpc("call/status", {room: view.room, phase: "heartbeat"});
    const connection = call;
    if (connection) {
      if (view.host && status.ready && !connection.localSent) await sendDescription(connection, "offer");
      const batch = await rpc("call/signal/poll", {room: view.room, ack: connection.ack});
      for (const message of batch.messages) {
        if (message.seq !== connection.ack + 1) throw new Denied();
        await receive(connection, message);
      }
      if (Date.now() / 1000 >= connection.expires) {
        const relay = await rpc("call/turn", {room: view.room});
        connection.pc.setConfiguration(peerConfig(relay));
        connection.expires = relay.expires_at;
      }
      const rtc = connection.pc.connectionState;
      if (rtc === "failed") throw new Denied();
      if (rtc === "disconnected") {
        connection.disconnectedAt ??= performance.now();
        if (performance.now() - connection.disconnectedAt >= 60000) throw new Denied();
      } else connection.disconnectedAt = null;
      if (rtc === "connected" && await checkRelay(connection) && !connection.connected) {
        await rpc("call/status", {room: view.room, phase: "connected"});
        connection.connected = true;
        notice = "Media connected through the relay.";
      }
    }
    render();
  }

  function schedule() {
    const mine = ++generation;
    let lastSuccess = performance.now();
    const loop = async () => {
      if (!signedIn || generation !== mine) return;
      if (!locked) {
        locked = true;
        try {
          await tick();
          lastSuccess = performance.now();
        } catch (error) {
          if (call && (error instanceof Denied || performance.now() - lastSuccess >= 60000)) {
            await failCall("The relay or signaling grant ended. Start with a new invitation.");
          }
        } finally { locked = false; }
      }
      if (signedIn && generation === mine) setTimeout(loop, 1400);
    };
    setTimeout(loop, 1400);
  }

  function action(fn) {
    return async () => {
      if (locked) return;
      locked = true;
      notice = "";
      try { await fn(); }
      catch { notice = "This action is unavailable."; }
      finally { locked = false; render(); }
    };
  }

  document.addEventListener("DOMContentLoaded", () => {
    $("login").onclick = login;
    $("issue").onclick = action(async () => {
      const result = await rpc("invite/issue", {});
      view = {state: "ISSUED"};
      $("link").value = result.link;
    });
    $("copy").onclick = action(async () => { await navigator.clipboard.writeText($("link").value); });
    $("claim").onclick = action(async () => { view = await rpc("invite/claim", {}); });
    $("accept").onclick = action(async () => {
      view = await rpc("attempt/consent", {attempt: view.attempt, accept: true});
    });
    $("decline").onclick = action(async () => {
      view = await rpc("attempt/consent", {attempt: view.attempt, accept: false});
    });
    $("cancel").onclick = action(async () => {
      view = await rpc("attempt/cancel", {attempt: view.attempt ?? null});
    });
    $("audio").onclick = () => { void startMedia(false); };
    $("video").onclick = () => { void startMedia(true); };
    $("hangup").onclick = action(async () => {
      const room = view.room;
      stopMedia();
      view = await rpc("call/hangup", {room, failed: false});
    });
    $("logout").onclick = action(async () => {
      stopMedia();
      await rpc("auth/logout", {});
      signedIn = false;
      view = {};
      csrf = undefined;
      generation++;
      await start();
    });
    $("mute").onclick = () => {
      const track = call?.media.getAudioTracks()[0];
      if (track) track.enabled = !track.enabled;
      $("mute").textContent = track?.enabled ? "Mute microphone" : "Unmute microphone";
    };
    $("camera").onclick = () => {
      const track = call?.media.getVideoTracks()[0];
      if (track) track.enabled = !track.enabled;
      $("camera").textContent = track?.enabled ? "Turn camera off" : "Turn camera on";
    };
    addEventListener("pagehide", stopMedia);
    start().catch(() => { notice = "Preview unavailable."; render(); });
  }, {once: true});
})();
