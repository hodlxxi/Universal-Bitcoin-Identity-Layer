// TORF — Between Algorithm and Silence (terminal film / stage script)
// Drop-in replacement for your current script.js
// Requires existing HTML elements: #terminal, #cursor, #overlay
// Assumes CSS has .white for spoken/spotlight lines (as in your current build).

const terminal = document.getElementById("terminal");
const cursor = document.getElementById("cursor");
const overlay = document.getElementById("overlay");

window.addEventListener("error", (e) => {
  try { terminal.innerHTML += `\n\n[error] ${e?.message || "Unknown error"}\n`; } catch (_) {}
});
window.addEventListener("unhandledrejection", (e) => {
  try {
    const msg = (e?.reason && (e.reason.message || String(e.reason))) || "Unhandled rejection";
    terminal.innerHTML += `\n\n[rejection] ${msg}\n`;
  } catch (_) {}
});

// --- DEBUG: print runtime errors into the terminal ---
window.addEventListener("error", (e) => {
  try {
    const msg = e?.message || "Unknown error";
    terminal.innerHTML += `\n\n[error] ${msg}\n`;
  } catch (_) {}
});

window.addEventListener("unhandledrejection", (e) => {
  try {
    const msg = (e?.reason && (e.reason.message || String(e.reason))) || "Unhandled rejection";
    terminal.innerHTML += `\n\n[rejection] ${msg}\n`;
  } catch (_) {}
});
// ---------- GLOBAL TIMING CONTROL ----------
/**
 * Pick a vibe:
 * - 180–240 seconds: festival teaser cut
 * - 360–600 seconds: full read (recommended)
 */
const TARGET_SECONDS = 920; // ~7 min full read

// Rough estimate of uncompressed runtime (seconds). Adjust if you want tighter matching.
const ORIGINAL_SECONDS_ESTIMATE = 1200;

// Global compression factor: higher = faster
const SPEED_FACTOR = ORIGINAL_SECONDS_ESTIMATE / TARGET_SECONDS;

// "Art pauses" that should remain meaningful even when compressed (REAL milliseconds).
const ART = {
  cursorOnlyMs: 4200,      // the "Space" scene (cursor only)
  longSilenceMs: 9000,     // the "Silence" scene
  breathMs: 2200,          // short breath pause
  roomScanMs: 2600,        // room-description beat
};

// Base typing speeds (will be compressed by SPEED_FACTOR)
const TIMING = {
  regularCharMs: 50,
  slowCharMs: 92,
  fastCharMs: 28,
  lineBreakPauseMs: 200,
};

// ---------- RENDER ----------
let displayBuffer = "";

// In your HTML, the real scroller is <main id="screen">
const screen = document.getElementById("screen");

function render() {
  terminal.innerHTML = displayBuffer;

  // Keep the live cursor centered (best behavior on iOS Safari)
  try {
    cursor.scrollIntoView({ block: "center", inline: "nearest" });
  } catch (e) {
    // Fallback: manual scroll
    const scroller = screen || terminal.parentElement || terminal;
    const y = cursor.offsetTop - Math.floor(scroller.clientHeight * 0.45);
    scroller.scrollTop = Math.max(0, y);
  }
}

function appendRaw(text) {
  displayBuffer += text;
  render();
}

function appendLineBreak(count = 1) {
  appendRaw("\n".repeat(count));
}
// ---------- SCALED WAIT HELPERS ----------
const waitScaled = (ms) => new Promise((r) => setTimeout(r, ms / SPEED_FACTOR));
const waitExact = (ms) => new Promise((r) => setTimeout(r, ms)); // for ART pauses

// ---------- AUDIO ----------
let audioCtx;
let masterGain;
let humGain;
let humOsc;
let humSub;

function setupAudio() {
  audioCtx = new (window.AudioContext || window.webkitAudioContext)();

  masterGain = audioCtx.createGain();
  masterGain.gain.value = 0.12;
  masterGain.connect(audioCtx.destination);

  humOsc = audioCtx.createOscillator();
  humSub = audioCtx.createOscillator();
  humGain = audioCtx.createGain();
  humGain.gain.value = 0;

  humOsc.type = "sine";
  humOsc.frequency.value = 49;

  humSub.type = "triangle";
  humSub.frequency.value = 24.5;

  humOsc.connect(humGain);
  humSub.connect(humGain);
  humGain.connect(masterGain);

  humOsc.start();
  humSub.start();

  // gentle fade-in
  humGain.gain.setTargetAtTime(0.35, audioCtx.currentTime, 1.6);
}

function stopHumForSilence() {
  if (!audioCtx || !humGain) return;
  humGain.gain.setTargetAtTime(0.0001, audioCtx.currentTime, 0.25);
}

function restoreHumAfterSilence() {
  if (!audioCtx || !humGain) return;
  humGain.gain.setTargetAtTime(0.22, audioCtx.currentTime, 1.2);
}

function keyClick() {
  if (!audioCtx || audioCtx.state !== "running") return;

  const now = audioCtx.currentTime;
  const osc = audioCtx.createOscillator();
  const gain = audioCtx.createGain();

  osc.type = "square";
  osc.frequency.value = 760 + Math.random() * 240;

  gain.gain.setValueAtTime(0.0001, now);
  gain.gain.linearRampToValueAtTime(0.09, now + 0.002);
  gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.075);

  osc.connect(gain);
  gain.connect(masterGain);

  osc.start(now);
  osc.stop(now + 0.05);
}

// ---------- TYPING ----------
async function typeLine(line, opts = {}) {
  const {
    charMs = TIMING.regularCharMs,
    isWhite = false,
    trailingBreaks = 1,
    skipAudio = false,
  } = opts;

  appendRaw(isWhite ? '<span class="white">' : "<span>");

  for (const ch of line) {
    appendRaw(ch);
    if (!skipAudio && ch.trim()) keyClick();

    // Scale typing delay by SPEED_FACTOR, keep jitter
    const base = charMs + Math.random() * (charMs * 0.28);
    const scaled = base / SPEED_FACTOR;
    await new Promise((r) => setTimeout(r, scaled));
  }

  appendRaw("</span>");
  appendLineBreak(trailingBreaks);

  const lb = TIMING.lineBreakPauseMs / SPEED_FACTOR;
  await new Promise((r) => setTimeout(r, lb));
}

async function typeBlock(lines, opts = {}) {
  for (const l of lines) {
    await typeLine(l, opts);
  }
}

async function beat(ms = 1200) {
  await waitScaled(ms);
}

async function breath() {
  await waitExact(ART.breathMs);
}

// ---------- STYLE HELPERS ----------
async function sceneHeader(title) {
  appendLineBreak();
  await typeLine(`=== ${title} ===`, { charMs: TIMING.fastCharMs, isWhite: true });
  await beat(800);
}

async function stageDir(text) {
  await typeLine(`[stage] ${text}`, { charMs: 60, isWhite: true, skipAudio: true });
}

async function voice(name, text, speed = TIMING.slowCharMs) {
  await typeLine(`${name}: ${text}`, { charMs: speed, isWhite: true });
}

async function sys(text, speed = TIMING.regularCharMs) {
  await typeLine(text, { charMs: speed });
}

// ---------- TORF TIMELINE ----------

async function sectionBootAndRoom() {
  await sceneHeader("TORF / boot");
  await sys("$ booting_future...", TIMING.fastCharMs);
  await sys("$ loading_models...", TIMING.fastCharMs);
  await sys("$ mapping_human_behavior...", TIMING.fastCharMs);
  await beat(2200);

  await sceneHeader("ROOM");
  await stageDir("a dark room. walls are screens. green digits fall like rain.");
  await stageDir("a desk at center. a terminal. a single lamp. a low server hum.");
  await stageDir("the cursor blinks. the room watches back.");
  await waitExact(ART.roomScanMs);
}

async function sectionAlgorithmAtmosphere() {
  await sceneHeader("ALGORITHM");
  await sys("prediction_accuracy: 94.2%", 48);
  await sys("recommended_action: ACCEPT", 48);
  await sys("friction_removed: TRUE", 48);
  await sys("latency_to_choice: 12ms", 48);
  await beat(1800);

  await sys("choose:", 52);
  await sys("[A] accept", 52);
  await sys("[E] edit", 52);
  await beat(1700);
}

async function sectionHumanEnters() {
  await sceneHeader("HUMAN");
  await stageDir("a person sits. not a hero. not a symbol. just tired presence.");
  await stageDir("a phone in the pocket. deadlines in the bones. a life in tabs.");
  await breath();

  await sys("$ life --mode=survival", 54);
  await sys("efficiency: increased", 54);
  await sys("uncertainty: minimized", 54);
  await sys("risk: reduced", 54);
  await beat(2200);

  await voice("HUMAN", "tomorrow is a deadline.", 86);
  await voice("HUMAN", "this helps. so i press accept.", 86);
  await beat(1600);
}

async function sectionZarathustra() {
  await sceneHeader("ZARATHUSTRA");
  await stageDir("a heat without flame. a will without body.");
  await breath();

  await voice("ZARATHUSTRA", "you avoided falling.", 86);
  await voice("ZARATHUSTRA", "but avoidance is not ascent.", 86);
  await beat(1400);

  await voice("ZARATHUSTRA", "a life without error", 86);
  await voice("ZARATHUSTRA", "is a life without edge.", 86);
  await beat(1600);

  await voice("ZARATHUSTRA", "comfort is a quiet erosion.", 86);
  await voice("ZARATHUSTRA", "it does not break you.", 86);
  await voice("ZARATHUSTRA", "it smooths you.", 86);
  await beat(2000);

  await voice("ZARATHUSTRA", "tell me —", 86);
  await voice("ZARATHUSTRA", "when the algorithm decides before you feel,", 86);
  await voice("ZARATHUSTRA", "who is ascending?", 86);
  await beat(2200);

  await sys("recommended_action: ACCEPT", 48);
  await beat(1200);
}
async function sectionSatoshi() {
  await sceneHeader("SATOSHI");
  await stageDir("no face. no stage. only a protocol-like calm.");
  await breath();

  await voice("SATOSHI", "if there is no exit,", 86);
  await voice("SATOSHI", "it is not freedom.", 86);
  await voice("SATOSHI", "it is infrastructure control.", 86);
  await beat(2200);

  await voice("SATOSHI", "do not ask if a system is kind.", 86);
  await voice("SATOSHI", "ask if you can leave it.", 86);
  await beat(1800);

  await sys("exit_cost: HIGH", 54);
  await sys("exit_path: THEORETICAL", 54);
  await beat(1200);
}

async function sectionSpace() {
  await sceneHeader("SPACE");
  await stageDir("not a character. the gap between impulse and action.");
  await stageDir("the cursor blinks. nothing speaks.");
  appendLineBreak(2);

  // Cursor-only pause
  await waitExact(ART.cursorOnlyMs);

  await voice("SPACE", "i am the second where you can still change.", 92);
  await voice("SPACE", "i shrink when everything becomes instant.", 92);
  await beat(2000);
}

async function sectionTime() {
  await sceneHeader("TIME");
  await stageDir("direction disguised as repetition.");
  await breath();

  await sys("simulating 20 years...", 56);
  await sys("decision_match_rate: 99.1%", 54);
  await sys("manual_override: rare", 54);
  await sys("pause_duration: shrinking", 54);
  await beat(2200);

  await voice("TIME", "one choice is a spark.", 92);
  await voice("TIME", "repetition is architecture.", 92);
  await beat(1600);

  await voice("TIME", "you think you choose daily.", 92);
  await voice("TIME", "but most days you repeat.", 92);
  await beat(1800);

  await voice("TIME", "repetition writes identity.", 92);
  await voice("TIME", "identity becomes trajectory.", 92);
  await beat(2000);

  await voice("TIME", "and trajectory feels like fate.", 92);
  await beat(2400);

  await stageDir("the world does not collapse.");
  await stageDir("it becomes smooth.");
  await stageDir("smooth enough to stop questioning.");
  await beat(2400);
}
async function sectionScaleAndBetweenWorlds() {
  await sceneHeader("BETWEEN");
  await stageDir("a presence both vast and tiny — the interval between atom and electron,");
  await stageDir("and the distance between galaxies — the 'between' itself.");
  await breath();

  await voice("BETWEEN", "i am the distance that makes movement visible.", 92);
  await voice("BETWEEN", "i am the hollow where possibility lives.", 92);
  await beat(2400);

  await voice("BETWEEN", "optimization tries to fill me.", 92);
  await voice("BETWEEN", "but if i vanish, choice becomes decoration.", 92);
  await beat(2600);
}

async function sectionSilence() {
  await sceneHeader("SILENCE");
  await stageDir("older than code. deeper than pause.");
  appendLineBreak(1);

  stopHumForSilence();
  await waitExact(ART.longSilenceMs);

  await voice("SILENCE", "before prediction,", TIMING.slowCharMs);
  await voice("SILENCE", "there was uncertainty.", TIMING.slowCharMs);
  await beat(1600);

  await voice("SILENCE", "before recommendation,", TIMING.slowCharMs);
  await voice("SILENCE", "there was hesitation.", TIMING.slowCharMs);
  await beat(1800);

  await voice("SILENCE", "hesitation is not weakness.", TIMING.slowCharMs);
  await voice("SILENCE", "it is the birthplace of freedom.", TIMING.slowCharMs);
  await beat(2200);

  await voice("SILENCE", "can you remain here,", TIMING.slowCharMs);
  await voice("SILENCE", "without seeking optimization?", TIMING.slowCharMs);
  await beat(2600);

  await voice("SILENCE", "if you cannot sit in me,", TIMING.slowCharMs);
  await voice("SILENCE", "you will always be steered.", TIMING.slowCharMs);
  await beat(2200);

  restoreHumAfterSilence();
}

async function finalPrompt() {
  await sceneHeader("CHOICE");
  await sys("choose:", 60);
  await sys("[A] accept", 56);
  await sys("[E] edit", 56);
  await beat(900);
}

async function endingAccept() {
  appendLineBreak();
  await voice("ALGORITHM", "accepted.", 84);
  await sys("friction_removed: TRUE", 54);
  await sys("pause_duration: shrinking", 54);
  await beat(1400);

  await voice("TIME", "direction locked by repetition.", 92);
  await beat(1400);

  fadeToBlackForever();
}

async function endingEdit() {
  appendLineBreak();
  await voice("HUMAN", "i will edit.", 92);
  await sys("manual_override: engaged", 54);
  await sys("pause_duration: expanding", 54);
  await sys("prediction_confidence: UNKNOWN", 54);
  await beat(1800);

  await voice("SPACE", "welcome back.", 92);
  await beat(1200);

  await voice("SILENCE", "stay.", 92);
  await beat(1200);
}

// ---------- END INPUT ----------
function fadeToBlackForever() {
  overlay.classList.remove("hidden");
  requestAnimationFrame(() => overlay.classList.add("visible"));
  if (cursor) cursor.style.display = "none";
}

// ---------- mobile choice UI (A/E buttons) ----------
let choiceUIEl = null;

function hideChoiceUI() {
  if (choiceUIEl) {
    choiceUIEl.remove();
    choiceUIEl = null;
  }
}

function showChoiceUI() {
  if (choiceUIEl) return;

  choiceUIEl = document.createElement("div");
  choiceUIEl.id = "choiceUI";
  choiceUIEl.style.position = "fixed";
  choiceUIEl.style.left = "0";
  choiceUIEl.style.right = "0";
  choiceUIEl.style.bottom = "0";
  choiceUIEl.style.zIndex = "9999";
  choiceUIEl.style.display = "flex";
  choiceUIEl.style.gap = "10px";
  choiceUIEl.style.justifyContent = "center";
  choiceUIEl.style.alignItems = "center";
  choiceUIEl.style.padding = "12px 12px calc(12px + env(safe-area-inset-bottom)) 12px";
  choiceUIEl.style.background = "rgba(0,0,0,0.92)";
  choiceUIEl.style.borderTop = "1px solid rgba(0,255,136,0.25)";
  choiceUIEl.style.backdropFilter = "blur(6px)";

  choiceUIEl.innerHTML = `
    <button data-choice="a" aria-label="Accept (A)">A — accept</button>
    <button data-choice="e" aria-label="Edit (E)">E — edit</button>
  `;

  const btns = choiceUIEl.querySelectorAll("button");
  btns.forEach((b) => {
    b.style.fontFamily =
      "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace";
    b.style.fontSize = "16px";
    b.style.padding = "10px 14px";
    b.style.borderRadius = "10px";
    b.style.border = "1px solid rgba(0,255,136,0.35)";
    b.style.background = "rgba(0,0,0,0.40)";
    b.style.color = "#00FF88";
    b.style.cursor = "pointer";
    b.style.touchAction = "manipulation";
    b.style.webkitTapHighlightColor = "rgba(0,0,0,0)";
  });

  document.body.appendChild(choiceUIEl);
}

function bindEndingInput() {
  // Show mobile buttons at the end
  showChoiceUI();

  let decided = false;

  const decide = (keyRaw) => {
    if (decided) return;
    const key = (keyRaw || "").toLowerCase();

    if (key !== "a" && key !== "e") return;

    decided = true;
    document.removeEventListener("keydown", onKey);
    hideChoiceUI();

    if (key === "a") {
      fadeToBlackForever();
    } else {
      void endingEdit(); // your edit branch
    }
  };

  const onKey = (event) => decide(event.key);
  document.addEventListener("keydown", onKey);

  // Tap/click buttons (works on iPhone/Android)
  choiceUIEl.addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-choice]");
    if (!btn) return;
    decide(btn.dataset.choice);
  });

  // iOS sometimes prefers pointerdown/touchstart responsiveness
  choiceUIEl.addEventListener(
    "pointerdown",
    (e) => {
      const btn = e.target.closest("button[data-choice]");
      if (!btn) return;
      decide(btn.dataset.choice);
    },
    { passive: true }
  );

  choiceUIEl.addEventListener(
    "touchstart",
    (e) => {
      const btn = e.target.closest("button[data-choice]");
      if (!btn) return;
      decide(btn.dataset.choice);
    },
    { passive: true }
  );
}

// ---------- START OVERLAY (iOS audio unlock) ----------
let started = false;
let startOverlayEl = null;

function showStartOverlay() {
  startOverlayEl = document.createElement("div");
  startOverlayEl.style.position = "fixed";
  startOverlayEl.style.inset = "0";
  startOverlayEl.style.display = "grid";
  startOverlayEl.style.placeItems = "center";
  startOverlayEl.style.background = "rgba(0,0,0,0.90)";
  startOverlayEl.style.color = "#00FF88";
  startOverlayEl.style.fontFamily =
    "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace";
  startOverlayEl.style.fontSize = "18px";
  startOverlayEl.style.letterSpacing = "0.5px";
  startOverlayEl.style.zIndex = "9999";
  startOverlayEl.style.textAlign = "center";
  startOverlayEl.innerHTML = `
    <div>
      <div style="font-size:20px; margin-bottom:10px;">TORF</div>
      <div style="opacity:0.95;">Between Algorithm and Silence</div>
      <div style="opacity:0.85; margin-top:12px;">Press any key / tap to begin</div>
      <div style="opacity:0.55; margin-top:10px; font-size:14px;">(enables audio)</div>
    </div>
  `;
  document.body.appendChild(startOverlayEl);
  // iPhone Safari: bind tap directly to the overlay (must be inside, after creation)
  startOverlayEl.addEventListener("click", startOnce, { once: true });
  startOverlayEl.addEventListener("touchend", startOnce, { once: true });
}


function hideStartOverlay() {
  if (startOverlayEl) startOverlayEl.remove();
  startOverlayEl = null;
}

// ---------- MAIN ----------
async function runTimeline() {
  await sectionBootAndRoom();
  await sectionAlgorithmAtmosphere();
  await sectionHumanEnters();
  await sectionZarathustra();
  await sectionSatoshi();
  await sectionSpace();
  await sectionTime();
  await sectionScaleAndBetweenWorlds();

  await sectionSilence();
  await finalPrompt();

  bindEndingInput(); // waits for A/E
}

function bindEndingInput_desktopOnly() {
  const onKey = (event) => {
    const key = (event.key || "").toLowerCase();

    if (key === "a") {
      document.removeEventListener("keydown", onKey);
      fadeToBlackForever();
      return;
    }

    if (key === "e") {
      document.removeEventListener("keydown", onKey);
      void sectionRebellionEdit(); // run the edit branch
      return;
    }
  };

  document.addEventListener("keydown", onKey);
}

async function sectionRebellionEdit() {
  appendLineBreak(2);

  await typeLine("[EDIT MODE]", {
    isWhite: true,
    charMs: TIMING.slowCharMs,
  });

  await typeLine("friction restored", {
    isWhite: true,
    charMs: TIMING.slowCharMs,
  });

  await typeLine("unpredictability enabled", {
    isWhite: true,
    charMs: TIMING.slowCharMs,
  });

  await typeLine("pause expanding...", {
    isWhite: true,
    charMs: TIMING.slowCharMs,
  });

  appendLineBreak(1);

  await typeLine("manual_override: ACTIVE", {
    charMs: TIMING.regularCharMs,
  });

  await typeLine("recommended_action: NONE", {
    charMs: TIMING.regularCharMs,
  });

  // Hold a moment (make sure waitExact exists; if not, replace with waitScaled)
  if (typeof waitExact === "function") {
    await waitExact(2500);
  } else {
    await waitScaled(2500);
  }

  await typeLine("> (the system does not stop.)", {
    isWhite: true,
    charMs: TIMING.slowCharMs,
    skipAudio: true,
  });

  await typeLine("> (it simply loses certainty.)", {
    isWhite: true,
    charMs: TIMING.slowCharMs,
    skipAudio: true,
  });
}

async function startOnce() {
  if (started) return;
  started = true;

  hideStartOverlay();

  // Create audio only after gesture (iOS/Safari requirement)
  setupAudio();
  if (audioCtx?.state === "suspended") {
    await audioCtx.resume();
  }

  await runTimeline();
}

function bindStartGestures() {
  window.addEventListener("keydown", startOnce, { once: true });
  window.addEventListener("click", startOnce, { once: true });
  window.addEventListener("touchend", startOnce, { once: true });
}
window.addEventListener("load", () => {
  showStartOverlay();
  bindStartGestures();
});
