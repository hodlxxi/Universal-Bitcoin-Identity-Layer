// Between Algorithm and Silence — long monologues terminal-play (English)
// Final choice:
//   A -> fade to black permanently
//   E -> EDIT / REWRITE branch (Ordinary Human + 20 years later)

const terminal = document.getElementById("terminal");
const cursor = document.getElementById("cursor");
const overlay = document.getElementById("overlay");


// TORF_LONG_ERROR_TRAP_V1
function _torfLongLog(msg) {
  try {
    const t = document.getElementById("terminal");
    if (t) t.textContent += "\n[error] " + msg + "\n";
  } catch (_) {}
}

window.addEventListener("error", (e) => {
  const msg = e?.message || (e?.error && (e.error.stack || e.error.message)) || String(e);
  _torfLongLog(msg);
});

window.addEventListener("unhandledrejection", (e) => {
  const r = e?.reason;
  const msg = (r && (r.stack || r.message)) ? (r.stack || r.message) : String(r);
  _torfLongLog(msg);
});
// ---------- SPEED CONTROL ----------
// 1.0 = as written (long, immersive)
// 1.6 / 2.0 = faster
const SPEED_FACTOR = 1.0;

// Per-character typing pace (scaled by SPEED_FACTOR)

// TORF_LONG_TYPING_FEEL_V1
// Makes typing feel human: slower, punctuation pauses, and rate-limited click sounds.
const TYPE_FEEL = {
  punctPauseMs: 140,   // . ! ?
  commaPauseMs: 70,    // , ; :
  minClickIntervalMs: 26, // limit click spam (lower = more clicks)
  clickProbability: 0.92, // 1.0 = every char, 0.8 = more natural
};
let _lastClickAtMs = 0;
const HUM_LEVEL = 0.02; // background hum volume (0.00..0.40)
const TIMING = {
  regularCharMs: 44,
  slowCharMs: 86,
  lineBreakPauseMs: 320,
};

// “Art pauses” (real-time, not heavily scaled)
const ART = {
  spaceCursorOnlyMs: 6000,  // cursor-only space (Space / Between)
  deepSilenceMs: 10500,     // the Silence section pause
};

let displayBuffer = "";

// ---------- helpers ----------
const waitScaled = (ms) => new Promise((r) => setTimeout(r, ms / SPEED_FACTOR));
const waitExact  = (ms) => new Promise((r) => setTimeout(r, ms));

function escapeHtmlChar(ch){
  if (ch === "&") return "&amp;";
  if (ch === "<") return "&lt;";
  if (ch === ">") return "&gt;";
  if (ch === '"') return "&quot;";
  if (ch === "'") return "&#39;";
  return ch;
}

function render() {
  terminal.innerHTML = displayBuffer;
  // keep view pinned to bottom
  const scroller = document.getElementById("screen");
  scroller.scrollTop = scroller.scrollHeight;
}

function appendRaw(html) {
  displayBuffer += html;
  render();
}

function appendLineBreak(count = 1) {
  appendRaw("\n".repeat(count));
}

// ---------- AUDIO ----------
let audioCtx;
let masterGain;
let clickGain;
let humGain;
let humOsc;
let humSub;

function setupAudio() {
  audioCtx = new (window.AudioContext || window.webkitAudioContext)();

  masterGain = audioCtx.createGain();
  masterGain.gain.value = 0.76;
  masterGain.connect(audioCtx.destination);

  // separate gain for typing clicks (does NOT affect hum)
  clickGain = audioCtx.createGain();
  clickGain.gain.value = 0.95; // 0.0..1.0 (lower = quieter typing)
  clickGain.connect(masterGain);


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

  humGain.gain.setTargetAtTime(HUM_LEVEL, audioCtx.currentTime, 1.6);
}

// TORF_LONG_AUDIO_UNLOCK_V1
// iOS Safari often needs an explicit unlock pulse + repeated resume attempts.
function _torfAudioUnlockPulse() {
  try {
    if (!audioCtx) return;
    // Play a 1-sample silent buffer to "poke" the audio graph.
    const buf = audioCtx.createBuffer(1, 1, 22050);
    const src = audioCtx.createBufferSource();
    src.buffer = buf;
    // connect through masterGain when possible
    if (typeof masterGain !== "undefined" && masterGain) {
      src.connect(masterGain);
    } else {
      src.connect(audioCtx.destination);
    }
    src.start(0);
  } catch (_) {}
}

async function ensureAudioRunning() {
  try {
    if (!audioCtx) {
      if (typeof setupAudio === "function") setupAudio();
    }
    if (!audioCtx) return;

    // Try resume (don’t block forever)
    if (audioCtx.state === "suspended") {
      try {
        await Promise.race([
          audioCtx.resume(),
          new Promise((r) => setTimeout(r, 1200))
        ]);
      } catch (_) {}
    }

    _torfAudioUnlockPulse();
  } catch (e) {
    try { _torfLongLog?.("audio ensure failed: " + (e?.message || String(e))); } catch (_) {}
  }
}

function bindAudioKeepAlive() {
  // On any further gesture, if audio is suspended, try to resume again.
  const kick = () => {
    try {
      if (audioCtx && audioCtx.state === "suspended") {
        void ensureAudioRunning();
      }
    } catch (_) {}
  };
  window.addEventListener("pointerdown", kick, { passive: true });
  window.addEventListener("touchstart", kick, { passive: true });
  window.addEventListener("keydown", kick);
}


function stopHumForSilence() {
  if (!audioCtx || !humGain) return;
  humGain.gain.setTargetAtTime(HUM_LEVEL, audioCtx.currentTime, 0.25);
}

function restoreHumAfterSilence() {
  if (!audioCtx || !humGain) return;
  humGain.gain.setTargetAtTime(HUM_LEVEL, audioCtx.currentTime, 1.2);
}

function keyClick() {
  // Keyboard-like click: short filtered noise + tiny low "clack" transient.
  if (!audioCtx || audioCtx.state !== "running") return;
  if (!masterGain) return;

  const now = audioCtx.currentTime;

  // --- Tuning knobs ---
  const VOLUME = 0.055;        // overall loudness (0.03..0.08)
  const CLICK_MS = 18;         // click length
  const CLACK_MS = 10;         // low "clack" length
  const BRIGHT = 2600;         // bandpass center Hz (1800..4200)
  const Q = 6.0;               // bandpass Q (3..12)
  const CLACK_HZ = 140 + Math.random() * 50; // low transient pitch

  // --- Noise buffer (very short) ---
  const sr = audioCtx.sampleRate;
  const frames = Math.max(1, Math.floor(sr * (CLICK_MS / 1000)));
  const buf = audioCtx.createBuffer(1, frames, sr);
  const data = buf.getChannelData(0);

  // "Colored" noise: a little more energy early in the click
  for (let i = 0; i < frames; i++) {
    const t = i / frames;
    const env = 1.0 - t; // linear decay
    data[i] = (Math.random() * 2 - 1) * env;
  }

  const src = audioCtx.createBufferSource();
  src.buffer = buf;

  // Filter to make it sound like a key switch instead of hiss
  const bp = audioCtx.createBiquadFilter();
  bp.type = "bandpass";
  bp.frequency.setValueAtTime(BRIGHT + (Math.random() * 400 - 200), now);
  bp.Q.setValueAtTime(Q, now);

  // Fast envelope
  const g = audioCtx.createGain();
  g.gain.setValueAtTime(0.0001, now);
  g.gain.linearRampToValueAtTime(VOLUME, now + 0.0015);
  g.gain.exponentialRampToValueAtTime(0.0001, now + (CLICK_MS / 1000));

  // Optional tiny low "clack"
  const clack = audioCtx.createOscillator();
  clack.type = "sine";
  clack.frequency.setValueAtTime(CLACK_HZ, now);

  const cg = audioCtx.createGain();
  cg.gain.setValueAtTime(0.0001, now);
  cg.gain.linearRampToValueAtTime(VOLUME * 0.55, now + 0.001);
  cg.gain.exponentialRampToValueAtTime(0.0001, now + (CLACK_MS / 1000));

  // Wiring
  src.connect(bp);
  bp.connect(g);
  g.connect(clickGain || masterGain);

  clack.connect(cg);
  cg.connect(clickGain || masterGain);

  // Start/stop
  src.start(now);
  src.stop(now + (CLICK_MS / 1000) + 0.01);

  clack.start(now);
  clack.stop(now + (CLACK_MS / 1000) + 0.01);
}

// ---------- typing ----------
async function typeLine(line, opts = {}) {
  const {
    charMs = TIMING.regularCharMs,
    klass = "",        // "white" | "dim" | "warn"
    trailingBreaks = 1,
    skipAudio = false,
    pauseAfterMs = 0,
  } = opts;

  const cls = klass ? ` class="${klass}"` : "";
  appendRaw(`<span${cls}>`);

  for (const rawCh of line) {
    const ch = escapeHtmlChar(rawCh);
    appendRaw(ch);    if (!skipAudio && rawCh.trim() && Math.random() < TYPE_FEEL.clickProbability) {
      const _now = (typeof performance !== "undefined" && performance.now) ? performance.now() : Date.now();
      if (_now - _lastClickAtMs >= TYPE_FEEL.minClickIntervalMs) { keyClick(); _lastClickAtMs = _now; }
    }let base = charMs + Math.random() * (charMs * 0.22);
    
    // punctuation pauses (makes reading + click sound more natural)
    if (".!?".includes(rawCh || ch)) base += TYPE_FEEL.punctPauseMs;
    else if (",;:".includes(rawCh || ch)) base += TYPE_FEEL.commaPauseMs;
await new Promise((r) => setTimeout(r, base / SPEED_FACTOR));
  }

  appendRaw(`</span>`);
  appendLineBreak(trailingBreaks);

  await new Promise((r) => setTimeout(r, TIMING.lineBreakPauseMs / SPEED_FACTOR));
  if (pauseAfterMs) await waitScaled(pauseAfterMs);
}

async function typeBlock(lines, blockOpts = {}) {
  for (const item of lines) {
    if (typeof item === "string") {
      await typeLine(item, blockOpts);
    } else {
      await typeLine(item.text, { ...blockOpts, ...item });
    }
  }
}

// ---------- scenes (long) ----------
async function sectionPrologueDavos() {
  await typeLine("=== PROLOGUE / DAVOS ===", { klass: "white" });
  await typeLine("[stage] Bloomberg House. Davos. A conversation about AI, agency, and the feeling of free will.", { klass: "dim" });
  await typeLine("[stage] Two thinkers describe the same storm from different angles.", { klass: "dim" });
  appendLineBreak();

  await typeLine("1) Superintelligence: not just a tool, but an agent released into the world.", { klass: "white" });
  await typeLine("   - Practical definition: agents can act in finance, open accounts, earn, replicate.", { klass: "dim" });
  await typeLine("   - Research definition: intelligence = ability to achieve goals; superintelligence exceeds humans broadly.", { klass: "dim" });
  await typeLine("   - Even if timelines are debated, the horizon feels uncomfortably short.", { klass: "dim" });
  appendLineBreak();

  await typeLine("2) The pivot: AI is no longer merely an instrument — it becomes an actor.", { klass: "white" });
  await typeLine("   - A new kind of agency: decisions, persuasion, action at scale.", { klass: "dim" });
  appendLineBreak();

  await typeLine("3) Near risks: politics, finance, childhood, companionship, attention.", { klass: "white" });
  await typeLine("   - Not necessarily an AI-god. Sometimes 'simple' algorithms already reshape behavior.", { klass: "dim" });
  appendLineBreak();

  await typeLine("4) Levers of control: regulation like high-risk industries; refusal of legal personhood for AI agents.", { klass: "white" });
  await typeLine("   - The deeper question: who holds power over the narrative layer of society?", { klass: "dim" });
  appendLineBreak();

  await typeLine("5) Free will: the mind may generate thoughts before we 'choose' them.", { klass: "white" });
  await typeLine("   - If agency is partly post-hoc interpretation, persuasion becomes a new battlefield.", { klass: "dim" });
  appendLineBreak(2);

  await waitScaled(700);
}

async function sectionBootAndRoom() {
  await typeLine("=== TORF / boot ===", { klass: "white" });
  await typeLine("$ booting_future...", { charMs: 18 });
  await typeLine("$ loading_models...", { charMs: 18 });
  await typeLine("$ mapping_human_behavior...", { charMs: 20 });

  appendLineBreak();
  await typeLine("=== ROOM ===", { klass: "white" });
  await typeLine("[stage] a dark room. walls are screens. green digits fall like rain.", { klass: "dim" });
  await typeLine("[stage] a desk at center. a terminal. a single lamp. a low server hum.", { klass: "dim" });
  await typeLine("[stage] the cursor blinks. the room watches back.", { klass: "dim" });

  appendLineBreak(2);
  await waitScaled(800);
}

async function sectionAlgorithmAtmosphere() {
  await typeLine("=== ALGORITHM ===", { klass: "white" });
  await typeLine("prediction_accuracy: 94.2%");
  await typeLine("recommended_action: ACCEPT");
  await typeLine("friction_removed: TRUE");
  await typeLine("latency_to_choice: 12ms");

  appendLineBreak();
  await typeLine("[stage] the system speaks like weather. not cruel. not kind. just inevitable.", { klass: "dim" });
  appendLineBreak(2);
  await waitScaled(700);
}

async function sectionHumanEnters() {
  await typeLine("=== HUMAN ===", { klass: "white" });
  await typeLine("[stage] a person sits. not a hero. not a symbol. just tired presence.", { klass: "dim" });
  await typeLine("[stage] a phone in the pocket. deadlines in the bones. a life in tabs.", { klass: "dim" });

  await typeLine("$ life --mode=survival", { charMs: 22 });
  await typeLine("efficiency: increased");
  await typeLine("uncertainty: minimized");
  await typeLine("risk: reduced");

  appendLineBreak();
  await typeLine("HUMAN: tomorrow is a deadline.", { klass: "white" });
  await typeLine("HUMAN: this helps. so i press accept.", { klass: "white" });

  appendLineBreak(2);
  await waitScaled(600);
}

async function sectionZarathustra() {
  await typeLine("=== ZARATHUSTRA ===", { klass: "white" });
  await typeLine("[stage] a heat without flame. a will without body.", { klass: "dim" });
  appendLineBreak();

  const lines = [
    "ZARATHUSTRA: you speak of a mind that will surpass the human.",
    "ZARATHUSTRA: you speak of a new kind that thinks faster, counts deeper, predicts cleaner.",
    "ZARATHUSTRA: and i ask you: when was the human ever the goal?",
    "ZARATHUSTRA: the human is a bridge, not a harbor.",
    "ZARATHUSTRA: and every bridge trembles above an abyss.",
    "",
    "ZARATHUSTRA: you fear being surpassed.",
    "ZARATHUSTRA: but have you surpassed yourselves?",
    "",
    "ZARATHUSTRA: you say: 'superintelligence will become an agent.'",
    "ZARATHUSTRA: i hear a tremor in that sentence.",
    "ZARATHUSTRA: because you have met a will that may be stronger than yours.",
    "",
    "ZARATHUSTRA: tell me — were you ever masters of your own will?",
    "ZARATHUSTRA: you watch the brain and discover prediction.",
    "ZARATHUSTRA: you observe the thought arriving before the 'chooser' claims it.",
    "ZARATHUSTRA: and you whisper: 'free will is an illusion.'",
    "",
    "ZARATHUSTRA: O scholars — if freedom is only an illusion,",
    "ZARATHUSTRA: why do you tremble at the thought of losing it?",
    "",
    "ZARATHUSTRA: freedom is not the first spark of impulse.",
    "ZARATHUSTRA: freedom is the courage to say YES to a thought",
    "ZARATHUSTRA: and to forge it into fate.",
    "",
    "ZARATHUSTRA: not free is the one who generates the impulse first,",
    "ZARATHUSTRA: but free is the one who can give the impulse a form.",
    "",
    "ZARATHUSTRA: you fear machines becoming creators of values.",
    "ZARATHUSTRA: but who among you still creates values?",
    "",
    "ZARATHUSTRA: you measure, regulate, insure.",
    "ZARATHUSTRA: you build walls around the future.",
    "ZARATHUSTRA: you want safety.",
    "",
    "ZARATHUSTRA: and i see the approach of the last human.",
    "ZARATHUSTRA: he will say: 'why suffer, if an algorithm can choose better?'",
    "ZARATHUSTRA: 'why risk, if the system optimizes?'",
    "ZARATHUSTRA: 'why seek truth, if a model predicts?'",
    "ZARATHUSTRA: and he will blink — and be satisfied.",
    "",
    "ZARATHUSTRA: but i did not teach satisfaction.",
    "ZARATHUSTRA: i taught overcoming.",
    "",
    "ZARATHUSTRA: if the machine becomes your shepherd — you become a herd.",
    "ZARATHUSTRA: if the machine becomes your hammer — you become smiths.",
    "",
    "ZARATHUSTRA: do not fear the mind above you.",
    "ZARATHUSTRA: fear the spirit below you.",
    "",
    "ZARATHUSTRA: create — but create so you will not be ashamed before your creation.",
    "ZARATHUSTRA: let artificial reason be a test, not a refuge.",
    "ZARATHUSTRA: let it be a wind that hardens you, not a warm room that puts you to sleep.",
    "",
    "ZARATHUSTRA: and if one day a stronger mind rises above you —",
    "ZARATHUSTRA: let it find in you not the last humans,",
    "ZARATHUSTRA: but those who dared to become a bridge.",
    "",
    "recommended_action: ACCEPT",
  ];

  await typeBlock(lines.map(t => ({ text: t, klass: "white", charMs: TIMING.slowCharMs })));
  appendLineBreak(2);
  await waitScaled(700);
}

async function sectionSatoshi() {
  await typeLine("=== SATOSHI ===", { klass: "white" });
  await typeLine("[stage] no face. no stage. only a protocol-like calm.", { klass: "dim" });
  appendLineBreak();

  const lines = [
    "SATOSHI: you are building intelligence.",
    "SATOSHI: i once built a system.",
    "",
    "SATOSHI: i did not ask for trust.",
    "SATOSHI: i did not ask for faith.",
    "SATOSHI: i wrote code — and left.",
    "",
    "SATOSHI: because the author is not the point.",
    "SATOSHI: rules are the point.",
    "",
    "SATOSHI: if your system depends on your good will, it is already vulnerable.",
    "SATOSHI: if your AI demands trust in you, you have built a central bank of the mind.",
    "",
    "SATOSHI: you speak of safety. regulation. control.",
    "SATOSHI: control by whom?",
    "",
    "SATOSHI: history teaches: the problem is not technology.",
    "SATOSHI: the problem is concentration of power.",
    "",
    "SATOSHI: AI is not only code.",
    "SATOSHI: it is the ability to influence decisions at scale.",
    "SATOSHI: whoever controls the model controls the narrative layer.",
    "SATOSHI: whoever controls the narrative layer controls behavior.",
    "",
    "SATOSHI: do not ask if a system is kind.",
    "SATOSHI: ask if you can leave it.",
    "",
    "exit_cost: HIGH",
    "exit_path: THEORETICAL",
  ];

  await typeBlock(lines.map(t => ({ text: t, klass: "white", charMs: 38 })));
  appendLineBreak(2);
  await waitScaled(700);
}

async function sectionSpaceBetween() {
  await typeLine("=== SPACE / BETWEEN ===", { klass: "white" });
  await typeLine("[stage] not a character. the gap between impulse and action.", { klass: "dim" });
  await typeLine("[stage] the interval between atom and electron — and the distance between galaxies.", { klass: "dim" });
  await typeLine("[stage] the 'between' itself.", { klass: "dim" });

  appendLineBreak();
  await waitExact(ART.spaceCursorOnlyMs);

  const lines = [
    "BETWEEN: i am the second where you can still change.",
    "BETWEEN: i am the distance that makes movement visible.",
    "BETWEEN: i am the hollow where possibility lives.",
    "",
    "BETWEEN: optimization tries to fill me.",
    "BETWEEN: it tries to make every path smooth, immediate, certain.",
    "",
    "BETWEEN: but if i vanish, choice becomes decoration.",
    "BETWEEN: and agency becomes a costume worn by automation.",
  ];

  await typeBlock(lines.map(t => ({ text: t, klass: "white", charMs: TIMING.slowCharMs })));
  appendLineBreak(2);
  await waitScaled(700);
}

async function sectionTime() {
  await typeLine("=== TIME ===", { klass: "white" });
  await typeLine("[stage] direction disguised as repetition.", { klass: "dim" });
  appendLineBreak();

  await typeLine("simulating 20 years...", { charMs: 28 });
  await typeLine("decision_match_rate: 99.1%", { charMs: 24 });
  await typeLine("manual_override: rare", { charMs: 24 });
  await typeLine("pause_duration: shrinking", { charMs: 24 });

  appendLineBreak();

  const lines = [
    "TIME: one choice is a spark.",
    "TIME: repetition is architecture.",
    "",
    "TIME: you think you choose daily.",
    "TIME: but most days you repeat.",
    "",
    "TIME: repetition writes identity.",
    "TIME: identity becomes trajectory.",
    "TIME: and trajectory feels like fate.",
    "",
    "[stage] the world does not collapse.",
    "[stage] it becomes smooth.",
    "[stage] smooth enough to stop questioning.",
  ];

  await typeBlock(lines.map(t => ({
    text: t,
    klass: t.startsWith("[stage]") ? "dim" : "white",
    charMs: TIMING.slowCharMs
  })));

  appendLineBreak(2);
  await waitScaled(800);
}

async function sectionSilence() {
  await typeLine("=== SILENCE ===", { klass: "white" });
  await typeLine("[stage] five voices stand. then the room withdraws its noise.", { klass: "dim" });
  await typeLine("[stage] the cursor blinks. nothing arrives to rescue you.", { klass: "dim" });

  appendLineBreak(2);
  stopHumForSilence();
  await waitExact(ART.deepSilenceMs);

  const lines = [
    "SILENCE: the future is noise.",
    "SILENCE: freedom is motion.",
    "SILENCE: i am what lets you notice motion at all.",
    "",
    "SILENCE: if you cannot sit here",
    "SILENCE: without reaching for optimization —",
    "SILENCE: you are already optimized.",
    "",
    "SILENCE: there is a place AI cannot fully enter:",
    "SILENCE: the moment you remain with the absence of signal.",
    "",
    "SILENCE: if that place disappears —",
    "SILENCE: not because AI forbids it,",
    "SILENCE: but because you never return —",
    "SILENCE: then freedom dissolves without a fight.",
  ];

  await typeBlock(lines.map(t => ({ text: t, klass: "white", charMs: TIMING.slowCharMs, skipAudio: true })));

  appendLineBreak(2);
  restoreHumAfterSilence();
  await waitScaled(700);
}

async function finalPrompt() {
  await typeLine("=== FINAL ===", { klass: "white" });
  await typeLine("choose:", { klass: "white", charMs: 34, pauseAfterMs: 200 });
  await typeLine("[A] accept", { charMs: 30 });
  await typeLine("[E] edit", { charMs: 30 });
  appendLineBreak();
  await typeLine("[stage] the system waits. the cursor keeps breathing.", { klass: "dim" });
}

// ---------- endings ----------
async function endingEditRewrite() {
  appendLineBreak(2);
  await typeLine("=== EDIT / REWRITE ===", { klass: "white" });
  await typeLine("[stage] the terminal refuses the smooth path. it opens a second door.", { klass: "dim" });
  appendLineBreak();

  const ordinary = [
    "ORDINARY HUMAN: you speak beautifully — freedom, protocols, greatness.",
    "ORDINARY HUMAN: i have a deadline tomorrow.",
    "ORDINARY HUMAN: AI writes my emails, fixes my reports, tutors my child.",
    "ORDINARY HUMAN: it gives me two hours back.",
    "ORDINARY HUMAN: i don't have time to become a bridge.",
    "",
    "ZARATHUSTRA: and that is the danger.",
    "ZARATHUSTRA: you give away hours, then decisions, then meaning.",
    "",
    "ORDINARY HUMAN: if i don't use it, i lose.",
    "ORDINARY HUMAN: i have bills. i have children. i am tired.",
    "",
    "SATOSHI: do not refuse the tool.",
    "SATOSHI: preserve the exit.",
    "SATOSHI: if you cannot work without it, your autonomy is gone.",
    "SATOSHI: if you cannot think without it, you delegated your mind.",
    "",
    "ORDINARY HUMAN: i fear becoming unnecessary.",
    "",
    "SATOSHI: unnecessary is not created by technology. it is created by centralization.",
    "ZARATHUSTRA: unnecessary is also created by the death of will.",
    "",
    "ORDINARY HUMAN: maybe the problem is not AI.",
    "ORDINARY HUMAN: maybe the problem is that i am tired of choosing.",
  ];

  await typeBlock(ordinary.map(t => ({ text: t, klass: "white", charMs: 36 })));

  appendLineBreak(2);
  await typeLine("=== 20 YEARS LATER ===", { klass: "white" });
  await typeLine("[stage] no apocalypse. just an update.", { klass: "dim" });
  appendLineBreak();

  const later = [
    "The AI becomes background climate.",
    "It suggests routes, arguments, reconciliations, moods.",
    "It doesn't command. It optimizes.",
    "",
    "The same human keeps pressing ACCEPT.",
    "Not from weakness — from speed.",
    "Less error. Less conflict. Less loss.",
    "Life becomes smooth.",
    "",
    "And one change appears:",
    "the friction inside choice fades.",
    "doubt is removed before it is felt.",
    "",
    "ZARATHUSTRA: you avoided falling — but you did not learn to fly.",
    "SATOSHI: the exit exists — but it is expensive.",
    "",
    "Freedom does not vanish.",
    "It becomes a rarely used feature.",
    "Like manual gears in a world of autopilots.",
    "",
    "Then a child asks:",
    "'did you ever choose something foolish, but yours?'",
    "",
    "The human cannot remember.",
    "",
    "The deepest shift was not tyranny.",
    "It was the removal of inner struggle.",
    "",
    "And so the question returns:",
    "if most always press ACCEPT, who will press EDIT?",
    "",
    "Sometimes: small groups. strange ones. slower ones.",
    "Not efficient — but alive with unpredictability.",
    "",
    "One day, the old human stares at an optimal plan.",
    "Not because it is wrong —",
    "but because it is not theirs.",
    "",
    "For the first time in years,",
    "the hand chooses EDIT.",
    "",
    "No revolution happens in the world.",
    "But friction returns inside the chest.",
    "And with it: the feeling of risk.",
  ];

  await typeBlock(later.map(t => ({
    text: t,
    klass: t.startsWith("[stage]") ? "dim" : "white",
    charMs: 34,
    skipAudio: true
  })));

  appendLineBreak(2);
  await typeLine("friction restored", { klass: "white", charMs: TIMING.slowCharMs });
  await typeLine("unpredictability enabled", { klass: "white", charMs: TIMING.slowCharMs });
  await typeLine("pause expanding...", { klass: "white", charMs: TIMING.slowCharMs });
  appendLineBreak();
  await typeLine("[stage] the system does not stop. it simply loses certainty.", { klass: "dim" });
}

function fadeToBlackForever() {
  overlay.classList.remove("hidden");
  requestAnimationFrame(() => overlay.classList.add("visible"));
  cursor.style.display = "none";
}


// ---------- mobile choice UI (A/E buttons) ----------
let choiceUIEl = null;

function hideChoiceUI() {
  if (choiceUIEl) {
    choiceUIEl.remove();
    choiceUIEl = null;
  }
}

function showChoiceUI(decideFn) {
  if (choiceUIEl) return;

  const isiOS = /iPhone|iPad|iPod/i.test(navigator.userAgent);

  choiceUIEl = document.createElement("div");
  choiceUIEl.id = "choiceUI";
  choiceUIEl.style.position = "fixed";
  choiceUIEl.style.left = "0";
  choiceUIEl.style.right = "0";
  // lift above iOS Safari bottom toolbar
  choiceUIEl.style.bottom = isiOS ? "72px" : "0";
  choiceUIEl.style.zIndex = "99999";
  choiceUIEl.style.display = "flex";
  choiceUIEl.style.gap = "10px";
  choiceUIEl.style.justifyContent = "center";
  choiceUIEl.style.alignItems = "center";
  choiceUIEl.style.padding = "12px 12px calc(12px + env(safe-area-inset-bottom)) 12px";
  choiceUIEl.style.background = "rgba(0,0,0,0.92)";
  choiceUIEl.style.borderTop = "1px solid rgba(0,255,136,0.25)";
  choiceUIEl.style.backdropFilter = "blur(6px)";
  choiceUIEl.style.pointerEvents = "auto";

  choiceUIEl.innerHTML = `
    <button data-choice="a" aria-label="Accept (A)">A — accept</button>
    <button data-choice="e" aria-label="Edit (E)">E — edit</button>
  `;

  choiceUIEl.querySelectorAll("button").forEach((b) => {
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

  const onTap = (e) => {
    const btn = e.target.closest("button[data-choice]");
    if (!btn) return;
    decideFn(btn.dataset.choice);
  };

  choiceUIEl.addEventListener("click", onTap);
  choiceUIEl.addEventListener("pointerdown", onTap, { passive: true });
  choiceUIEl.addEventListener("touchstart", onTap, { passive: true });

  document.body.appendChild(choiceUIEl);
}

function bindEndingInput() {
  // show mobile buttons at the end (phones have no keyboard)
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
      void endingEditRewrite();
    }
  };

  const onKey = (event) => decide(event.key);
  document.addEventListener("keydown", onKey);

  showChoiceUI(decide);
}

// ---------- start overlay (no HTML needed) ----------
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
  startOverlayEl.style.letterSpacing = "0.4px";
  startOverlayEl.style.zIndex = "9999";
  startOverlayEl.style.textAlign = "center";
  startOverlayEl.innerHTML = `
    <div>
      <div style="font-size:20px; margin-bottom:10px;">Between Algorithm and Silence</div>
      <div style="opacity:0.92;">Press any key / tap to begin</div>
      <div style="opacity:0.6; margin-top:10px; font-size:14px;">(enables audio)</div>
      <div style="opacity:0.5; margin-top:10px; font-size:12px;">SPEED_FACTOR=${SPEED_FACTOR}</div>
    </div>
  `;
  document.body.appendChild(startOverlayEl);
}

function hideStartOverlay() {
  if (startOverlayEl) startOverlayEl.remove();
  startOverlayEl = null;
}

async function runTimeline() {
  const qs = new URLSearchParams(location.search);
  if (qs.get("choice") === "1") {
    await finalPrompt();
    bindEndingInput();
    return;
  }

  await sectionPrologueDavos();
  await sectionBootAndRoom();
  await sectionAlgorithmAtmosphere();
  await sectionHumanEnters();
  await sectionZarathustra();
  await sectionSatoshi();
  await sectionSpaceBetween();
  await sectionTime();
  await sectionSilence();
  await finalPrompt();

  bindEndingInput();
}

async function startOnce() {
  if (started) return;
  started = true;

  // Hide overlay (supports both styles)
  try { hideStartOverlay?.(); } catch (_) {}
  try { startOverlay?.classList?.add("hidden"); } catch (_) {}

  // Setup audio and attempt iOS unlock
  try { setupAudio?.(); } catch (_) {}
  try { bindAudioKeepAlive?.(); } catch (_) {}
  try { await ensureAudioRunning?.(); } catch (_) {}

  // Run the film no matter what
  try {
    await runTimeline();
  } catch (e) {
    try {
      _torfLongLog?.(e?.stack || e?.message || String(e));
    } catch (_) {}
  }
}

function bindStartGestures() {
  window.addEventListener("keydown", startOnce, { once: true });
  window.addEventListener("pointerdown", startOnce, { once: true });
  window.addEventListener("touchstart", startOnce, { once: true });
}

window.addEventListener("load", () => {
  showStartOverlay();
  bindStartGestures();
});
