import time
from flask import redirect, render_template, render_template_string, session, url_for

_BROWSER_ROUTE_HANDLERS = {}


class _NoopRouteRegistrar:
    """Route decorator shim used to build browser handlers without binding routes."""

    @staticmethod
    def route(*_args, **_kwargs):
        def decorator(func):
            return func

        return decorator


def get_browser_route_handler(name):
    return _BROWSER_ROUTE_HANDLERS.get(name)


def call_browser_route_handler(name, *, default_handler=None):
    handler = get_browser_route_handler(name)
    if handler is not None:
        return handler()
    if default_handler is not None:
        return default_handler()
    raise RuntimeError(f"Browser route handler '{name}' is not registered")


def render_browser_playground(*, render_template_func=render_template):
    return render_template_func("playground.html")


def render_browser_login(*, generate_challenge, get_rpc_connection, render_template_string_func=render_template_string):
    # Session challenge for legacy /verify_signature flow
    challenge_str = generate_challenge()
    session["challenge"] = challenge_str
    session["challenge_timestamp"] = time.time()

    # Optional node stats (safe if node unreachable)
    from datetime import datetime, timedelta, timezone

    try:
        rpc = get_rpc_connection()
        wallet_balance = rpc.getbalance()
        block_height = rpc.getblockcount()
        remaining = 1777777 - block_height

        uptime_sec = rpc.uptime()
        startup_time = (datetime.now(timezone.utc) - timedelta(seconds=uptime_sec)).strftime("%Y-%m-%d %H:%M:%S UTC")

        mp_info = rpc.getmempoolinfo()
        mempool_txs = mp_info.get("size", 0)
        mempool_usage = mp_info.get("usage", 0)
    except Exception:
        wallet_balance = None
        block_height = None
        remaining = None
        startup_time = None
        mempool_txs = None
        mempool_usage = None

    # Login page with dual Matrix backgrounds (toggle embedded inside panel)
    html = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"/>
  <meta name="apple-mobile-web-app-capable" content="yes"/>
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent"/>
  <meta name="theme-color" content="#00ff88"/>
  <title>HODLXXI — Login</title>

  <style>
    :root{
      --bg: #000;
      --fg: rgba(235,255,245,.92);
      --muted: rgba(235,255,245,.70);

      --accent: rgba(0,255,136,.95);
      --warn: rgba(255,42,42,.90);
      --blue: rgba(59,130,246,.95);
      --violet: rgba(139,92,246,.95);
      --orange: rgba(249,115,22,.95);

      --glass: rgba(8,12,10,.22);
      --glass2: rgba(0,0,0,.20);
      --stroke: rgba(255,255,255,.08);

      --radius: 16px;
      --pad: 14px;
      --mono: ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;
      --sans: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    }

    *{ box-sizing:border-box; margin:0; padding:0; -webkit-tap-highlight-color: transparent; }
    html,body{ height:100%; background:var(--bg); color:var(--fg); overflow-x:hidden; }
    body{ font-family: var(--sans); }

    /* Matrix canvas */
    #matrix-bg{ position:fixed; inset:0; width:100vw; height:100vh; display:block; z-index:0; pointer-events:none; }
    body > *:not(#matrix-bg){ position:relative; z-index:1; }

    /* Content */
    .wrap{
      max-width: 980px;
      margin: 0 auto;
      padding: 84px 14px 22px;
    }

    /* Minimal header */
    .topline{
      display:flex;
      align-items:flex-end;
      justify-content:space-between;
      gap:10px;
      margin-bottom: 14px;
    }
    .brand{
      font-family: var(--mono);
      letter-spacing: .14em;
      text-transform: uppercase;
      font-size: 12px;
      color: var(--warn);
      text-shadow: 0 0 6px rgba(255,42,42,.18);
      user-select:none;
    }
    .sub{
      font-family: var(--mono);
      font-size: 11px;
      color: rgba(235,255,245,.62);
      user-select:none;
    }

    /* Panel (glass card) */
    .panel{
      border-radius: var(--radius);
      border: 1px solid var(--stroke);
      background: var(--glass);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      box-shadow: 0 10px 40px rgba(0,0,0,.45);
      overflow:hidden;
      margin: 12px 0;
    }
    .panel-hd{
      padding: 12px 12px 10px;
      border-bottom: 1px solid rgba(255,255,255,.06);
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
      flex-wrap: wrap;
    }
    .panel-title{
      font-family: var(--mono);
      letter-spacing: .12em;
      text-transform: uppercase;
      font-size: 11px;
      color: var(--warn);
      text-shadow: 0 0 6px rgba(255,42,42,.18);
      user-select:none;
    }
    .panel-bd{ padding: var(--pad); }

    .manifesto-text{font-family:var(--mono);font-size:12px;line-height:1.55;color:rgba(235,255,245,.78)}
    .manifesto-text b{color:var(--accent)}
    .manifesto-text p{margin:.35rem 0}
    .home-link{color:var(--accent);text-decoration:none}
    .home-link:hover,.home-link:focus{text-decoration:underline;outline:none;text-shadow:0 0 14px rgba(0,255,136,.45)}


    .hintline{
      font-family: var(--mono);
      font-size: 11px;
      color: rgba(235,255,245,.72);
      line-height: 1.35;
    }
    .hintline b{ color: var(--accent); }

    /* Tabs + actions */
    .tabs{
      display:flex; gap:6px; flex-wrap:wrap; align-items:center;
    }
    .tab{
      border-radius: 12px;
      border:1px solid rgba(255,255,255,.08);
      background: rgba(0,0,0,.18);
      color: rgba(235,255,245,.9);
      padding: 8px 10px;
      font-size: 12px;
      font-family: var(--mono);
      cursor:pointer;
      user-select:none;
      touch-action: manipulation;
    }
    .tab.is-active{
      border-color: rgba(0,255,136,.35);
      box-shadow: 0 0 0 1px rgba(0,255,136,.12) inset;
    }

    .pill-actions{
      display:flex; gap:8px; flex-wrap:wrap; justify-content:flex-end; align-items:center;
      margin-left:auto;
    }
    .pill{
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,.10);
      background: rgba(0,0,0,.22);
      color: rgba(235,255,245,.92);
      padding: 8px 12px;
      font-family: var(--mono);
      font-size: 12px;
      cursor:pointer;
      user-select:none;
      touch-action: manipulation;
      display:inline-flex;
      align-items:center;
      gap:8px;
    }
    .pill:active{ transform: translateY(1px); background: rgba(0,0,0,.28); }

    .pill.ln{ border-color: rgba(249,115,22,.35); box-shadow: 0 0 0 1px rgba(249,115,22,.10) inset; }
    .pill.nostr{ border-color: rgba(139,92,246,.35); box-shadow: 0 0 0 1px rgba(139,92,246,.10) inset; }
    .pill.primary{ border-color: rgba(0,255,136,.35); box-shadow: 0 0 0 1px rgba(0,255,136,.12) inset; }

    /* Forms */
    label{
      display:block;
      font-family: var(--mono);
      font-size: 10px;
      letter-spacing: .08em;
      text-transform: uppercase;
      color: rgba(255,42,42,.85);
      margin: 10px 0 6px;
    }
    input, textarea{
      width:100%;
      border-radius: 14px;
      border: 1px solid var(--stroke);
      background: rgba(0,0,0,.22);
      color: var(--fg);
      padding: 12px 12px;
      font-size: 16px;
      outline:none;
      -webkit-appearance:none;
      appearance:none;
    }
    textarea{ min-height: 120px; resize: vertical; font-family: var(--mono); font-size: 12px; }

    input:focus, textarea:focus{
      border-color: rgba(0,255,136,.35);
      box-shadow: 0 0 0 1px rgba(0,255,136,.12) inset;
    }

    .row{ display:flex; gap:10px; flex-wrap:wrap; align-items:flex-start; }
    .col{ flex: 1 1 260px; min-width: 0; }

    .btnrow{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-top: 10px; }
    .btn{
      flex: 1 1 180px;
      border-radius: 14px;
      border: 1px solid var(--stroke);
      background: rgba(0,0,0,.20);
      color: var(--fg);
      padding: 12px 12px;
      font-family: var(--mono);
      font-size: 12px;
      letter-spacing: .02em;
      cursor:pointer;
      user-select:none;
      touch-action: manipulation;
      text-align:center;
    }
    .btn:active{ transform: translateY(1px); background: rgba(0,0,0,.28); }
    .btn.primary{
      border-color: rgba(0,255,136,.35);
      box-shadow: 0 0 0 1px rgba(0,255,136,.12) inset;
    }
    .btn.warn{
      border-color: rgba(255,42,42,.35);
      box-shadow: 0 0 0 1px rgba(255,42,42,.10) inset;
    }

    .status{
      font-family: var(--mono);
      font-size: 11px;
      color: rgba(235,255,245,.72);
      padding: 10px 0 0;
      min-height: 18px;
    }

    /* Challenge card */
    .card{
      border-radius: 14px;
      border: 1px solid var(--stroke);
      background: rgba(0,0,0,.20);
      padding: 12px 12px;
      margin: 10px 0;
      overflow:hidden;
    }
    .challenge{
      font-family: var(--mono);
      font-size: 12px;
      color: var(--accent);
      text-shadow: 0 0 8px rgba(0,255,136,.18);
      word-break: break-word;
      cursor: pointer;
      user-select: none;
      text-align: center;
    }

    .hidden{ display:none !important; }

    /* QR modal (glass, not white) */
    .body-locked{ height: 100dvh; overflow:hidden; }
    #qrModal{
      position:fixed; inset:0;
      background: rgba(0,0,0,.92);
      display:none;
      align-items:center;
      justify-content:center;
      z-index:99999;
      padding: max(12px, env(safe-area-inset-top)) 12px max(12px, env(safe-area-inset-bottom));
      backdrop-filter: blur(2px);
      -webkit-backdrop-filter: blur(2px);
    }
    .qr-content{
      width: min(420px, 92vw);
      border-radius: 16px;
      border: 1px solid rgba(255,255,255,.10);
      background: rgba(8,12,10,.22);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      box-shadow: 0 10px 40px rgba(0,0,0,.55);
      padding: 14px;
      text-align:center;
      color: rgba(235,255,245,.92);
    }
    .qr-title{
      font-family: var(--mono);
      font-size: 11px;
      letter-spacing: .12em;
      text-transform: uppercase;
      color: var(--warn);
      text-shadow:0 0 6px rgba(255,42,42,.18);
      margin-bottom: 10px;
      user-select:none;
    }
    #qrcode{ display:flex; justify-content:center; padding: 6px 0 2px; }
    #openInWallet{
      display:inline-block;
      margin-top: 8px;
      font-family: var(--mono);
      font-size: 12px;
      color: var(--blue);
      text-decoration:none;
    }
    #openInWallet:hover{ text-decoration: underline; }
    #lnurlText{
      margin-top: 10px;
      padding: 10px 10px;
      border-radius: 14px;
      border: 1px solid rgba(255,255,255,.08);
      background: rgba(0,0,0,.20);
      font-family: var(--mono);
      font-size: 11px;
      word-break: break-all;
      color: rgba(235,255,245,.82);
    }
    #countdown{
      margin-top: 8px;
      font-family: var(--mono);
      font-size: 11px;
      color: rgba(235,255,245,.72);
    }

    @media (prefers-reduced-motion: reduce){
      #matrix-bg{ display:none !important; }
      *{ transition:none !important; animation:none !important; }
    }


/* LOGIN_MANIFESTO_SINGLE_V1_CSS */
.manifesto-details{ position:relative; }
.manifesto-summary{
  list-style:none;
  cursor:pointer;
  user-select:none;
  display:flex;
  align-items:center;
  justify-content:flex-end;
  gap:8px;
  margin: 6px 0 10px;
  font-family: var(--mono);
  font-size: 11px;
  color: rgba(235,255,245,.78);
}
.manifesto-summary::-webkit-details-marker{ display:none; }
.manifesto-summary-label{
  color: var(--accent);
  text-shadow: 0 0 10px rgba(0,255,136,.25);
}
.manifesto-summary-icon{
  opacity:.85;
  transform: translateY(-1px);
  transition: transform .18s ease;
}

/* closed: show ~3 lines */
.manifesto-preview{
  max-height: 4.9em;
  overflow:hidden;
  position:relative;
  padding-bottom: 4px;
}
.manifesto-preview:after{
  content:"";
  position:absolute;
  left:0; right:0; bottom:0;
  height: 1.6em;
  background: linear-gradient(to bottom, rgba(0,0,0,0), rgba(0,0,0,.55));
  pointer-events:none;
}

/* open: reveal full */
.manifesto-full{ display:none; }
.manifesto-details[open] .manifesto-full{ display:block; margin-top: 10px; }
.manifesto-details[open] .manifesto-preview{ max-height:none; }
.manifesto-details[open] .manifesto-preview:after{ display:none; }
.manifesto-details[open] .manifesto-summary-icon{ transform: rotate(180deg); }
.manifesto-details[open] .manifesto-summary-label::after{
  content:" (collapse)";
  color: rgba(235,255,245,.55);
}

</style>
  <link rel="stylesheet" href="/static/ui_core.css?v=1"/></head>

<body>
  <canvas id="matrix-bg" aria-hidden="true"></canvas>

  <!-- Optional login sound -->
  <audio id="login-sound" src="/static/sounds/message.mp3" preload="auto" playsinline></audio>

  <div class="wrap">
    <!-- LOGIN_MANIFESTO_SINGLE_V1: single manifesto panel -->
    <div class="manifesto panel">
      <div class="panel-hd">
        <div class="panel-title">HODLXXI MANIFESTO</div>
        <div class="hintline">Bitcoin-native identity, presence, and covenants.</div>
      </div>
      <div class="panel-bd">
        <details class="manifesto-details" id="manifestoDetails">
          <summary class="manifesto-summary">
            <span class="manifesto-summary-label">Read more</span>
            <span class="manifesto-summary-icon" aria-hidden="true">▾</span>
          </summary>

          <div class="manifesto-preview manifesto-text">
            <p><b>HODLXXI</b> is a Bitcoin-native Auth0: sign-in with keys, not accounts.</p>
            <p>OAuth2/OIDC for apps, LNURL-Auth for wallets, Nostr for social identity, and Proof-of-Funds for trust gating.</p>
          </div>

          <div class="manifesto-full manifesto-text">
            <p><b>Keys replace accounts.</b> You authenticate by proving control of a key — not by handing over email + password.</p>
            <p><b>Developers get standards:</b> OAuth2/OIDC for Web2/Web3 apps, sessions, scopes, and redirects.</p>
            <p><b>Users get native flows:</b> Bitcoin signatures, LNURL-Auth QR, Nostr extensions, and optional Proof-of-Funds signals.</p>
            <p><b>Presence is a signal</b> (who is online / ready to coordinate), not a harvested social graph.</p>
            <p><b>Covenant descriptors</b> extend identity into time: reciprocal commitments with observable rules.</p>

            <p style="margin-top:.6rem;opacity:.92">
              <a class="home-link" href="/new-index">← Home</a>
            </p>
          </div>
        </details>
      </div>
    </div>




    <div class="topline">
      <div>
        <div class="brand">HODLXXI // LOGIN</div>
      </div>
      <div class="sub" id="miniStatus">status: ready</div>
    </div>

    <section class="panel">
      <div class="panel-hd">
        <div class="panel-title">Authenticate</div>

<div class="tabs" role="tablist" aria-label="Login methods">
  <button id="tabGuest" class="tab is-active" onclick="showTab('guest')" type="button">Guest</button>
  <button id="tabLegacy" class="tab" onclick="showTab('legacy')" type="button">Legacy</button>
  <button id="tabApi" class="tab" onclick="showTab('api')" type="button">API</button>
  <button id="tabSpecial" class="tab" onclick="showTab('special')" type="button">Special</button>
</div>

        <div class="pill-actions">
          <button class="pill nostr" type="button" onclick="loginWithNostr()" id="nostrBtn">🟣 Nostr</button>
          <button class="pill ln" type="button" onclick="loginWithLightning()" id="lnBtn">⚡ Lightning</button>
          <a class="pill" href="/pof/leaderboard" style="text-decoration:none;">🏆 PoF</a>
          <a class="pill" href="/playground" style="text-decoration:none;">▶ Playground</a>
          <a class="pill" href="/docs2" style="text-decoration:none;">📚 Docs</a>
        </div>
        <!-- LOGIN_MANIFESTO_DETAILS_V2: Variant C -->


      </div>

      <div class="panel-bd">
        <div class="hintline">
          Start with <b>Guest</b> or authenticate using <b>Lightning</b>, <b>Nostr</b>, or <b>Legacy</b>.
          Use <b>Lightning</b> for LNURL-Auth QR. Use <b>Nostr</b> via extension.
        </div>

        <!-- Legacy panel -->
         <div id="panelLegacy" class="hidden">
          <div class="card">
            <div class="challenge" id="legacyChallenge" title="Tap to copy">{{ challenge }}</div>
          </div>

          <div class="row">
            <div class="col">
              <label for="legacyPubkey">Public key (hex)</label>
              <input id="legacyPubkey" placeholder="02.. or 03.." autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"/>
            </div>
            <div class="col">
              <label for="legacySignature">Signature (base64)</label>
              <textarea id="legacySignature" rows="4" placeholder="paste signature"></textarea>
            </div>
          </div>

          <div class="btnrow">
            <button class="btn" type="button" onclick="copyText('legacyChallenge')">Copy challenge</button>
            <button class="btn primary" type="button" onclick="legacyVerify()">Verify &amp; Login</button>
          </div>

          <div id="legacyStatus" class="status"></div>
        </div>

        <!-- API panel -->
        <div id="panelApi" class="hidden">
          <div class="row">
            <div class="col">
              <label for="apiPubkey">Public key (hex)</label>
              <input id="apiPubkey" placeholder="02.. or 03.." autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"/>
            </div>
            <div class="col">
              <label for="apiChallenge">Challenge (readonly)</label>
              <textarea id="apiChallenge" rows="3" readonly></textarea>
            </div>
          </div>

          <div class="btnrow">
            <button class="btn primary" type="button" onclick="getChallenge()">Get challenge</button>
            <button class="btn" type="button" onclick="copyText('apiChallenge')">Copy</button>
          </div>

          <div class="row">
            <div class="col">
              <label for="apiSignature">Signature (base64)</label>
              <textarea id="apiSignature" rows="4" placeholder="paste signature"></textarea>
            </div>
            <div class="col">
              <label for="apiCid">Challenge ID</label>
              <input id="apiCid" readonly />
            </div>
          </div>

          <div class="btnrow">
            <button class="btn primary" type="button" onclick="apiVerify()">Verify &amp; Login</button>
          </div>

          <div id="apiStatus" class="status"></div>
        </div>

        <!-- Special panel -->
        <div id="panelSpecial" class="hidden">
          <label for="specialSignature">Special signature</label>
          <textarea id="specialSignature" rows="4" placeholder="Paste special signature"></textarea>
  <div style="margin-top:10px;">
    <div style="opacity:.75;font-size:.9em;margin-bottom:6px;">Challenge (sign this)</div>
    <textarea class="challenge" id="specialChallenge" rows="2" readonly title="Tap to copy"></textarea>
    <button class="btn" type="button" onclick="copyText('specialChallenge')">Copy challenge</button>
  </div>
          <div class="btnrow">
            <button class="btn primary" type="button" onclick="specialLogin()">Verify &amp; Login</button>
          </div>
          <div id="specialStatus" class="status"></div>
        </div>

        <!-- Guest panel -->
        <div id="panelGuest">
          <label for="guestPin">Guest / PIN (blank = random)</label>
          <input id="guestPin" type="text" placeholder="PIN or leave blank" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"/>
          <div class="btnrow">
            <button class="btn primary" type="button" onclick="guestLogin()">Enter as Guest</button>
          </div>
          <div class="status">Tip: invited PINs map to named guests (server-side).</div>
        </div>
      </div>
    </section>

    <!-- Optional stats panel (only shows if you later inject values with Jinja) -->
    <section class="panel hidden" id="nodePanel">
      <div class="panel-hd">
        <div class="panel-title">Node</div>
      </div>
      <div class="panel-bd">
        <div class="hintline mono">block_height={{ block_height }} · balance={{ wallet_balance }} · remaining={{ remaining }}</div>
        <div class="hintline mono">startup={{ startup_time }} · mempool={{ mempool_txs }} ({{ mempool_usage }})</div>
      </div>
    </section>
  </div>

<!-- QR modal -->
<div id="qrModal" aria-hidden="true">
  <div class="qr-content">
    <div class="qr-title">Scan with wallet</div>



<style>
/* LOGIN_QR_UI_V6: final QR modal layout (iPad landscape + phone) */

/* Background never steals taps */
#matrix-bg, #matrix-canvas, canvas#matrix-bg, canvas#matrix-canvas { pointer-events:none !important; z-index:0 !important; }

/* Buttons always tappable */
#lnBtn, #nostrBtn, button, .pill { position:relative; z-index:50; pointer-events:auto; touch-action:manipulation; -webkit-tap-highlight-color:rgba(0,0,0,0); }

/* Modal on top */
#qrModal{ position:fixed !important; inset:0 !important; z-index:999999 !important; overflow:auto !important; -webkit-overflow-scrolling:touch; padding:max(10px, env(safe-area-inset-top)) max(10px, env(safe-area-inset-right)) max(10px, env(safe-area-inset-bottom)) max(10px, env(safe-area-inset-left)); }

/* Card (your #qrCard wrapper) */
#qrCard, #qrCard.qr-card{
  width:min(92vw, 520px);
  max-height:86vh;
  overflow:auto;
  margin:10px auto;
  padding:12px;
  border-radius:16px;
  border:1px solid rgba(0,255,0,0.25);
  background:rgba(0,0,0,0.55);
  box-shadow:0 0 18px rgba(0,255,0,0.12);
}

/* QR + text */
#qrcode{ display:flex; justify-content:center; padding:8px 0 4px; }
#lnurlText{
  display:block;
  font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;
  font-size:13px; line-height:1.25; opacity:.95;
  word-break:break-all;
  max-height:11em; overflow:auto;
  padding:8px 10px;
  border-radius:10px;
  border:1px solid rgba(0,255,0,0.25);
  background:rgba(0,0,0,0.35);
}
#countdown{ display:block; margin-top:8px; font-size:13px; opacity:.9; }

/* LANDSCAPE: use max-height so it works on ALL iPads (including Pro) */
@media (orientation: landscape) and (max-height: 900px){
  #qrCard, #qrCard.qr-card{
    width:min(96vw, 980px);
    display:grid;
    grid-template-columns:260px 1fr;
    gap:12px;
    align-items:start;
  }
  #qrcode{ grid-column:1; }
  #lnurlText{ grid-column:2; max-height:8.5em; }
  #countdown{ grid-column:2; }
  #qrcode img, #qrcode canvas{ width:240px !important; height:240px !important; }
}

/* Very short landscape (phones): shrink QR */
@media (orientation: landscape) and (max-height: 700px){
  #qrcode img, #qrcode canvas{ width:200px !important; height:200px !important; }
}
</style>

<div id="qrCard" class="qr-card"> <!-- QR_MODAL_WRAPPER_V3 -->
    <div id="qrcode"></div>

    <a id="openInWallet" href="#" rel="noopener">Open in wallet</a>

    <!-- Mobile fallback: big tap target -->
    <button class="btn primary" id="openWalletBtn" type="button" style="margin-top:10px; width:100%;">
      ⚡ Open Lightning Wallet
    </button>

    <div id="lnurlText"></div>
    <div id="countdown"></div>

</div> <!-- /QR_MODAL_WRAPPER_V3 -->

                <button class="btn" id="copyLnurlBtn" type="button" style="margin-top:8px; width:100%;">📋 Copy LNURL</button>

<div class="btnrow" style="margin-top:10px;">
      <button class="btn warn" type="button" onclick="closeQR()">✕ Close</button>
    </div>
  </div>
</div>

  <script src="/static/js/qrcode.min.js"></script>
  <script src="/static/js/ios_tapfix.js"></script>
<script src="/static/js/tapfix_v2.js"></script>
<script src="/static/js/tap_probe.js"></script>


  <script>
    // Helper to respect ?next= parameter for post-login redirects
    function getRedirectUrl() {
      const params = new URLSearchParams(window.location.search);
      const next = params.get("next");
      return next || "/home";
    }

    function showTab(which) {
      const panels = {
        legacy: ["tabLegacy", "panelLegacy"],
        api: ["tabApi", "panelApi"],
        special: ["tabSpecial", "panelSpecial"],
        guest: ["tabGuest", "panelGuest"],
      };
      Object.entries(panels).forEach(([k,[tabId,panelId]]) => {
        const tab = document.getElementById(tabId);
        const panel = document.getElementById(panelId);
        if (tab) tab.classList.toggle("is-active", k === which);
        if (panel) panel.classList.toggle("hidden", k !== which);
      });
    }

    function setStatus(id, msg) {
      const el = document.getElementById(id);
      if (el) el.textContent = msg || "";
      const mini = document.getElementById("miniStatus");
      if (mini) mini.textContent = "status: " + (msg ? msg.toLowerCase() : "ready");
    }

    function copyText(id) {
      const el = document.getElementById(id);
      const txt =
        el.tagName === "TEXTAREA" || el.tagName === "INPUT"
          ? el.value
          : el.textContent.trim();
      navigator.clipboard.writeText(txt).catch(()=>{});
    }

    // Tap-to-copy challenge
    (function(){
      const legacyEl = document.getElementById("legacyChallenge");
      if (!legacyEl) return;
      legacyEl.addEventListener("click", () => {
        const text = legacyEl.textContent.trim();
        navigator.clipboard.writeText(text).then(() => {
          const orig = legacyEl.style.opacity || "1";
          legacyEl.style.opacity = "0.65";
          setTimeout(() => (legacyEl.style.opacity = orig), 220);
        }).catch(()=>{});
      });
    })();

    // Mirror legacy challenge into Special tab
    (function(){
      const src = document.getElementById("legacyChallenge");
      const dst = document.getElementById("specialChallenge");
      if (src && dst) dst.value = (src.textContent || "").trim();
    })();

    // --- Legacy verify ---
    async function legacyVerify() {
      const pubkey = document.getElementById("legacyPubkey").value.trim();
      const signature = document.getElementById("legacySignature").value.trim();
      const challenge = document.getElementById("legacyChallenge").textContent.trim();
      setStatus("legacyStatus", "Verifying...");
      try {
        const r = await fetch("/verify_signature", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pubkey, signature, challenge }),
        });
        const d = await r.json().catch(()=> ({}));
        if (r.ok && d.verified) {
          sessionStorage.setItem("playLoginSound", "1");
          // SOUND_IMMEDIATE_V1
          try{ window.HODLXXI_PLAY_SOUND('/static/sounds/message.mp3', 0.9); }catch(e){}

          window.location.href = getRedirectUrl();
        } else {
          setStatus("legacyStatus", d.error || "Failed");
        }
      } catch (e) {
        setStatus("legacyStatus", "Network error");
      }
    }

    // --- API challenge/verify ---
    async function getChallenge() {
      const pubkey = document.getElementById("apiPubkey").value.trim();
      setStatus("apiStatus", "Requesting challenge...");
      try {
        const r = await fetch("/api/challenge", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pubkey }),
        });
        const d = await r.json();
        if (!r.ok) throw new Error(d.error || "Request failed");
        document.getElementById("apiChallenge").value = d.challenge || "";
        document.getElementById("apiCid").value = d.challenge_id || "";
        setStatus("apiStatus", "Challenge ready");
      } catch (e) {
        setStatus("apiStatus", e.message || "Error");
      }
    }

    async function apiVerify() {
      const pubkey = document.getElementById("apiPubkey").value.trim();
      const signature = document.getElementById("apiSignature").value.trim();
      const cid = document.getElementById("apiCid").value.trim();
      setStatus("apiStatus", "Verifying...");
      try {
        const r = await fetch("/api/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pubkey, signature, challenge_id: cid }),
        });
        const d = await r.json().catch(()=> ({}));
        if (r.ok && d.verified) {
          sessionStorage.setItem("playLoginSound", "1");
          // SOUND_IMMEDIATE_V1
          try{ window.HODLXXI_PLAY_SOUND('/static/sounds/message.mp3', 0.9); }catch(e){}

          window.location.href = getRedirectUrl();
        } else {
          setStatus("apiStatus", d.error || "Failed");
        }
      } catch (e) {
        setStatus("apiStatus", "Network error");
      }
    }

    // --- Guest login ---
    async function guestLogin() {
      const pin = (document.getElementById("guestPin")?.value || "").trim();
      try {
        const res = await fetch("/guest_login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pin }),
        });
        const data = await res.json().catch(()=> ({}));
        if (!res.ok || !data.ok) {
          alert(data.error || "Guest login failed");
          return;
        }
        window.location.href = getRedirectUrl();
      } catch (e) {
        alert("Guest login error");
      }
    }

    // --- Special login ---
    async function specialLogin() {
      const sig = (document.getElementById("specialSignature")?.value || "").trim();
      setStatus("specialStatus", "Verifying...");
      try {
        const r = await fetch("/special_login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ signature: sig }),
        });
        const d = await r.json().catch(()=> ({}));
        if (r.ok && d.verified) {
          sessionStorage.setItem("playLoginSound", "1");
          // SOUND_IMMEDIATE_V1
          try{ window.HODLXXI_PLAY_SOUND('/static/sounds/message.mp3', 0.9); }catch(e){}

          window.location.href = getRedirectUrl();
        } else {
          setStatus("specialStatus", d.error || "Failed");
        }
      } catch (e) {
        setStatus("specialStatus", "Network error");
      }
    }
  </script>

  <!-- LNURL auth + Nostr -->
  <script>
    function urlToLnurl(url) {
      const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
      function polymod(v) {
        const G = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3];
        let chk = 1;
        for (const val of v) {
          const top = chk >>> 25;
          chk = ((chk & 0x1ffffff) << 5) ^ val;
          for (let i=0;i<5;i++) if ((top>>>i)&1) chk ^= G[i];
        }
        return chk;
      }
      function hrpExpand(hrp) {
        const ret = [];
        for (let i=0;i<hrp.length;i++) ret.push(hrp.charCodeAt(i)>>5);
        ret.push(0);
        for (let i=0;i<hrp.length;i++) ret.push(hrp.charCodeAt(i)&31);
        return ret;
      }
      function createChecksum(hrp, data) {
        const values = hrpExpand(hrp).concat(data).concat([0,0,0,0,0,0]);
        const mod = polymod(values) ^ 1;
        const ret = [];
        for (let p=0;p<6;p++) ret.push((mod >> (5*(5-p))) & 31);
        return ret;
      }
      function convertBits(data, from, to) {
        let acc=0, bits=0, ret=[], maxv=(1<<to)-1;
        for (const value of data) {
          acc = (acc<<from) | value;
          bits += from;
          while (bits >= to) { bits -= to; ret.push((acc>>bits) & maxv); }
        }
        if (bits > 0) ret.push((acc << (to-bits)) & maxv);
        return ret;
      }
      const bytes = new TextEncoder().encode(url);
      const data5 = convertBits(Array.from(bytes), 8, 5);
      const combined = data5.concat(createChecksum("lnurl", data5));
      let out = "lnurl1";
      for (const d of combined) out += CHARSET[d];
      return out.toUpperCase();
    }

    function renderQR(el, text) {
      el.innerHTML = "";
      new QRCode(el, { text, width: 256, height: 256, colorDark: "#000", colorLight: "#fff" });
    }


    // --- Mobile-friendly wallet open + copy fallbacks ---
    function openLightningWallet(lnurl) {
      const walletUrl = "lightning:" + lnurl;

      // 1) direct navigation (best when allowed)
      try {window.location.href = walletUrl;} catch(e) {}

      // 2) fallback: temp <a> click (some browsers prefer this)
      setTimeout(() => {
        try {const a = document.createElement("a");
          a.href = walletUrl;
          a.rel = "noopener";
          a.style.display = "none";
          document.body.appendChild(a);
          a.click();
          a.remove();} catch(e) {}
      }, 50);

      // 3) fallback: new tab (some Android cases)
      setTimeout(() => {
        try {window.location.href = walletUrl;} catch(e) {}
      }, 120);
    }

    (function bindLnurlFallbackButtons(){
      const openBtn = document.getElementById("openWalletBtn");
      const copyBtn = document.getElementById("copyLnurlBtn");
      const lnurlBox = document.getElementById("lnurlText");

      if (openBtn && !openBtn.dataset.bound) {
        openBtn.dataset.bound = "1";
        openBtn.addEventListener("click", () => {
          const lnurl = (lnurlBox?.textContent || "").trim();
          if (!lnurl) return alert("LNURL not ready yet");
          openLightningWallet(lnurl);
        }, { passive: true });
      }

      if (copyBtn && !copyBtn.dataset.bound) {
        copyBtn.dataset.bound = "1";
        copyBtn.addEventListener("click", async () => {
          const lnurl = (lnurlBox?.textContent || "").trim();
          if (!lnurl) return alert("LNURL not ready yet");
          try {await navigator.clipboard.writeText(lnurl);
            const old = copyBtn.textContent;
            copyBtn.textContent = "✅ Copied";
            setTimeout(() => (copyBtn.textContent = old), 900);} catch(e) {
            alert("Copy failed — press and hold the LNURL text to copy.");
          }
        }, { passive: true });
      }
    })();
    let poll=null, expire=null;

    function startPolling(sid) {
      clearInterval(poll);
      poll = setInterval(async () => {
        const r = await fetch(`/api/lnurl-auth/check/${sid}`);
        const j = await r.json().catch(()=> ({}));
        if (j.authenticated) {
          clearInterval(poll);
          clearInterval(expire);
          closeQR();
          window.location.href = getRedirectUrl();
        }
      }, 2000);
    }

    function startCountdown(s) {
      clearInterval(expire);
      let r = s;
      const el = document.getElementById("countdown");
      expire = setInterval(() => {
        r--;
        if (el) el.textContent = `Expires in ${Math.floor(r/60)}:${(r%60).toString().padStart(2,"0")}`;
        if (r <= 0) {
          clearInterval(poll);
          clearInterval(expire);
          closeQR();
        }
      }, 1000);
    }

    function closeQR() {
      const modal = document.getElementById("qrModal");
      if (modal) modal.style.display = "none";
      document.body.classList.remove("body-locked");
    }

    async function loginWithLightning() {
      const modal     = document.getElementById("qrModal");
      const qrBox     = document.getElementById("qrcode");
      const lnurlBox  = document.getElementById("lnurlText");
      const countdown = document.getElementById("countdown");

      try {
        if (qrBox) qrBox.innerHTML = "";
        if (lnurlBox) lnurlBox.textContent = "Requesting Lightning login…";
        if (countdown) countdown.textContent = "";
        if (modal) modal.style.display = "flex";
        document.body.classList.add("body-locked");

        const res = await fetch("/api/lnurl-auth/create", { method: "POST", headers: { "Accept": "application/json" }, credentials: "same-origin" });
if (!res.ok) {
          const txt = await res.text().catch(()=> "");
          console.error("LNURL-auth create failed:", res.status, txt);
          alert("Lightning login init failed: " + res.status);
          closeQR();
          return;
        }

        let j;
        try {j = await res.json();} catch (e) {
          console.error("LNURL-auth JSON parse error:", e);
          alert("Lightning login error: invalid server response");
          closeQR();
          return;
        }

        if (!j || !j.callback_url) {
          console.error("LNURL-auth missing callback_url:", j);
          alert("Lightning login error: missing callback_url");
          closeQR();
          return;
        }

        const lnurl = urlToLnurl(j.callback_url);



// bind mobile fallback buttons (must be a user gesture)

          try {await navigator.clipboard.writeText(lnurl);} catch(e) {}
// Set the link + mobile fallback button

    // REMOVED: orphaned e.preventDefault()



        // --- Canonical LNURL UI wiring (single source of truth) ---
        const walletUrl = "lightning:" + lnurl;

        // "Open in wallet" link (works on desktop and some mobile browsers)
        const openInWalletEl = document.getElementById("openInWallet");
        if (openInWalletEl) {
          openInWalletEl.href = walletUrl;
          openInWalletEl.onclick = (e) => {
            e.preventDefault();
            // some mobile browsers require direct navigation
            window.location.href = walletUrl;
          };
        }

        // Mobile-friendly explicit button (user gesture)
        const openBtn = document.getElementById("openWalletBtn");
        if (openBtn) {
          openBtn.onclick = () => {
            try {window.location.href = walletUrl;} catch(e) {}
            // fallback: attempt <a> click
            setTimeout(() => {
              try {const a = document.createElement("a");
                a.href = walletUrl;
                a.rel = "noopener";
                a.style.display = "none";
                document.body.appendChild(a);
                a.click();
                a.remove();} catch(e) {}
            }, 50);
          };
        }

        // Copy LNURL button (works even if wallet open is blocked)
        const copyBtn = document.getElementById("copyLnurlBtn");
        if (copyBtn) {
          copyBtn.onclick = async () => {
            try {await navigator.clipboard.writeText(lnurl);
              alert("LNURL copied");} catch (e) {
              // fallback: prompt
              window.prompt("Copy LNURL:", lnurl);
            }
          };
        }
if (qrBox && typeof QRCode !== "undefined") renderQR(qrBox, lnurl);
        if (lnurlBox) lnurlBox.textContent = lnurl;

        const openEl = document.getElementById("openInWallet");
        if (openEl) {
  openEl.href = "lightning:" + lnurl;
  openEl.onclick = (e) => {
    // Ensure this is a user gesture
    e.preventDefault();
    window.location.href = "lightning:" + lnurl;
  };
}


        startPolling(j.session_id);
        startCountdown(j.expires_in || 300);
      } catch (e) {
        console.error("Lightning login error:", e);
        alert("Lightning login error");
        closeQR();
      }
    }

    async function loginWithNostr() {
      if (!window.nostr) {
        alert("No Nostr extension found");
        return;
      }
      const pubkey = await window.nostr.getPublicKey();
      const r = await fetch("/api/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pubkey, method: "nostr" }),
      });
      const d = await r.json();
      const event = {
        kind: 22242,
        created_at: Math.floor(Date.now()/1000),
        tags: [["challenge", d.challenge], ["app", "HODLXXI"]],
        content: `HODLXXI Login: ${d.challenge}`,
      };
      const signed = await window.nostr.signEvent(event);
      const vr = await fetch("/api/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challenge_id: d.challenge_id, pubkey, nostr_event: signed }),
      });
      const j2 = await vr.json();
      if (j2.verified) window.location.href = getRedirectUrl();
      else alert(j2.error || "Verification failed");
    }

    // --- Bind pill buttons (mobile-safe) ---
    (function bindLoginPills(){
      function setMini(msg){
        const mini = document.getElementById("miniStatus");
        if (mini) mini.textContent = "status: " + msg;
      }

      function bindOne(id, fnName){
        const el = document.getElementById(id);
        if (!el) return;

        const fire = async (e) => {
          try {
            if (e && e.preventDefault) e.preventDefault();
            if (e && e.stopPropagation) e.stopPropagation();
            setMini(fnName + "…");
            // Call the function by name to avoid scope issues
            const fn = window[fnName] || (typeof eval === "function" ? eval(fnName) : null);
            if (typeof fn !== "function") {
              setMini(fnName + " missing");
              alert(fnName + " is not available (JS load error).");
              return;
            }
            await fn();
            setMini("ready");
          } catch (err) {
            console.error(fnName + " error:", err);
            setMini("error");
            alert(fnName + " failed: " + (err && err.message ? err.message : "unknown"));
          }
        };

        // iOS: touchstart is often more reliable than click
        el.addEventListener("touchstart", fire, { passive: false });
        el.addEventListener("click", fire, { passive: false });
      }

      // Make sure the global functions are reachable via window
      try {if (typeof loginWithLightning === "function") window.loginWithLightning = loginWithLightning;} catch(e) {}
      try {if (typeof loginWithNostr === "function") window.loginWithNostr = loginWithNostr;} catch(e) {}

      setMini("ready");
    })();



</script>
  <script>
    // --- Top-level pill wiring (runs on page load) ---
    (function bindLoginPillsTopLevel(){
      function bind(id, fnName){
        const el = document.getElementById(id);
        if (!el) return;

        el.addEventListener("click", async (e) => {
          try {
            e.preventDefault();
            e.stopPropagation();
            const fn = window[fnName];
            if (typeof fn !== "function") {
              console.error("Missing handler:", fnName);
              alert("Init failed: " + fnName + " is not available");
              return;
            }
            await fn();
          } catch (err) {
            console.error(fnName + " error:", err);
            alert("Init failed");
          }
        }, { passive: false });
      }

      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", () => {
          bind("lnBtn", "loginWithLightning");
          bind("nostrBtn", "loginWithNostr");
        });
      } else {
        bind("lnBtn", "loginWithLightning");
        bind("nostrBtn", "loginWithNostr");
      }
    })();
  </script>
</script>

  <!-- Matrix Animation (warp) -->
  <script>
    (function() {
      const canvas = document.getElementById('matrix-bg');
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      const CHARS = ['0','1'];
      let width = 0, height = 0, particles = [], raf = null;

      function resize() {
        const dpr = Math.max(1, Math.min(window.devicePixelRatio || 1, 2));
        const cssW = window.innerWidth, cssH = window.innerHeight;
        canvas.width = Math.floor(cssW * dpr);
        canvas.height = Math.floor(cssH * dpr);
        canvas.style.width = cssW + 'px';
        canvas.style.height = cssH + 'px';
        ctx.setTransform(1,0,0,1,0,0);
        ctx.scale(dpr, dpr);
        width = cssW; height = cssH;

        particles = [];
        for (let i = 0; i < 400; i++) {
          particles.push({
            x: (Math.random() - 0.5) * width,
            y: (Math.random() - 0.5) * height,
            z: Math.random() * 800 + 100
          });
        }
        ctx.fillStyle = 'rgba(0,0,0,1)';
        ctx.fillRect(0, 0, width, height);
      }

      function draw() {
        ctx.fillStyle = 'rgba(0,0,0,0.25)';
        ctx.fillRect(0, 0, width, height);
        ctx.fillStyle = '#00ff88';

        for (const p of particles) {
          const scale = 200 / p.z;
          const x2 = width / 2 + p.x * scale;
          const y2 = height / 2 + p.y * scale;
          const size = Math.max(8 * scale, 1);
          ctx.font = size + 'px monospace';
          ctx.fillText(CHARS[(Math.random() > 0.5) | 0], x2, y2);
          p.z -= 5;
          if (p.z < 1) {
            p.x = (Math.random() - 0.5) * width;
            p.y = (Math.random() - 0.5) * height;
            p.z = 800;
          }
        }
        raf = requestAnimationFrame(draw);
      }

      function onVis() {
        if (document.hidden) { if (raf) cancelAnimationFrame(raf), raf = null; }
        else { if (!raf) raf = requestAnimationFrame(draw); }
      }

      window.addEventListener('resize', resize);
      document.addEventListener('visibilitychange', onVis);
      resize();
      raf = requestAnimationFrame(draw);
    })();
  </script>
</body>
</html>

"""

    return render_template_string(
        html,
        challenge=challenge_str,
        block_height=block_height,
        wallet_balance=wallet_balance,
        remaining=remaining,
        startup_time=startup_time,
        mempool_txs=mempool_txs,
        mempool_usage=mempool_usage,
    )


def perform_browser_logout(*, audit_logger=None, remote_addr=None):
    if audit_logger is not None:
        try:
            audit_logger.log_event("auth.logout", ip=remote_addr)
        except Exception:
            pass
    session.clear()
    return redirect(url_for("login"))


def register_browser_routes(
    app,
    *,
    generate_challenge,
    get_rpc_connection,
    logger,
    render_template_string_func,
    special_names,
    force_relay,
    chat_history,
    online_users,
    purge_old_messages,
):
    """Register minimal browser entry routes."""

    @app.route("/login", methods=["GET"])
    def login():
        return render_browser_login(
            generate_challenge=generate_challenge,
            get_rpc_connection=get_rpc_connection,
            render_template_string_func=render_template_string_func,
        )

    _BROWSER_ROUTE_HANDLERS["login"] = login

    @app.route("/app", endpoint="chat")
    def chat():
        my_pubkey = session.get("logged_in_pubkey", "")
        online_users_list = list(online_users)

        # Make sure only fresh messages are in memory (<= 45 seconds old)
        purge_old_messages()

        chat_html = r"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <title>HODLXXI — Covenant Lounge</title>
      <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
      <meta name="theme-color" content="#00ff88" />

      <!-- Socket.IO -->
      <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.1/socket.io.min.js"></script>

      <style>
        :root {
          --bg: #000;
          --fg: #e6f1ef;
          --accent: #00ff88;
          --red: #ff3b30;
          --blue: #3b82f6;
          --muted: #8a9da4;

          --stroke: rgba(255,255,255,.08);
          --glass: rgba(8,12,10,.22);

          --radius-lg: 16px;
          --radius-pill: 999px;
          --touch: 44px;

          --mono: ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;
        }

        * { box-sizing:border-box; margin:0; padding:0; -webkit-tap-highlight-color: transparent; }
        html, body { width:100%; height:100%; background:var(--bg); color:var(--fg); overflow:hidden; }

        html, body { height: var(--app-height, 100dvh) !important; }
        .shell { height: var(--app-height, 100dvh) !important; }
        body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Mono", Menlo, Consolas, monospace; }

        /* Matrix canvas */
        #matrix-bg { position:fixed; inset:0; z-index:0; pointer-events:none; }
        body > *:not(#matrix-bg){ position:relative; z-index:1; }

        .shell{
          width:100%;
          height:100%;
          padding: 1.25rem;
          display:flex;
          flex-direction:column;
          gap: 0.9rem;
        }



        .top-bar{
          display:flex;
          align-items:center;
          justify-content:space-between;
          gap:0.75rem;
        }
        .top-left{ display:flex; align-items:center; gap:0.75rem; }

        .back-btn{
          min-width:var(--touch);
          height:var(--touch);
          border-radius:50%;
          border:1px solid var(--stroke);
          background: rgba(0,0,0,.25);
          color: var(--accent);
          cursor:pointer;
          display:inline-flex;
          align-items:center;
          justify-content:center;
          box-shadow: 0 0 14px rgba(0,255,136,.18);
          font-family: var(--mono);
          font-size: 12px;
          padding: 0 10px;
        }

        .title-block{ display:flex; flex-direction:column; gap:0.1rem; }
        .title{
          font-size: clamp(1.05rem, 1.4vw, 1.25rem);
          letter-spacing:.08em;
          text-transform: uppercase;
          color: var(--accent);
        }
        .subtitle{ font-size:0.8rem; color:var(--muted); }

        .top-right{
          display:flex;
          align-items:center;
          gap:0.65rem;
          font-size:0.8rem;
          color:var(--muted);
          flex-wrap:wrap;
          justify-content:flex-end;
        }

        .online-chip{
          display:inline-flex;
          align-items:center;
          gap:0.35rem;
          padding:0.3rem 0.7rem;
          border-radius:var(--radius-pill);
          border:1px solid rgba(34,197,94,0.35);
          background: radial-gradient(circle at 0 0, rgba(34,197,94,0.20), transparent 65%);
          font-family: var(--mono);
        }
        .online-dot{
          width:0.5rem; height:0.5rem; border-radius:50%;
          background:#22c55e;
          box-shadow:0 0 8px rgba(34,197,94,.9);
        }
        .status-pill{
          font-family: var(--mono);
          font-size:0.72rem;
          padding:0.12rem 0.55rem;
          border-radius:999px;
          border:1px solid rgba(148,163,184,0.55);
          background: rgba(0,0,0,.22);
          color: rgba(148,163,184,0.95);
        }

        .layout{
          flex:1;
          min-height:0;
          display:grid;
          grid-template-columns: minmax(0, 2.1fr) minmax(0, 1.3fr);
          gap: 0.9rem;
        }

        .panel{
          border-radius: var(--radius-lg);
          border: 1px solid var(--stroke);
          background: var(--glass);
          backdrop-filter: blur(10px);
          -webkit-backdrop-filter: blur(10px);
          box-shadow: 0 10px 40px rgba(0,0,0,.45);
          padding: 0.9rem;
          display:flex;
          flex-direction:column;
          gap:0.75rem;
          min-height:0;
          overflow:hidden;
        }

        .panel-header{
          display:flex;
          align-items:center;
          justify-content:space-between;
          gap:0.5rem;
          font-size:0.78rem;
          color:var(--muted);
          font-family: var(--mono);
        }
        .panel-title{
          text-transform:uppercase;
          letter-spacing:0.12em;
          font-size:0.7rem;
          color: rgba(255,59,48,.88);
          text-shadow: 0 0 6px rgba(255,59,48,.18);
        }
        .panel-badge{
          border-radius:var(--radius-pill);
          border:1px solid rgba(148,163,184,0.45);
          padding:0.18rem 0.6rem;
          font-size:0.7rem;
          white-space:nowrap;
        }

        .panel-body{ flex:1; min-height:0; display:flex; flex-direction:column; gap:0.75rem; }

        .messages-wrap{
          flex:1; min-height:0;
          border-radius: 12px;
          border: 1px solid rgba(255,255,255,.08);
          background: rgba(0,0,0,.22);
          padding: 0.6rem;
          display:flex;
          flex-direction:column;
          overflow:hidden;
        }
        .message-list{
          list-style:none;
          flex:1;
          min-height:0;
          overflow-y:auto;
          padding-right:0.3rem;
          display:flex;
          flex-direction:column;
          gap:0.45rem;
          scrollbar-width:thin;
          scrollbar-color: rgba(148,163,184,0.7) transparent;
        }
        .message-list::-webkit-scrollbar{ width:6px; }
        .message-list::-webkit-scrollbar-thumb{ background: rgba(148,163,184,0.7); border-radius:999px; }

        .message{
          align-self:flex-start;
          max-width:min(85%, 520px);
          border-radius:12px;
          padding:0.45rem 0.6rem;
          background: rgba(15,23,42,0.75);
          border:1px solid rgba(255,255,255,.06);
          box-shadow: 0 10px 18px rgba(0,0,0,.45);
        }
        .message.me{
          align-self:flex-end;
          border-color: rgba(34,197,94,0.45);
          box-shadow: 0 0 0 1px rgba(34,197,94,0.08) inset, 0 10px 18px rgba(0,0,0,.45);
        }

        .message-meta{
          display:flex;
          justify-content:space-between;
          gap:0.6rem;
          font-size:0.68rem;
          color: var(--muted);
          margin-bottom: 0.18rem;
          font-family: var(--mono);
        }
        .message-sender{ max-width:70%; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .message-text{ font-size:0.86rem; line-height:1.3; word-break:break-word; }

        .composer{
          display:flex;
          align-items:center;
          gap:0.5rem;
          margin-top:0.1rem;
        }
        .input-shell{
          flex:1;
          border-radius: var(--radius-pill);
          border: 1px solid rgba(255,255,255,.08);
          background: rgba(0,0,0,.22);
          display:flex;
          align-items:center;
          gap:0.45rem;
          padding:0.28rem 0.7rem;
        }
        .input-shell input{
          width:100%;
          border:none;
          outline:none;
          background:transparent;
          color:var(--fg);
          font-size:0.9rem;
        }
        .hint-pill{
          font-family: var(--mono);
          font-size:0.72rem;
          padding:0.12rem 0.45rem;
          border-radius:999px;
          border: 1px dashed rgba(148,163,184,0.5);
          color: rgba(148,163,184,0.9);
          white-space:nowrap;
        }
        .send-btn{
          min-width:var(--touch);
          height:var(--touch);
          border-radius:50%;
          border:none;
          cursor:pointer;
          display:inline-flex;
          align-items:center;
          justify-content:center;
          font-size:1.25rem;
          color:#e5fdf2;
          background: radial-gradient(circle at 20% 0, #22c55e 0, #15803d 45%, #052e16 100%);
          box-shadow: 0 0 0 1px rgba(34,197,94,0.55), 0 0 22px rgba(34,197,94,0.55);
        }
        .send-btn:active{ transform: translateY(1px) scale(0.98); }

        .ephemeral{
          font-family: var(--mono);
          font-size:0.72rem;
          color: var(--muted);
        }
        .ephemeral span{ color: var(--accent); }

        /* Sidebar */
        .sidebar{ display:flex; flex-direction:column; gap:0.75rem; min-height:0; }

        .users-list-wrap{
          flex:1; min-height:0;
          border-radius:12px;
          border:1px solid rgba(255,255,255,.08);
          background: rgba(0,0,0,.22);
          padding:0.6rem;
          display:flex;
          flex-direction:column;
          overflow:hidden;
        }
        .users-list{
          list-style:none;
          flex:1; min-height:0;
          overflow-y:auto;
          padding-right:0.3rem;
          display:flex;
          flex-direction:column;
          gap:0.4rem;
        }
        .user-item{
          display:flex;
          align-items:center;
          justify-content:space-between;
          gap:0.5rem;
          padding:0.35rem 0.45rem;
          border-radius:10px;
          border:1px solid rgba(255,255,255,.06);
          background: rgba(0,0,0,.20);
          cursor:pointer;
          user-select:none;
          -webkit-user-select:none;
        }
        .user-left{ display:flex; align-items:center; gap:0.45rem; min-width:0; }
        .user-dot{
          width:0.42rem; height:0.42rem; border-radius:50%;
          background:#22c55e;
          box-shadow:0 0 8px rgba(34,197,94,.85);
          flex:0 0 auto;
        }
        .user-name{ font-size:0.8rem; max-width:170px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .user-sub{ font-size:0.66rem; color:var(--muted); opacity:.9; font-family: var(--mono); }
        .user-tag{
          display:inline-flex;
          padding:0.08rem 0.4rem;
          border-radius:999px;
          border:1px solid rgba(148,163,184,0.55);
          font-size:0.64rem;
          color: rgba(148,163,184,0.95);
          font-family: var(--mono);
          margin-top: 2px;
          width: fit-content;
        }
        .user-btn{
          font-size:0.9rem;
          min-width:30px; height:30px;
          border-radius:999px;
          border:1px solid rgba(148,163,184,0.5);
          background: rgba(0,0,0,.18);
          color: var(--fg);
          cursor:pointer;
          flex:0 0 auto;
        }

        /* Group call panel */
        .group-call-panel{
          border-radius:12px;
          border:1px solid rgba(255,255,255,.08);
          background: rgba(0,0,0,.22);
          padding:0.6rem;
          overflow:hidden;
        }
        .group-call-panel.hidden{ display:none; }

        .call-header{
          display:flex;
          align-items:flex-start;
          justify-content:space-between;
          gap:0.6rem;
          flex-wrap:wrap;
          margin-bottom:0.6rem;
        }
        .call-status{
          font-family: var(--mono);
          font-size:0.78rem;
          color: var(--muted);
        }
        .call-controls{
          display:flex;
          flex-wrap:wrap;
          gap:0.35rem;
        }
        .ctrl-btn{
          font-family: var(--mono);
          font-size:0.75rem;
          padding:0.35rem 0.7rem;
          border-radius:999px;
          border:1px solid rgba(148,163,184,0.5);
          background: rgba(0,0,0,.18);
          color: var(--fg);
          cursor:pointer;
          display:inline-flex;
          align-items:center;
          gap:0.3rem;
          transition: all .15s ease;
        }
        .ctrl-btn:hover{ border-color: rgba(0,255,136,.35); }
        .ctrl-btn.active{
          border-color: rgba(239,68,68,0.6);
          background: rgba(239,68,68,0.12);
          color: #fecaca;
        }
        .ctrl-btn.ctrl-danger{
          border-color: rgba(239,68,68,0.7);
          background: rgba(239,68,68,0.12);
          color: #fecaca;
        }

        .call-grid{
          display:grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap:0.5rem;
        }
        @media (min-width: 600px){
          .call-grid{ grid-template-columns: repeat(2, 1fr); }
        }

    /* VIDEO_PIN_MODE_V1: click a remote tile to pin it (full mode) */
    #remoteVideosContainer{ display: contents; } /* remote tiles become grid items */
    .video-tile{ cursor: pointer; }
    .video-tile.pinned{
      grid-column: 1 / -1;
      aspect-ratio: 16 / 9;
    }
    .video-tile.dim{
      opacity: 0.25;
      filter: blur(0.4px);
    }
    .video-tile{
          position:relative;
          width:100%;
          aspect-ratio: 4/3;
          border-radius:10px;
          overflow:hidden;
          border:1px solid rgba(148,163,184,0.45);
          background:#020617;
        }
        .video-tile.local-tile{ border-color: rgba(59,130,246,0.55); }
        .video-tile video{ width:100%; height:100%; object-fit:cover; background:#020617; }
        .video-label{
          position:absolute;
          left:0.5rem; right:0.5rem; bottom:0.5rem;
          font-family: var(--mono);
          font-size:0.7rem;
          color: rgba(226,232,240,0.95);
          background: rgba(0,0,0,0.45);
          padding:0.2rem 0.4rem;
          border-radius:6px;
          backdrop-filter: blur(4px);
          -webkit-backdrop-filter: blur(4px);
          white-space:nowrap;
          overflow:hidden;
          text-overflow:ellipsis;
        }

        .floating-call-btn{
          position:fixed;
          bottom: 18px;
          right: 18px;
          width: 56px;
          height: 56px;
          border-radius: 50%;
          border: 2px solid var(--accent);
          background: rgba(0,0,0,.28);
          color: var(--accent);
          font-size: 1.35rem;
          cursor:pointer;
          box-shadow: 0 0 18px rgba(59,130,246,0.22), 0 0 18px rgba(0,255,136,0.18);
          z-index: 1000;
        }

    @media (max-width: 768px){
      html, body { overflow-y:auto !important; -webkit-overflow-scrolling:touch; }
      .shell { padding: 0.75rem; height:auto; min-height:100%; }

      .layout{
        display:flex !important;
        flex-direction:column !important;
        gap:0.75rem !important;
      }

      .chat-panel { order: 1; }
      .sidebar    { order: 2; }

      /* ✅ make chat area actually usable in portrait */
      .chat-panel{
        flex: 1 1 auto !important;
        min-height: 62vh !important;
      }

      .chat-panel .panel-body{
        flex: 1 1 auto !important;
        min-height: 0 !important;
      }

      .chat-panel .messages-wrap{
        flex: 1 1 auto !important;
        min-height: 0 !important;
        overflow:hidden;
      }

      /* remove fixed vh; let it fill remaining height */
      .chat-panel .message-list{
        flex: 1 1 auto !important;
        min-height: 0 !important;
        height: auto !important;
        max-height: none !important;
        overflow-y:auto !important;
        -webkit-overflow-scrolling:touch;
      }

      /* ✅ shrink presence list so chat wins vertical space */
      .presence-panel .users-list-wrap{
        max-height: 22vh !important;
        overflow:auto;
      }

      /* ✅ iOS safe area so composer isn't hidden behind home bar */
      .composer{
        padding-bottom: calc(env(safe-area-inset-bottom, 0px) + 6px);
      }

      /* ✅ ensure online list is actually visible on mobile */
      .sidebar{
        flex: 0 0 auto !important;
        min-height: 180px !important;
      }

      .presence-panel{
        min-height: 180px !important;
      }

      .presence-panel .panel-body{
        min-height: 120px !important;
      }

      .presence-panel .users-list-wrap{
        height: 180px !important;
        max-height: 30vh !important;
        overflow-y: auto !important;
        -webkit-overflow-scrolling: touch;
      }

    }
      .sidebar    { order: 2; }

      .chat-panel .messages-wrap{
        flex:1 !important;
        min-height:0 !important;
        overflow:hidden;
      }

      .chat-panel .message-list{
        height: 55vh !important;
        max-height: 60vh !important;
        overflow-y:auto !important;
        -webkit-overflow-scrolling:touch;
      }

      .presence-panel .users-list-wrap{
        height: 24vh;
        max-height: 28vh;
        overflow:auto;
      }
    }
      .sidebar    { order: 2; }

      .chat-panel .messages-wrap{
        height: 60vh;
        max-height: 65vh;
        overflow:auto;
      }

      .presence-panel .users-list-wrap{
        height: 24vh;
        max-height: 28vh;
        overflow:auto;
      }
    }


    /* LOGIN_MODAL_MOBILE_CSS: make LN modal readable on phones */
    #lnurlText{
      display:block;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 12px;
      line-height: 1.25;
      opacity: 0.95;
      word-break: break-all;
      max-height: 10.5em;
      overflow:auto;
      padding: 8px 10px;
      border-radius: 10px;
      border: 1px solid rgba(0,255,0,0.25);
      background: rgba(0,0,0,0.35);
    }

    #countdown{
      display:block;
      margin-top: 8px;
      font-size: 13px;
      opacity: 0.9;
    }

    @media (max-width: 768px){
      /* ensure modal content stacks nicely */
      #qrModal .modal-content, #qrModal .modal-inner, #qrModal .qr-wrap{
        width: min(92vw, 520px) !important;
        max-height: 86vh !important;
        overflow: auto !important;
      }
      #qrcode{
        display:flex;
        justify-content:center;
        padding: 8px 0 4px;
      }
      #lnurlText{
        font-size: 13px;
      }
    }


    /* LOGIN_LANDSCAPE_QR_FIX: stable modal + prevent bg tap stealing */
    #matrix-bg, #matrix-canvas, canvas#matrix-bg, canvas#matrix-canvas,
    #matrix-bg *, #matrix-canvas *, .matrix-bg, .matrix-bg *{
      pointer-events: none !important;
    }

    /* Make sure actual UI is tappable above background layers */
    .pill, .pill *, button, a, .btn, .toolbar, .shell, .panel, .main, .content {
      pointer-events: auto;
    }

    /* QR Modal always above everything */
    #qrModal{
      position: fixed !important;
      inset: 0 !important;
      z-index: 999999 !important;
    }

    /* iPad / tablet landscape: modal should fit and show QR + text + timer */
    @media (max-width: 1024px) and (orientation: landscape){
      #qrModal{
        padding: 10px !important;
      }

      /* allow scrolling if height is tight */
      #qrModal *{
        max-height: none;
      }

      /* make QR smaller so it doesn't get clipped */
      #qrcode img, #qrcode canvas{
        width: 220px !important;
        height: 220px !important;
      }

      #lnurlText{
        max-height: 7.5em !important;
      }
    }


    /* LOGIN_MODAL_LAYOUT_V3 */

    /* Keep matrix background behind everything */
    #matrix-bg, #matrix-canvas, canvas#matrix-bg, canvas#matrix-canvas,
    #matrix-bg *, #matrix-canvas * {
      pointer-events: none !important;
      z-index: 0 !important;
    }

    /* Ensure main UI sits above background */
    .shell, .main, .content, .panel, .toolbar, .login-wrap, .auth-row, .pillbar {
      position: relative;
      z-index: 10;
    }

    /* QR modal always on top */
    #qrModal{
      position: fixed !important;
      inset: 0 !important;
      z-index: 999999 !important;
    }

    /* Make modal content scroll if height is tight */
    #qrModal{
      overflow: auto !important;
      -webkit-overflow-scrolling: touch;
    }

    /* Improve readability of lnurl text (keep your neon vibe) */
    #lnurlText{
      display:block;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      word-break: break-all;
      overflow:auto;
      padding: 8px 10px;
      border-radius: 10px;
      border: 1px solid rgba(0,255,0,0.25);
      background: rgba(0,0,0,0.35);
    }

    /* iPad / tablet LANDSCAPE: show QR + text side-by-side */
    @media (orientation: landscape) and (max-height: 600px){
      /* Try multiple container names so it works with your current markup */
      #qrModal > div,
      #qrModal .modal-content,
      #qrModal .modal-inner,
      #qrModal .qr-wrap{
        display: grid !important;
        grid-template-columns: 260px 1fr !important;
        gap: 12px !important;
        align-items: start !important;
        width: min(96vw, 980px) !important;
        margin: 10px auto !important;
        max-height: 86vh !important;
        overflow: auto !important;
      }

      #qrcode{ grid-column: 1 !important; display:flex; justify-content:center; }
      #lnurlText{ grid-column: 2 !important; max-height: 9em !important; }
      #countdown{ grid-column: 2 !important; margin-top: 8px !important; }
      #qrcode img, #qrcode canvas { width: 240px !important; height: 240px !important; }
    }

    /* Phones portrait: keep it stacked, readable */
    @media (max-width: 768px){
      #qrcode{ display:flex; justify-content:center; padding: 8px 0 4px; }
      #lnurlText{ font-size: 13px; max-height: 11em; }
      #countdown{ font-size: 13px; opacity: .9; }
    }


    /* QR_MODAL_LANDSCAPE_V1: iPad/tablet landscape QR modal layout */
    @media (orientation: landscape) and (max-width: 1024px){
      /* assume first inner wrapper holds qrcode + lnurlText + countdown */
      #qrModal > div{
        width: min(96vw, 980px) !important;
        max-height: 86vh !important;
        overflow: auto !important;
        display: grid !important;
        grid-template-columns: 260px 1fr !important;
        grid-auto-rows: min-content !important;
        gap: 12px !important;
        align-items: start !important;
        margin: 10px auto !important;
      }

      #qrcode{ grid-column: 1 !important; display:flex !important; justify-content:center !important; }
      #lnurlText{ grid-column: 2 !important; max-height: 8.5em !important; }
      #countdown{ grid-column: 2 !important; margin-top: 8px !important; }

      #qrcode img, #qrcode canvas{
        width: 240px !important;
        height: 240px !important;
      }
    }


    /* QR_MODAL_WRAPPER_V3 */
    #qrCard.qr-card{
      width: min(92vw, 520px);
      max-height: 86vh;
      overflow: auto;
      margin: 10px auto;
      padding: 12px;
      border-radius: 16px;
      border: 1px solid rgba(0,255,0,0.25);
      background: rgba(0,0,0,0.55);
      box-shadow: 0 0 18px rgba(0,255,0,0.12);
    }

    @media (orientation: landscape) and (max-width: 1024px){
      #qrCard.qr-card{
        width: min(96vw, 980px);
        display: grid;
        grid-template-columns: 260px 1fr;
        gap: 12px;
        align-items: start;
      }
      #qrcode{ grid-column: 1; display:flex; justify-content:center; }
      #lnurlText{ grid-column: 2; max-height: 8.5em; }
      #countdown{ grid-column: 2; margin-top: 8px; }
      #qrcode img, #qrcode canvas{ width: 240px !important; height: 240px !important; }
    }


    /* LOGIN_QR_LAYOUT_V4 */

    /* Never let the matrix/bg steal taps */
    #matrix-bg, #matrix-canvas, canvas#matrix-bg, canvas#matrix-canvas,
    #matrix-bg *, #matrix-canvas *, canvas {
      pointer-events: none !important;
    }

    /* Make sure login controls are above background */
    .shell, .main, .content, .panel, .toolbar, .login-wrap, .auth-row, .pillbar, .pill, button {
      position: relative;
      z-index: 10;
    }

    /* Modal always on top */
    #qrModal{
      position: fixed !important;
      inset: 0 !important;
      z-index: 999999 !important;
      overflow: auto !important;
      -webkit-overflow-scrolling: touch;
    }

    /* Our wrapper card */
    #qrCard{
      width: min(92vw, 520px);
      max-height: 86vh;
      overflow: auto;
      margin: 10px auto;
      padding: 12px;
      border-radius: 16px;
      border: 1px solid rgba(0,255,0,0.25);
      background: rgba(0,0,0,0.55);
      box-shadow: 0 0 18px rgba(0,255,0,0.12);
    }

    /* Text + timer look good on phones */
    #lnurlText{
      display:block;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 13px;
      line-height: 1.25;
      opacity: 0.95;
      word-break: break-all;
      max-height: 11em;
      overflow:auto;
      padding: 8px 10px;
      border-radius: 10px;
      border: 1px solid rgba(0,255,0,0.25);
      background: rgba(0,0,0,0.35);
    }
    #countdown{
      display:block;
      margin-top: 8px;
      font-size: 13px;
      opacity: 0.9;
    }

    /* iPad/tablet LANDSCAPE: QR left, text+timer right */
    @media (orientation: landscape) and (max-width: 1024px){
      #qrCard{
        width: min(96vw, 980px);
        display: grid;
        grid-template-columns: 260px 1fr;
        gap: 12px;
        align-items: start;
      }
      #qrcode{ grid-column: 1; display:flex; justify-content:center; padding: 8px 0 4px; }
      #lnurlText{ grid-column: 2; max-height: 8.5em; }
      #countdown{ grid-column: 2; }
      #qrcode img, #qrcode canvas{ width: 240px !important; height: 240px !important; }
    }



    /* LOGIN_QR_COSMETIC_POLISH_V1 */
    /* Cosmetic only: spacing, readability, consistent card + better landscape behavior */

    #qrModal{
      /* nicer overlay */
      background: rgba(0,0,0,0.70) !important;
      backdrop-filter: blur(10px) saturate(120%);
      -webkit-backdrop-filter: blur(10px) saturate(120%);
    }

    /* The modal “card” */
    #qrCard, #qrCard.qr-card{
      border-radius: 18px !important;
      padding: 14px !important;
      border: 1px solid rgba(0,255,0,0.28) !important;
      box-shadow:
        0 0 26px rgba(0,255,0,0.14),
        inset 0 0 0 1px rgba(0,255,0,0.08) !important;
    }

    /* QR block */
    #qrcode{
      padding: 10px 0 6px !important;
    }
    #qrcode img, #qrcode canvas{
      border-radius: 12px !important;
      box-shadow: 0 0 18px rgba(0,255,0,0.12) !important;
    }

    /* LNURL text box */
    #lnurlText{
      font-size: 13px !important;
      letter-spacing: 0.15px;
      scrollbar-width: thin;
    }

    /* Countdown: centered + tabular digits (cleaner timer look) */
    #countdown{
      text-align: center;
      font-variant-numeric: tabular-nums;
      letter-spacing: 0.25px;
      padding: 2px 0 0;
    }

    /* Buttons/links inside the modal: consistent tap target + spacing */
    #qrModal a, #qrModal button{
      min-height: 44px; /* iOS recommended */
      border-radius: 14px;
    }
    #qrModal a{
      text-decoration: none;
    }
    #qrModal .qr-card a,
    #qrModal .qr-card button{
      width: 100%;
      margin-top: 10px;
    }

    /* Open-in-wallet link: make it look intentional */
    #openInWallet{
      display:block;
      text-align:center;
      opacity: 0.95;
      padding: 6px 0 2px;
    }

    /* Small phones: tighten spacing */
    @media (max-width: 420px){
      #qrCard, #qrCard.qr-card{ padding: 12px !important; }
      #lnurlText{ font-size: 12.5px !important; max-height: 10.5em !important; }
    }

    /* iPad / landscape with limited height: keep everything visible */
    @media (orientation: landscape) and (max-height: 700px){
      #qrCard, #qrCard.qr-card{
        width: min(96vw, 980px) !important;
        display: grid !important;
        grid-template-columns: 220px 1fr !important;
        gap: 12px !important;
        align-items: start !important;
      }
      #qrcode{ grid-column: 1 !important; }
      #lnurlText{ grid-column: 2 !important; max-height: 7.5em !important; }
      #countdown{ grid-column: 2 !important; }
      #qrcode img, #qrcode canvas{ width: 200px !important; height: 200px !important; }
    }



    /* KEYBOARD_LIFT_V1: lift composer + keep last messages visible when mobile keyboard opens */
    /* VIDEO_PIN_LAYOUT_V3: make remote tiles actual grid items + pinned big tile */
    #remoteVideosContainer{ display: contents; } /* critical: children become grid items */

    /* When a tile is pinned, make a 2-col layout: big pinned + small strip */
    .call-grid.pinned-mode{
      grid-template-columns: minmax(0, 1fr) 220px;
      grid-auto-rows: min-content;
      align-items: start;
    }
    .call-grid.pinned-mode .video-tile.pinned{
      grid-column: 1;
      grid-row: 1 / span 99;
      aspect-ratio: 16/9;
      min-height: 280px;
    }
    .call-grid.pinned-mode .video-tile.local-tile{
      grid-column: 2;
    }
    .call-grid.pinned-mode .video-tile:not(.pinned){
      grid-column: 2;
      height: 140px;
      aspect-ratio: 1/1;
    }

    @media (max-width: 768px){
      .call-grid.pinned-mode{ grid-template-columns: minmax(0, 1fr) 140px; }
      .call-grid.pinned-mode .video-tile:not(.pinned){ height: 110px; }
      .call-grid.pinned-mode .video-tile.pinned{ min-height: 220px; }
    }



    /* PRESENCE_ROLE_COLORS_V1: color users by role (full/limited/pin/random) */
    .user-item.role-full{
      border-color: rgba(255,149,0,0.55) !important;
      box-shadow: 0 0 18px rgba(255,149,0,0.12);
    }
    .user-item.role-full .user-dot{
      background:#ff9500 !important;
      box-shadow:0 0 10px rgba(255,149,0,0.85) !important;
    }

    .user-item.role-limited{
      border-color: rgba(34,197,94,0.40) !important;
    }
    .user-item.role-limited .user-dot{
      background:#22c55e !important;
      box-shadow:0 0 10px rgba(34,197,94,0.85) !important;
    }

    .user-item.role-pin{
      border-color: rgba(255,255,255,0.35) !important;
    }
    .user-item.role-pin .user-dot{
      background:#e5e7eb !important;
      box-shadow:0 0 10px rgba(229,231,235,0.65) !important;
    }

    .user-item.role-random{
      border-color: rgba(255,59,48,0.45) !important;
    }
    .user-item.role-random .user-dot{
      background:#ff3b30 !important;
      box-shadow:0 0 10px rgba(255,59,48,0.75) !important;
    }

    /* CALL_FULLSCREEN_OVERLAY_V1: true “big” call view (panel breaks out of sidebar) */
    body.call-full #groupCallPanel{
      position: fixed !important;
      inset: 10px !important;
      z-index: 999999 !important;
      display: block !important;
      max-height: none !important;
      overflow: hidden !important;
      background: rgba(0,0,0,0.82) !important;
      backdrop-filter: blur(10px) saturate(120%);
      -webkit-backdrop-filter: blur(10px) saturate(120%);
      border: 1px solid rgba(0,255,136,0.22) !important;
      box-shadow: 0 0 30px rgba(0,255,136,0.12);
    }
    body.call-full .floating-call-btn{ display:none !important; }

    /* make call grid fill available height in overlay */
    body.call-full #groupCallPanel .call-grid{
      height: calc(100vh - 170px);
    }
    body.call-full #groupCallPanel .video-tile.pinned{
      min-height: calc(100vh - 210px) !important;
    }
    @media (max-width: 768px){
      body.call-full #groupCallPanel{ inset: 6px !important; }
      body.call-full #groupCallPanel .call-grid{ height: calc(100vh - 190px); }
    }


    /* KB_LIFT_DISABLED_V1: disable mobile keyboard lift (restore old behavior) */
    </style></head>

    <body
      data-my-pubkey="{{ my_pubkey|e }}"
      data-access-level="{{ access_level|e }}"
    >
      <canvas id="matrix-bg"></canvas>

      <!-- expose SPECIAL_NAMES to JS -->
      <script id="specialNames" type="application/json">{{ special_names|tojson }}</script>

      <main class="shell">
        <header class="top-bar">
          <div class="top-left">
            <div class="title-block">
              <div class="title">Global Chat</div>
              <div class="subtitle">Presence chips ·  whispers · p2p call</div>
            </div>
          </div>
          <div class="top-right">
            <div class="online-chip">
              <span class="online-dot"></span>
              <span><span id="onlineCount">{{ online_users|length }}</span> online</span>
            </div>
            <div id="room-status" class="status-pill">Connecting…</div>
          </div>
        </header>

        <section class="layout">
          <!-- Chat -->
          <section class="panel chat-panel">
            <div class="panel-header">
              <div class="panel-title">Live flow · <span style="color:var(--accent)">HODLXXI</span></div>
              <div class="panel-badge">Self-erase after 45s</div>
            </div>

            <div class="panel-body">
              <div class="messages-wrap">
                <ul id="messages" class="message-list">
                  {% for m in history %}
                  <li class="message{% if m.pubkey == my_pubkey %} me{% endif %}" data-ts="{{ m.ts|default(0) }}">
                    <div class="message-meta">
                      <div class="message-sender">
      {%- set pk = (m.pubkey or 'anon') -%}
      {%- if pk.startswith('guest') or pk|length < 20 -%}
        …{{ pk[-4:] }}
      {%- else -%}
        {{ pk[:2] }}…{{ pk[-4:] }}
      {%- endif -%}
    </div>
                      <div class="message-timestamp">''</div>
                    </div>
                    <div class="message-text">{{ (m.text or '')|e }}</div>
                  </li>
                  {% endfor %}
                </ul>
              </div>

              <div class="composer">
                <div class="input-shell">
                  <input id="chatInput" type="text" autocomplete="off" placeholder="Type a whisper…" />
                  <div class="hint-pill">@</div>
                </div>
                <button id="sendBtn" class="send-btn" type="button">➤</button>
              </div>

          </section>

          <!-- Sidebar -->
          <aside class="sidebar">
            <section class="panel presence-panel">
              <div class="panel-header">
                <div class="panel-title">Online presence</div>
                <div class="panel-badge">@ = mention · Hold = call</div>
              </div>

              <div class="panel-body">
                <div class="users-list-wrap">
                  <ul id="userList" class="users-list">
                    {% for pk in online_users %}
                    <li class="user-item" data-pubkey="{{ pk|e }}">
                      <div class="user-left">
                        <span class="user-dot"></span>
                        <div style="min-width:0;">
                          <div class="user-name">…{{ pk[-4:] }}</div>
                          {% if pk == my_pubkey %}
                            <div class="user-tag">you</div>
                          {% else %}
                            <div class="user-sub"><!-- PRESENCE_USER_SUB_JINJA_V2 -->{% set p = pk or '' %}{% if p[:10] == 'guest-pin-' %}PIN…{{ p[-4:] }}{% elif p[:6] == 'guest-' %}GUEST…{{ p[-4:] }}{% elif p|length > 10 and (p[:2] == '02' or p[:2] == '03') %}{{ p[:2] }}…{{ p[-4:] }}{% elif p|length > 10 %}…{{ p[-4:] }}{% else %}{{ p }}{% endif %}</div>
                          {% endif %}
                        </div>
                      </div>
                      <button class="user-btn" type="button">@</button>
                    </li>
                    {% endfor %}
                  </ul>
                </div>
              </div>
            </section>

            <!-- Group call panel -->
            <section id="groupCallPanel" class="group-call-panel hidden">
              <div class="call-header">
                <div id="callStatus" class="call-status">Not in a call</div>
                <div class="call-controls">
                  <button id="muteBtn" class="ctrl-btn" type="button"><span>🔊</span>Mute</button>
                  <button id="cameraBtn" class="ctrl-btn" type="button"><span>📷</span>Camera Off</button>
                  <button id="fsBtn" class="ctrl-btn" type="button"><span>⛶</span>Full</button>
                  <button id="hangupGroupBtn" class="ctrl-btn ctrl-danger" type="button"><span>✕</span>Hang Up</button>
                </div>
              </div>

              <div class="call-grid">
                <div class="video-tile local-tile">
                  <video id="localVideo" muted playsinline autoplay></video>
                  <div class="video-label">You</div>
                </div>
                <div id="remoteVideosContainer"></div>
              </div>
            </section>
          </aside>
        </section>
      </main>

      <button class="floating-call-btn" onclick="startGroupCall()" title="Start group call">📞</button>

      <script>
        const myPubkey = document.body.dataset.myPubkey || "";
        const accessLevel = document.body.dataset.accessLevel || "limited";
        const SPECIAL_NAMES = (() => {
          try { return JSON.parse(document.getElementById("specialNames")?.textContent || "{}"); }
          catch { return {}; }
        })();

        // Matrix "space warp"
        (() => {
          const canvas = document.getElementById('matrix-bg');
          if (!canvas) return;
          const ctx = canvas.getContext('2d');
          const CHARS = ['0','1'];
          const isMobile = window.matchMedia && window.matchMedia('(max-width: 768px)').matches;
          let width = 0, height = 0, particles = [], raf = null;

          function resize() {
            const dpr = Math.max(1, Math.min(window.devicePixelRatio || 1, 2));
            const cssW = window.innerWidth;
            const cssH = window.innerHeight;
            canvas.width  = Math.floor(cssW * dpr);
            canvas.height = Math.floor(cssH * dpr);
            canvas.style.width  = cssW + 'px';
            canvas.style.height = cssH + 'px';
            ctx.setTransform(1,0,0,1,0,0);
            ctx.scale(dpr, dpr);
            width = cssW; height = cssH;

            particles = [];
            for (let i = 0; i < (isMobile ? 120 : 400); i++) {
              particles.push({ x:(Math.random()-0.5)*width, y:(Math.random()-0.5)*height, z:Math.random()*800+100 });
            }
            ctx.fillStyle = 'rgba(0,0,0,1)';
            ctx.fillRect(0, 0, width, height);
          }

          function draw() {
            ctx.fillStyle = 'rgba(0,0,0,0.25)';
            ctx.fillRect(0, 0, width, height);
            ctx.fillStyle = '#00ff88';
            for (const p of particles) {
              const scale = 200 / p.z;
              const x2 = width/2 + p.x * scale;
              const y2 = height/2 + p.y * scale;
              const size = Math.max(8 * scale, 1);
              ctx.font = size + 'px monospace';
              ctx.fillText(CHARS[(Math.random() > 0.5) | 0], x2, y2);
              p.z -= (isMobile ? 2 : 5);
              if (p.z < 1) { p.x=(Math.random()-0.5)*width; p.y=(Math.random()-0.5)*height; p.z=800; }
            }
            raf = requestAnimationFrame(draw);
          }

          document.addEventListener('visibilitychange', () => {
            if (document.hidden) { if (raf) cancelAnimationFrame(raf), raf = null; }
            else { if (!raf) raf = requestAnimationFrame(draw); }
          });

          window.addEventListener('resize', resize);
          resize(); raf = requestAnimationFrame(draw);
        })();

        function goHome(hash) {
          const base = "{{ url_for('home') }}";
          window.location.href = hash ? base + hash : base;
        }

        // PRESENCE_APPLY_LABELS_GLOBAL_V1: global helper to apply server-broadcast labels to presence DOM chips

        try {

          window.__applyPresenceLabels = window.__applyPresenceLabels || function() {

            try {

              const lm = window.__labelByPubkey || {};

              const entries = Object.entries(lm).filter(([pk, lbl]) => pk && lbl);

              if (!entries.length) return 0;


              const tails = entries.map(([pk, lbl]) => {

                const s = String(pk);

                return { t8: s.slice(-8), t6: s.slice(-6), lbl: String(lbl) };

              });


              let changed = 0;

              document.querySelectorAll('span,div,li,p,a,button').forEach((el) => {

                try {

                  if (!el || (el.children && el.children.length)) return;

                  const txt = (el.textContent || '').trim();

                  if (!txt) return;

                  if (!(txt.includes('…') || txt.includes('...'))) return;

                  if (txt.length > 32) return;


                  for (const x of tails) {

                    if ((x.t8 && txt.endsWith(x.t8)) || (x.t6 && txt.endsWith(x.t6))) {

                      el.textContent = x.lbl;

                      changed += 1;

                      break;

                    }

                  }

                } catch(e) {}

              });

              return changed;

            } catch(e) {}

            return 0;

          };


          // Observe future rerenders (React)

          if (!window.__presenceLabelObserver) {

            window.__presenceLabelObserver = new MutationObserver(() => {

              try {

                clearTimeout(window.__presenceLabelTO);

                window.__presenceLabelTO = setTimeout(() => {

                  try { window.__applyPresenceLabels && window.__applyPresenceLabels(); } catch(e) {}

                }, 50);

              } catch(e) {}

            });

            try {

              window.__presenceLabelObserver.observe(document.body, { childList:true, subtree:true, characterData:true });

            } catch(e) {}

          }

        } catch(e) {}


        function shortKey(pk) {
      // Prefer server-broadcast labels first (PIN guests, etc.)
      try {
        const lm = window.__labelByPubkey || {};
        const lbl = lm[pk];
        if (lbl) return String(lbl);
      } catch(e) {}

      // Current PIN guest label for self
      try {
        const my = (window.__myPubkey || '').trim();
        const gl = (window.__guestLabel || '').trim();
        if (gl && my && pk === my) return gl;
      } catch(e) {}

      if (!pk) return "";
      const s = String(pk);

      // Guests / short IDs -> just tail4
      if (s.startsWith("guest-") || s.length < 12) return "…" + s.slice(-4);

      // compressed pubkeys: show 02…ABCD / 03…ABCD
      if ((s.startsWith("02") || s.startsWith("03")) && s.length >= 10) return s.slice(0,2) + "…" + s.slice(-4);

      // default: just tail4
      return "…" + s.slice(-4);
    }


        /* PRESENCE_SUBKEY_V1: shorter key under user (avoid long pubkey line) */
        function subKey(pk) {
          // prefer label map (PIN guests show Guest-1234 to everyone)
          try {
            const lm = window.__labelByPubkey || {};
            const lbl = lm[pk];
            if (lbl) return String(lbl);
          } catch(e) {}

          if (!pk) return "";
          const x = String(pk);

          // guests / short ids: only last4
          if (x.startsWith("guest") || x.length < 20) return "…" + x.slice(-4);

          // real pubkeys: show 02/03 prefix + last4
          return x.slice(0,2) + "…" + x.slice(-4);
        }

    function displayName(pk) {
          // PRESENCE_DISPLAYNAME_LABELMAP_V1: prefer server-broadcast labels for ANY user (PIN guests, etc.)
          try {
            const lm = window.__labelByPubkey || {};
            const lbl = lm[pk];
            if (lbl) return lbl;
          } catch(e) {}

          if (!pk) return "anon";
          if (SPECIAL_NAMES && SPECIAL_NAMES[pk]) return SPECIAL_NAMES[pk];
          const last4 = pk.slice(-4);
          if (pk.startsWith("guest") || pk.length < 20) return "guest …" + last4;
          if (pk === myPubkey) return "you · …" + last4;
          return "…"+last4;
        }

        function mentionUser(pubkey) {
          const input = document.getElementById('chatInput');
          if (!input) return;
          const prefix = input.value && !input.value.endsWith(' ') ? ' ' : '';
          input.value = (input.value || '') + prefix + '@' + shortKey(pubkey) + ' ';
          input.focus();
        }

        function openExplorerFor(pubkey) {
          if (!pubkey) return;
          if (pubkey.startsWith('guest')) return;
          try { localStorage.setItem('hodlxxi_explorer_target', pubkey); } catch {}
          goHome('#explorer');
        }

        const messagesEl    = document.getElementById('messages');
        function scrollMessagesToBottom(){
          if (!messagesEl) return;
          messagesEl.scrollTop = messagesEl.scrollHeight;
        }
        const userListEl    = document.getElementById('userList');
        const onlineCountEl = document.getElementById('onlineCount');
        const statusEl      = document.getElementById('room-status');
        const inputEl       = document.getElementById('chatInput');

        // KEYBOARD_LIFT_JS_V1: track mobile keyboard height and lift composer
        (function(){
          try{
            const vv = window.visualViewport || null;
            function update(){
              const h = vv ? vv.height : window.innerHeight;
              const off = vv ? (vv.offsetTop || 0) : 0;
              const kb = Math.max(0, window.innerHeight - h - off);
    // KB_LIFT_DISABLED_V1:           document.documentElement.style.setProperty('--kb', kb + 'px');
            }

            if (vv){
              vv.addEventListener('resize', update);
              vv.addEventListener('scroll', update);
            }
            window.addEventListener('resize', update);

            const onFocus = () => {
    // KB_LIFT_DISABLED_V1:           document.body.classList.add('kb-open');
              update();
              setTimeout(update, 50);
              setTimeout(update, 250);
            };
            const onBlur = () => {
    // KB_LIFT_DISABLED_V1:           document.body.classList.remove('kb-open');
    // KB_LIFT_DISABLED_V1:           document.documentElement.style.setProperty('--kb', '0px');
            };

            try{ inputEl && inputEl.addEventListener('focus', onFocus); }catch(e){}
            try{ inputEl && inputEl.addEventListener('blur', onBlur); }catch(e){}

            update();
          }catch(e){}
        })();


        const sendBtn       = document.getElementById('sendBtn');

        // MOBILE_KEYBOARD_FIX_V2: keep composer visible + chat usable on iOS/Android keyboards
        (function(){
          // KB_LIFT_DISABLED_V2: rollback to old behavior
          return;

          function setAppHeight(){
            try{
              const h = (window.visualViewport && window.visualViewport.height) ? window.visualViewport.height : window.innerHeight;
              document.documentElement.style.setProperty('--app-height', h + 'px');
            }catch(e){}
          }
          setAppHeight();
          window.addEventListener('resize', setAppHeight);
          if (window.visualViewport){
            window.visualViewport.addEventListener('resize', () => {
              setAppHeight();
              try { scrollMessagesToBottom(); } catch(e) {}
            });
          }
          try{
            inputEl?.addEventListener('focus', () => {
              setTimeout(() => {
                try { inputEl.scrollIntoView({ block:'end', behavior:'smooth' }); } catch(e){}
                try { scrollMessagesToBottom(); } catch(e){}
              }, 80);
            });
          }catch(e){}
        })();

        function setStatus(text) { if (statusEl) statusEl.textContent = text; }
        function setOnlineCount(n) { if (onlineCountEl) onlineCountEl.textContent = n; }

        // 45s prune (UI)
        const EXPIRY_SECONDS = 45;
        setInterval(() => {
          if (!messagesEl) return;
          const now = Date.now() / 1000;
          messagesEl.querySelectorAll('.message').forEach(li => {
            const ts = parseFloat(li.dataset.ts || "0");
            if (ts && (now - ts) > EXPIRY_SECONDS) li.remove();
          });
        }, 5000);

        function renderMessage(msg) {
          if (!messagesEl || !msg) return;
          const li = document.createElement('li');
          li.className = 'message';

          const fromPk = msg.pubkey || msg.sender_pubkey || '';
          if (fromPk && myPubkey && fromPk === myPubkey) li.classList.add('me');

          // MSG_SENDER_SHORT_V1: show only 02/03…LAST4 (or label) in message header
          let senderLabel = '';
          try{
            const lm = window.__labelByPubkey || {};
            senderLabel = String(msg.label || msg.sender || lm[fromPk] || '').trim();
          }catch(e){ senderLabel = ''; }

          const shortSender = senderLabel ? senderLabel : subKey(fromPk);

          const rawTs = msg.ts || msg.timestamp || msg.created_at || (Date.now() / 1000);
          const timeStr = new Date(rawTs * 1000).toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' });

          li.dataset.ts = String(rawTs);
          li.innerHTML = `
            <div class="message-meta">
              <div class="message-sender">${shortSender.replace(/</g,'&lt;')}</div>
              <div class="message-timestamp">${timeStr}</div>
            </div>
            <div class="message-text">${(msg.text || msg.body || '').replace(/</g,'&lt;')}</div>
          `;

          messagesEl.appendChild(li);
          requestAnimationFrame(() => { scrollMessagesToBottom(); });
        }

        function extractPubkeys(payload) {
          if (!payload) return [];
          const arr = Array.isArray(payload) ? payload : (payload.users || payload.online_users || []);
          return arr.map(u => typeof u === 'string' ? u : (u && (u.pubkey || u.id)) || null).filter(Boolean);
        }

        function renderUserList(users) {
          if (!userListEl || !Array.isArray(users)) return;
          userListEl.innerHTML = '';

          users.forEach(pk => {
            /* PRESENCE_APPLY_ROLECLASS_V1 */
            let role = "limited";
            try{
              const rm = window.__roleByPubkey || {};
              role = (rm[pk] || role);
            }catch(e){}
            // fallback inference if not provided
            try{
              if (!role || role === "limited"){
                if (pk && String(pk).startswith("guest-")) role = "random";
              }
            }catch(e){}

            const li = document.createElement('li');
            li.className = 'user-item';
            try{ li.classList.add('role-' + String(role)); }catch(e){}
            li.dataset.pubkey = pk;

            const isMe = myPubkey && pk === myPubkey;
            const isGuest = pk.length < 20 || pk.startsWith('guest');

            li.innerHTML = `
              <div class="user-left">
                <span class="user-dot"></span>
                <div style="min-width:0;">
                  <div class="user-name">${displayName(pk).replace(/</g,'&lt;')}</div>
                  ${isMe ? `<div class="user-tag">you</div>` : `<div class="user-sub">${subKey(pk)}</div><!-- PRESENCE_USER_SUB_USE_SUBKEY_V1 -->`}
                </div>
              </div>
              <button class="user-btn" type="button">@</button>
            `;

            li.querySelector('.user-btn')?.addEventListener('click', (ev) => {
              ev.stopPropagation();
              mentionUser(pk);
            });

            // Long-press to call (direct room)
            let pressTimer = null;
            let didLongPress = false;

            const startPress = () => {
              if (pk === myPubkey) return;
              if (pressTimer) return;
              pressTimer = setTimeout(() => {
                pressTimer = null;
                didLongPress = true;
                startCall(pk);
                setTimeout(() => { didLongPress = false; }, 120);
              }, 700);
            };
            const cancelPress = () => { if (pressTimer) { clearTimeout(pressTimer); pressTimer = null; } };

            li.addEventListener('mousedown', startPress);
            li.addEventListener('touchstart', startPress, { passive:true });
            ['mouseup','mouseleave','touchend','touchcancel'].forEach(ev => li.addEventListener(ev, cancelPress));

            // Tap (non-guest) opens Explorer
            if (!isGuest) {
              li.addEventListener('click', () => {
                if (didLongPress) return;
                openExplorerFor(pk);
              });
            }

            userListEl.appendChild(li);
          });

          setOnlineCount(users.length);
        }

        // Socket.IO
        const socket = io();

        socket.on('connect', () => setStatus('Connected'));
        socket.on('disconnect', () => setStatus('Disconnected'));

        socket.on('chat:history', (payload) => {
          const msgs = payload?.messages || payload;
          if (!Array.isArray(msgs)) return;
          messagesEl.innerHTML = '';
          msgs.forEach(renderMessage);
          requestAnimationFrame(() => { scrollMessagesToBottom(); });
          setStatus('History loaded');
        });

        socket.on('chat:message', renderMessage);

        // APP_PRESENCE_ONLINE_CACHE_V1: cache latest payload so we can re-render once guest_label arrives

        // APP_PRESENCE_GUEST_LABEL_INIT_V1: fetch guest_label for current session so presence UI can show Guest-HOST
    ;(function(){

          if (window.__guestLabelInit) return; window.__guestLabelInit = true;

          try {

            const ds = (document.body && document.body.dataset) ? document.body.dataset : {};

            window.__myPubkey = window.__myPubkey || ds.myPubkey || ds.loggedInPubkey || ds.loggedIn || '';

            window.__guestLabel = window.__guestLabel || ds.guestLabel || '';

          } catch(e) {}

          try {

            fetch('/api/debug/session', { credentials: 'same-origin' })

              .then(r => r.json())

              .then(d => {

                if (!d) return;

                window.__myPubkey = d.pubkey || window.__myPubkey || '';

                window.__guestLabel = d.guest_label || d.guestLabel || window.__guestLabel || '';
            // APP_PRESENCE_DOM_APPLY_GUESTLABEL_V1: persist to dataset + update rendered presence chips immediately
            try {
              if (document && document.body && document.body.dataset) {
                document.body.dataset.guestLabel = window.__guestLabel || '';
              // APP_PRESENCE_FORCE_GUESTLABEL_DOMFIX_V2: best-effort DOM fix for presence chips that still show truncated pubkey like …59cb
              try {
                window.__applyGuestLabelPresence = window.__applyGuestLabelPresence || function() {
                  try {
                    const my = (window.__myPubkey || '').trim();
                    const gl = (window.__guestLabel || '').trim();
                    if (!my || !gl) return;

                    const tail8 = my.slice(-8);
                    const tail6 = my.slice(-6);
                    const tail4 = my.slice(-4);

                    // Find likely presence/userlist containers
                    const roots = [];
                    document.querySelectorAll('[id],[class]').forEach((el) => {
                      const s = ((el.id || '') + ' ' + (el.className || '')).toLowerCase();
                      if (s.includes('online') || s.includes('presence') || s.includes('userlist') || s.includes('user-list') || s.includes('users')) {
                        roots.push(el);
                      }
                    });
                    if (!roots.length) roots.push(document.body);

                    // Only touch leaf nodes that contain ellipsis and end with our tail
                    const tryTails = (tails) => {
                      let changed = 0;
                      roots.slice(0, 10).forEach((root) => {
                        root.querySelectorAll('*').forEach((el) => {
                          try {
                            if (!el || (el.children && el.children.length)) return;
                            const txt = (el.textContent || '').trim();
                            if (!txt) return;
                            if (!(txt.includes('…') || txt.includes('...'))) return;
                            if (tails.some(t => t && txt.endsWith(t))) {
                              el.textContent = gl;
                              changed += 1;
                            }
                          } catch(e) {}
                        });
                      });
                      return changed;
                    };

                    // Prefer longer tails first (less collision), then fallback to tail4
                    if (tryTails([tail8, tail6]) === 0) {
                      // Only apply tail4 replacement if the text is short-ish (chip), to avoid accidental matches
                      roots.slice(0, 10).forEach((root) => {
                        root.querySelectorAll('*').forEach((el) => {
                          try {
                            if (!el || (el.children && el.children.length)) return;
                            const txt = (el.textContent || '').trim();
                            if (!txt) return;
                            if (txt.length > 20) return;
                            if (!(txt.includes('…') || txt.includes('...'))) return;
                            if (tail4 && txt.endsWith(tail4)) el.textContent = gl;
                          } catch(e) {}
                        });
                      });
                    }
                  } catch(e) {}
                };
              } catch(e) {}

              // Run now + again shortly (covers “render happens after fetch” timing)
              try { window.__applyGuestLabelPresence && window.__applyGuestLabelPresence(); } catch(e) {}
              try { setTimeout(() => window.__applyGuestLabelPresence && window.__applyGuestLabelPresence(), 250); } catch(e) {}
              try { setTimeout(() => window.__applyGuestLabelPresence && window.__applyGuestLabelPresence(), 1000); } catch(e) {}

              }
            } catch(e) {}
            try {
              const my = window.__myPubkey || '';
              const gl = window.__guestLabel || '';
              if (my && gl) {
                document.querySelectorAll('[data-pubkey]').forEach((el) => {
                  try {
                    if (el && el.dataset && el.dataset.pubkey === my) {
                      el.textContent = gl;
                    }
                  } catch(e) {}
                });
              }
            } catch(e) {}


                // Re-render online list if we already drew it

                if (window.__guestLabel && window.__lastOnlinePayload && typeof renderUserList === 'function' && typeof extractPubkeys === 'function') {

                  try { renderUserList(extractPubkeys(window.__lastOnlinePayload)); } catch(e) {}

                }

              })

              .catch(() => {});

          } catch(e) {}

        })();



        // PRESENCE_ROLE_FROM_SCRATCH_V1: map roles -> apply role-* classes + keep updated
        window.__presenceRoles = window.__presenceRoles || {};

        window.__presenceApplyRoles = function(){
          try{
            const map = window.__presenceRoles || {};
            document.querySelectorAll('.user-item').forEach((el) => {
              const pk = (el.dataset.pubkey || el.dataset.pk || el.getAttribute('data-pubkey') || el.getAttribute('data-pk') || '').trim();
              if (!pk) return;

              const role = (el.dataset.role || map[pk] || '').trim();
              if (role) el.dataset.role = role;

              el.classList.remove('role-full','role-limited','role-pin','role-random');
              if (role) el.classList.add('role-' + role);
            });
          }catch(e){}
        };

        if (!window.__presenceRoleObserver) {
          window.__presenceRoleObserver = new MutationObserver(() => {
            try{ clearTimeout(window.__presenceRoleTO); }catch(e){}
            window.__presenceRoleTO = setTimeout(() => {
              try{ window.__presenceApplyRoles && window.__presenceApplyRoles(); }catch(e){}
            }, 50);
          });
          const ul = document.getElementById('userList') || document.querySelector('.users-list');
          if (ul) window.__presenceRoleObserver.observe(ul, { childList:true, subtree:true, attributes:true });
        }

    socket.on('online:list', (payload) => {
          // PRESENCE_ROLE_MAP_UPDATE_V1
          try{
            window.__presenceRoles = window.__presenceRoles || {};
            (payload || []).forEach((it) => {
              if (!it) return;
              const pk = String(it.pubkey || it.pk || '').trim();
              if (!pk) return;
              const role = String(it.role || it.access_level || '').trim();
              if (role) window.__presenceRoles[pk] = role;
            });
          }catch(e){}
          // PRESENCE_ROLEMAP_SOCKET_V1: capture role per pubkey from server payload
          try{
            const list = Array.isArray(payload) ? payload : (payload ? [payload] : []);
            window.__roleByPubkey = window.__roleByPubkey || {};
            list.forEach((x) => {
              try{
                if (x && typeof x === 'object' && x.pubkey && x.role){
                  window.__roleByPubkey[x.pubkey] = String(x.role);
                }
              }catch(e){}
            });
          }catch(e){}

          // PRESENCE_LABELMAP_SOCKET_V2: build label map from server payload so everyone renders Guest-* labels
          // PRESENCE_DOM_LABEL_APPLY_V1: apply label map to any presence chips that still show truncated pubkey like …59cb
          try {
            window.__applyPresenceLabels = window.__applyPresenceLabels || function() {
              try {
                const lm = window.__labelByPubkey || {};
                const entries = Object.entries(lm).filter(([pk, lbl]) => pk && lbl);
                if (!entries.length) return;

                // precompute tails
                const tails = entries.map(([pk, lbl]) => {
                  const s = String(pk);
                  return { t8: s.slice(-8), t6: s.slice(-6), lbl: String(lbl) };
                });

                // scan leaf nodes likely used as chips
                document.querySelectorAll('span,div,li,p,a,button').forEach((el) => {
                  try {
                    if (!el || (el.children && el.children.length)) return;
                    const txt = (el.textContent || '').trim();
                    if (!txt) return;
                    if (!(txt.includes('…') || txt.includes('...'))) return;
                    if (txt.length > 32) return; // avoid touching paragraphs

                    for (const x of tails) {
                      if ((x.t8 && txt.endsWith(x.t8)) || (x.t6 && txt.endsWith(x.t6))) {
                        el.textContent = x.lbl;
                        break;
                      }
                    }
                  } catch(e) {}
                });
              } catch(e) {}
            };

            // observe re-renders (React / DOM updates)
            if (!window.__presenceLabelObserver) {
              window.__presenceLabelObserver = new MutationObserver(() => {
                try {
                  clearTimeout(window.__presenceLabelTO);
                  window.__presenceLabelTO = setTimeout(() => {
                    try { window.__applyPresenceLabels && window.__applyPresenceLabels(); } catch(e) {}
                  }, 50);
                } catch(e) {}
              });
              try {
                window.__presenceLabelObserver.observe(document.body, { childList:true, subtree:true, characterData:true });
              } catch(e) {}
            }

            // run now and shortly after
            try { window.__applyPresenceLabels(); } catch(e) {}
            try { setTimeout(() => window.__applyPresenceLabels && window.__applyPresenceLabels(), 50); } catch(e) {}
            try { setTimeout(() => window.__applyPresenceLabels && window.__applyPresenceLabels(), 250); } catch(e) {}
          } catch(e) {}

          try {
            const list = Array.isArray(payload) ? payload : (payload ? [payload] : []);
            window.__labelByPubkey = window.__labelByPubkey || {};
            list.forEach((x) => {
              try {
                if (x && typeof x === 'object' && x.pubkey && x.label) {
                  window.__labelByPubkey[x.pubkey] = x.label;
                }
              } catch(e) {}
            });
          } catch(e) {}

          try { window.__labelByPubkey = window.__labelByPubkey || {}; (payload||[]).forEach((x)=>{ if(x && typeof x==='object' && x.pubkey && x.label){ window.__labelByPubkey[x.pubkey]=x.label; } }); } catch(e) {}


          try { window.__lastOnlinePayload = payload; } catch (e) {}

          renderUserList(extractPubkeys(payload));
          // PRESENCE_ROLE_APPLY_ON_ONLINE_LIST_V1
          try{ window.__presenceApplyRoles && window.__presenceApplyRoles(); }catch(e){}


          try { window.__applyGuestLabelPresence && window.__applyGuestLabelPresence(); } catch(e) {}
        });

        socket.on('user:list',   (payload) => renderUserList(extractPubkeys(payload)));

        socket.on('user:joined', (payload) => {
          // PRESENCE_ROLEMAP_JOIN_V1: capture role on join events
          try{
            if (payload && typeof payload === 'object' && payload.pubkey && payload.role){
              window.__roleByPubkey = window.__roleByPubkey || {};
              window.__roleByPubkey[payload.pubkey] = String(payload.role);
            }
          }catch(e){}

          // PRESENCE_LABELMAP_SOCKET_V2: also capture label on incremental join events
          try { window.__applyPresenceLabels && window.__applyPresenceLabels(); } catch(e) {}

          try {
            if (payload && typeof payload === 'object' && payload.pubkey && payload.label) {
              window.__labelByPubkey = window.__labelByPubkey || {};
              window.__labelByPubkey[payload.pubkey] = payload.label;
            }
          } catch(e) {}

          try { if(payload && payload.pubkey && payload.label){ window.__labelByPubkey = window.__labelByPubkey || {}; window.__labelByPubkey[payload.pubkey]=payload.label; } } catch(e) {}

          const [pk] = extractPubkeys([payload]);
          if (!pk || !userListEl) return;
          const existing = Array.from(userListEl.querySelectorAll('.user-item')).map(li => li.dataset.pubkey);
          if (existing.includes(pk)) return;
          renderUserList([...existing, pk]);
        });

        socket.on('user:left', (payload) => {
          const [pk] = extractPubkeys([payload]);
          if (!pk || !userListEl) return;
          userListEl.querySelector(`.user-item[data-pubkey="${pk}"]`)?.remove();
          setOnlineCount(userListEl.querySelectorAll('.user-item').length);
        });

        function sendMessage() {
          const text = (inputEl?.value || '').trim();
          if (!text) return;
          socket.emit('chat:send', { text });
          inputEl.value = '';
          inputEl.focus();
        }
        sendBtn?.addEventListener('click', sendMessage);
        inputEl?.addEventListener('keydown', (evt) => {
          if (evt.key === 'Enter' && !evt.shiftKey) { evt.preventDefault(); sendMessage(); }
        });

        // ================== GROUP CALL MANAGER (single implementation) ==================
        const GroupCallManager = (() => {
          let localStream = null;
          let peerConnections = {};
          let pendingIceCandidates = {};
          let remoteStreams = {};
          let currentRoomId = null;
          let iceServersCache = null;
          let isMuted = false;
          let isCameraOff = false;

          const panel = document.getElementById("groupCallPanel");
          const callStatusEl = document.getElementById("callStatus");
          const localVideoEl = document.getElementById("localVideo");
          const remoteWrap = document.getElementById("remoteVideosContainer");
          const muteBtn = document.getElementById("muteBtn");
          const cameraBtn = document.getElementById("cameraBtn");
          const hangupBtn = document.getElementById("hangupGroupBtn");
          const fsBtn = document.getElementById("fsBtn");


          function updateStatus(t){ if (callStatusEl) callStatusEl.textContent = t || "No active call"; }

          // CALL_FULLSCREEN_TOGGLE_V1: overlay fullscreen + best-effort native Fullscreen API
          function toggleCallFullscreen(forceOn=null){
            try{
              const wantOn = (forceOn===null) ? !document.body.classList.contains("call-full") : !!forceOn;
              document.body.classList.toggle("call-full", wantOn);

              try{
                if (fsBtn){
                  fsBtn.classList.toggle("active", wantOn);
                  fsBtn.innerHTML = wantOn ? "<span>⛶</span>Exit" : "<span>⛶</span>Full";
                }
              }catch(e){}

              // best-effort native fullscreen (desktop). overlay works even if this fails.
              try{
                if (wantOn){
                  const el = panel || document.documentElement;
                  if (el && el.requestFullscreen) el.requestFullscreen().catch(()=>{});
                }else{
                  if (document.fullscreenElement && document.exitFullscreen) document.exitFullscreen().catch(()=>{});
                }
              }catch(e){}
            }catch(e){}
          }
          function setUI(active){
            if (!panel) return;
            panel.classList.toggle("hidden", !active);
          }

          async function getIceServers() {
            if (iceServersCache) return iceServersCache;
            try {
              const resp = await fetch("/turn_credentials");
              iceServersCache = resp.ok ? await resp.json() : [];
            } catch { iceServersCache = []; }
            return iceServersCache;
          }

          async function ensureLocalStream() {
            if (localStream) return localStream;
            const stream = await navigator.mediaDevices.getUserMedia({
              audio: true,
              video: { width:{ideal:640}, height:{ideal:480} }
            });
            localStream = stream;
            if (localVideoEl) {
              localVideoEl.srcObject = stream;
              localVideoEl.muted = true;
              localVideoEl.play().catch(()=>{});
            }
            return stream;
          }

                // VIDEO_PIN_STATE_V2
          let pinnedPk = null;

          function applyPinClasses(){
            try{
              const tiles = document.querySelectorAll(".video-tile");
              tiles.forEach(t => {
                const id = t.getAttribute("id") || "";
                const isRemoteTile = id.startsWith("tile-");
                const isPinned = pinnedPk && (id === ("tile-" + pinnedPk));
                t.classList.toggle("pinned", !!isPinned);
                if (pinnedPk && isRemoteTile && !isPinned) t.classList.add("dim");
                else t.classList.remove("dim");
              });
            }catch(e){}
          }

          function togglePin(pk){
            pinnedPk = (pinnedPk === pk) ? null : pk;
            applyPinClasses();
          }

    function addRemoteTile(pk, stream){
            if (!remoteWrap) return;
            let tile = document.getElementById("tile-" + pk);
            if (!tile){
              tile = document.createElement("div");
              tile.className = "video-tile";
              tile.id = "tile-" + pk;

              const v = document.createElement("video");
              v.autoplay = true; v.playsinline = true;

              const label = document.createElement("div");
              label.className = "video-label";
              label.textContent = displayName(pk);

              tile.appendChild(v);
              tile.appendChild(label);
              remoteWrap.appendChild(tile);
              // VIDEO_PIN_CLICK_V2: click remote tile to pin/unpin
              try{
                tile.addEventListener("click", (ev) => {
                  ev.preventDefault();
                  ev.stopPropagation();
                  togglePin(pk);
                }, { passive: true });
              }catch(e){}

            }
            const vid = tile.querySelector("video");
            if (vid){
              vid.srcObject = stream;
              vid.play().catch(()=>{});
            }
          }

          function removeRemoteTile(pk){
            // VIDEO_PIN_UNPIN_V2
            try{ if (pinnedPk === pk) pinnedPk = null; }catch(e){}
            try{ applyPinClasses(); }catch(e){}

            document.getElementById("tile-" + pk)?.remove();
          }

          async function createPC(remotePk){
            const iceServers = await getIceServers();
            const pc = new RTCPeerConnection({ iceServers });

            pc.onicecandidate = (e) => {
              if (e.candidate && currentRoomId){
                socket.emit("rtc:signal", { room_id: currentRoomId, to: remotePk, type: "ice", payload: e.candidate });
              }
            };

            pc.ontrack = (e) => {
              let stream = (e.streams && e.streams[0]) ? e.streams[0] : null;
              if (!stream){
                remoteStreams[remotePk] = remoteStreams[remotePk] || new MediaStream();
                stream = remoteStreams[remotePk];
              }
              if (e.track && stream && !stream.getTracks().some(t => t.id === e.track.id)){
                stream.addTrack(e.track);
              }
              addRemoteTile(remotePk, stream);
            };

            pc.oniceconnectionstatechange = () => {
              if (["disconnected","failed","closed"].includes(pc.iceConnectionState)){
                closePC(remotePk);
              }
            };

            localStream?.getTracks().forEach(track => pc.addTrack(track, localStream));

            peerConnections[remotePk] = pc;
            // Flush ICE that arrived before the remote description/PC existed.
            const queued = pendingIceCandidates[remotePk] || [];
            if (queued.length){
              for (const c of queued){
                try{ await pc.addIceCandidate(new RTCIceCandidate(c)); }catch{}
              }
              delete pendingIceCandidates[remotePk];
            }
            return pc;
          }

          function closePC(remotePk){
            const pc = peerConnections[remotePk];
            if (pc){ try{ pc.close(); }catch{} delete peerConnections[remotePk]; }
            delete pendingIceCandidates[remotePk];
            delete remoteStreams[remotePk];
            removeRemoteTile(remotePk);
          }

          async function joinRoom(roomId){
            if (!myPubkey){ updateStatus("Please log in to join a call"); return; }
            if (currentRoomId) await leaveRoom();

            try{
              await ensureLocalStream();
              currentRoomId = roomId;
              setUI(true);
              updateStatus("Joining room…");
              socket.emit("rtc:join_room", { room_id: roomId });
            } catch (e){
              updateStatus("Camera/mic denied");
              await leaveRoom();
            }
          }

          async function leaveRoom(){
            if (currentRoomId) socket.emit("rtc:leave_room", { room_id: currentRoomId });

            Object.keys(peerConnections).forEach(closePC);
            peerConnections = {};
            pendingIceCandidates = {};
            remoteStreams = {};

            if (localStream){
              localStream.getTracks().forEach(t => t.stop());
              localStream = null;
              if (localVideoEl) localVideoEl.srcObject = null;
            }

            if (remoteWrap) remoteWrap.innerHTML = "";
            currentRoomId = null;
            isMuted = false;
            isCameraOff = false;
            muteBtn?.classList.remove("active");
            cameraBtn?.classList.remove("active");
            if (muteBtn) muteBtn.innerHTML = "<span>🔊</span>Mute";
            if (cameraBtn) cameraBtn.innerHTML = "<span>📷</span>Camera Off";
            try{ toggleCallFullscreen(false); }catch(e){}
            setUI(false);
            updateStatus("Not in a call");
          }

          async function handleRoomPeers(data){
            if (!data?.peers || !currentRoomId) return;
            updateStatus(`In room with ${data.peers.length} peer(s)`);

            for (const remotePk of data.peers){
              if (remotePk === myPubkey) continue;
              if (peerConnections[remotePk]) continue;
              try{
                const pc = await createPC(remotePk);
                const offer = await pc.createOffer();
                await pc.setLocalDescription(offer);
                socket.emit("rtc:signal", { room_id: currentRoomId, to: remotePk, type: "offer", payload: offer });
              } catch {}
            }
          }

          async function handleSignal(data){
            if (!data || !data.from || !currentRoomId) return;
            if (data.room_id && data.room_id !== currentRoomId) return;
            const remotePk = data.from;
            if (remotePk === myPubkey) return;

            try{
              if (data.type === "offer"){
                let pc = peerConnections[remotePk];
                if (!pc) pc = await createPC(remotePk);
                await pc.setRemoteDescription(new RTCSessionDescription(data.payload));
                const answer = await pc.createAnswer();
                await pc.setLocalDescription(answer);
                socket.emit("rtc:signal", { room_id: currentRoomId, to: remotePk, type: "answer", payload: answer });
              } else if (data.type === "answer"){
                const pc = peerConnections[remotePk];
                if (pc) await pc.setRemoteDescription(new RTCSessionDescription(data.payload));
              } else if (data.type === "ice"){
                const pc = peerConnections[remotePk];
                if (data.payload){
                  if (pc){
                    await pc.addIceCandidate(new RTCIceCandidate(data.payload));
                  } else {
                    pendingIceCandidates[remotePk] = pendingIceCandidates[remotePk] || [];
                    pendingIceCandidates[remotePk].push(data.payload);
                  }
                }
              }
            } catch {}
          }

          async function handlePeerJoined(data){
            if (!data?.pubkey || !currentRoomId) return;
            if (data.room_id && data.room_id !== currentRoomId) return;
            const remotePk = data.pubkey;
            if (remotePk === myPubkey || peerConnections[remotePk]) return;
            try{
              const pc = await createPC(remotePk);
              const offer = await pc.createOffer();
              await pc.setLocalDescription(offer);
              socket.emit("rtc:signal", { room_id: currentRoomId, to: remotePk, type: "offer", payload: offer });
            } catch {}
          }

          function toggleMute(){
            if (!localStream) return;
            isMuted = !isMuted;
            localStream.getAudioTracks().forEach(t => t.enabled = !isMuted);
            if (muteBtn){
              muteBtn.classList.toggle("active", isMuted);
              muteBtn.innerHTML = isMuted ? "<span>🔇</span>Unmute" : "<span>🔊</span>Mute";
            }
          }

          function toggleCamera(){
            if (!localStream) return;
            isCameraOff = !isCameraOff;
            localStream.getVideoTracks().forEach(t => t.enabled = !isCameraOff);
            if (cameraBtn){
              cameraBtn.classList.toggle("active", isCameraOff);
              cameraBtn.innerHTML = isCameraOff ? "<span>📹</span>Camera On" : "<span>📷</span>Camera Off";
            }
          }

          function init(){
            hangupBtn?.addEventListener("click", leaveRoom);
            muteBtn?.addEventListener("click", toggleMute);
            cameraBtn?.addEventListener("click", toggleCamera);
            fsBtn?.addEventListener("click", () => toggleCallFullscreen());

            socket.on("rtc:room_peers", handleRoomPeers);
            socket.on("rtc:signal", handleSignal);
            socket.on("rtc:peer_joined", handlePeerJoined);

            socket.on("rtc:peer_left", (d) => { if (d?.pubkey) closePC(d.pubkey); });

            // accept invites from either event name (backward compatibility)
            socket.on("rtc:invite", (d) => { if (d?.room_id) joinRoom(d.room_id); });
            socket.on("rtc:call_invite", (d) => { if (d?.room_id) joinRoom(d.room_id); });

            socket.on("rtc:error", (d) => updateStatus(d?.error || "RTC error"));
          }

          return { init, joinRoom, leaveRoom };
        })();

        GroupCallManager.init();

        // direct call from long-press
        async function startCall(targetPubkey){
          if (!targetPubkey || !myPubkey) return;
          const roomId = "direct-" + [myPubkey, targetPubkey].sort().join("-");
          GroupCallManager.joinRoom(roomId);

          // invite the other side (supports either handler server-side)
          socket.emit("rtc:invite", { to: targetPubkey, room_id: roomId, from_name: shortKey(myPubkey) });
          socket.emit("rtc:call_invite", { to: targetPubkey, room_id: roomId, from_name: shortKey(myPubkey) });
        }

        // group call picker (max 3 others)
        function startGroupCall(){
          const onlineUsers = Array.from(document.querySelectorAll('.user-item'))
            .map(li => li.dataset.pubkey)
            .filter(pk => pk && pk !== myPubkey);

          if (onlineUsers.length === 0){ alert("No other users online"); return; }

          const popup = document.createElement('div');
          popup.style.cssText =
            'position:fixed;inset:0;display:flex;align-items:center;justify-content:center;' +
            'background:rgba(0,0,0,.75);z-index:10000;padding:16px;';
          popup.innerHTML =
            '<div style="max-width:420px;width:100%;background:rgba(8,12,10,.92);border:1px solid rgba(0,255,136,.35);' +
            'box-shadow:0 0 30px rgba(0,255,136,.18);border-radius:14px;padding:16px;">' +
            '<div style="font-family:var(--mono);color:#00ff88;margin-bottom:10px;">Select users (max 3)</div>' +
            '<div id="userCheckboxes" style="max-height:260px;overflow:auto;margin-bottom:12px;"></div>' +
            '<div style="display:flex;gap:10px;justify-content:flex-end;">' +
            '<button id="cancelCallBtn" style="padding:8px 12px;border-radius:10px;border:1px solid rgba(255,255,255,.12);background:rgba(0,0,0,.25);color:#e6f1ef;cursor:pointer;">Cancel</button>' +
            '<button id="startCallBtn" style="padding:8px 12px;border-radius:10px;border:1px solid rgba(0,255,136,.35);background:rgba(0,255,136,.12);color:#00ff88;cursor:pointer;">Start</button>' +
            '</div></div>';
          document.body.appendChild(popup);

          const box = popup.querySelector('#userCheckboxes');
          onlineUsers.forEach(pk => {
            const row = document.createElement('label');
            row.style.cssText = 'display:flex;align-items:center;gap:10px;color:#e6f1ef;margin:8px 0;cursor:pointer;font-family:var(--mono);font-size:12px;';
            row.innerHTML = `<input type="checkbox" value="${pk}" /> <span>${displayName(pk)}</span>`;
            box.appendChild(row);
          });

          popup.querySelector('#cancelCallBtn').onclick = () => popup.remove();
          popup.querySelector('#startCallBtn').onclick = () => {
            const selected = Array.from(popup.querySelectorAll('input[type=checkbox]:checked')).map(cb => cb.value);
            if (selected.length === 0) { alert('Select at least one'); return; }
            if (selected.length > 3) { alert('Max 3 others (4 total)'); return; }

            const roomId = 'room-' + Math.random().toString(36).slice(2, 9);
            GroupCallManager.joinRoom(roomId);

            selected.forEach(pk => {
              socket.emit("rtc:invite", { to: pk, room_id: roomId, from_name: shortKey(myPubkey) });
              socket.emit("rtc:call_invite", { to: pk, room_id: roomId, from_name: shortKey(myPubkey) });
            });

            popup.remove();
          };
        }
      </script>
    </body>
    </html>


        """
        return render_template_string_func(
            chat_html,
            history=chat_history,
            my_pubkey=my_pubkey,
            online_users=online_users_list,
            online_count=len(online_users_list),
            special_names=special_names,
            force_relay=force_relay,
            access_level=session.get("access_level", "limited"),
        )

    _BROWSER_ROUTE_HANDLERS["chat"] = chat

    @app.route("/logout")
    def logout():
        return perform_browser_logout()

    _BROWSER_ROUTE_HANDLERS["logout"] = logout

    @app.route("/", methods=["GET"])
    def root_redirect():
        """Public front door:
        - logged-in users -> /home
        - everyone else   -> agent-first homepage
        """
        from flask import session, redirect, url_for, render_template

        try:
            if session.get("logged_in_pubkey"):
                return redirect(url_for("ui.legacy_home_route"))
        except Exception:
            pass

        return render_template(
            "home_agent.html",
            agent_name="HODLXXI / UBID",
            tagline="Cryptographic identity, payment, and trust infrastructure for agents.",
            endpoints=[
                ("/agent/capabilities", "Supported jobs and pricing"),
                ("/agent/request", "Submit paid agent jobs"),
                ("/agent/reputation", "Public reputation surface"),
                ("/agent/attestations", "Public attestation chain"),
                ("/agent/chain/health", "Chain health surface"),
                ("/agent/marketplace/listing", "Marketplace-facing listing"),
                ("/screensaver", "Human / narrative interface"),
                ("/.well-known/openid-configuration", "OpenID discovery surface"),
            ],
            capabilities=[
                ("ping", "Lightweight liveness / protocol test"),
                ("verify_signature", "Verify secp256k1 signed payloads"),
                ("covenant_decode", "Decode covenant and script-related requests"),
            ],
            trust_features=[
                "Payment required before work",
                "Signed receipts",
                "Public attestations",
                "Public reputation surface",
                "Chain health visibility",
                "Bitcoin-native identity orientation",
            ],
        )

    _BROWSER_ROUTE_HANDLERS["root_redirect"] = root_redirect

    @app.route("/playground", methods=["GET"])
    def playground():
        # Public demo page
        from flask import render_template

        return render_template("playground.html")

    _BROWSER_ROUTE_HANDLERS["playground"] = playground


def register_browser_route_handlers(
    *,
    generate_challenge,
    get_rpc_connection,
    logger,
    render_template_string_func,
    special_names,
    force_relay,
    chat_history,
    online_users,
    purge_old_messages,
):
    """
    Register browser route handlers only (no Flask route registration).

    This keeps browser helper ownership explicit for factory-first runtime boot
    while avoiding import-time route side effects.
    """
    register_browser_routes(
        _NoopRouteRegistrar(),
        generate_challenge=generate_challenge,
        get_rpc_connection=get_rpc_connection,
        logger=logger,
        render_template_string_func=render_template_string_func,
        special_names=special_names,
        force_relay=force_relay,
        chat_history=chat_history,
        online_users=online_users,
        purge_old_messages=purge_old_messages,
    )
