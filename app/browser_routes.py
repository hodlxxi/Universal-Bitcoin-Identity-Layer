import time
from flask import redirect, render_template, render_template_string, session, url_for

_BROWSER_ROUTE_HANDLERS = {}


def get_browser_route_handler(name):
    return _BROWSER_ROUTE_HANDLERS.get(name)


def register_browser_routes(app, *, generate_challenge, get_rpc_connection, logger):
    """Register minimal browser entry routes."""

    @app.route("/login", methods=["GET"])
    def login():
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
    _BROWSER_ROUTE_HANDLERS["login"] = login
    
    

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))
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


    @app.route("/onboard", methods=["GET"], endpoint="onboard_alias")
    def onboard_alias():
        return redirect("/home#onboard")
    _BROWSER_ROUTE_HANDLERS["onboard_alias"] = onboard_alias
    
