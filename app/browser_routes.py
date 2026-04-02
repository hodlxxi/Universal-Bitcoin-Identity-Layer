import time
from flask import redirect, render_template, render_template_string, request, session, url_for

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
    
    

    @app.route("/home", methods=["GET"], endpoint="home")  # 👈 alias keeps url_for('home') working
    def home_page():
        access_level = session.get("access_level", "limited")
        initial_pubkey = request.args.get("pubkey", "")
    
        html = r"""
    
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>HODLXXI — Covenant Explorer & Onboard</title>
        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
        <meta name="apple-mobile-web-app-capable" content="yes">
        <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
        <meta name="theme-color" content="#00ff88">
    
        <!-- QR library for scanning -->
        <script src="https://unpkg.com/jsqr/dist/jsQR.js"></script>
    
        <style>
            .hidden { display: none !important; }
    
    :root{
      --bg: #070b0f;
      --panel: rgba(12, 16, 22, 0.78);
      --fg: #e7fff4;
      --muted: rgba(231,255,244,.72);
      --accent: #00ff88;
      --accent2: #3b82f6;
      --danger: #ff3b30;
      --warn: #f59e0b;
      --glass: rgba(10, 14, 20, 0.55);
      --glass2: rgba(10, 14, 20, 0.25);
      --border: rgba(0, 255, 136, 0.18);
      --border2: rgba(59, 130, 246, 0.22);
      --shadow: 0 10px 40px rgba(0,0,0,.55);
      --shadow2: 0 0 24px rgba(0,255,136,.16);
      --radius: 16px;
      --radius2: 12px;
      --pad: 16px;
      --touch: 44px;
    }
    
    *{ box-sizing:border-box; -webkit-tap-highlight-color: transparent; }
    html,body{ height:100%; }
    body{
      margin:0;
      font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, "Apple Color Emoji","Segoe UI Emoji";
      color: var(--fg);
      background: radial-gradient(900px 450px at 50% 0%, rgba(0,255,136,.14), rgba(0,0,0,0) 55%),
                  radial-gradient(700px 420px at 70% 12%, rgba(59,130,246,.10), rgba(0,0,0,0) 60%),
                  #03060a;
      overflow-x:hidden;
    }
    
    /* Matrix canvas behind everything */
    #matrix-bg{
      position: fixed;
      inset: 0;
      z-index: 0;
      pointer-events:none;
    }
    body > *:not(#matrix-bg){ position:relative; z-index:1; }
    
    .container{
      max-width: 1100px;
      margin: 0 auto;
      padding: 4.25rem 1rem 2rem;
    }
    
    .header{
      text-align:center;
      margin-bottom: 1rem;
    }
    
    .app-title{
      margin: 0 0 .5rem;
      font-size: clamp(1.55rem, 5.5vw, 2.25rem);
      letter-spacing: .18em;
      text-transform: uppercase;
      color: var(--accent);
      text-shadow: 0 0 18px rgba(0,255,136,.35);
    }
    
    .home-link{
      color: var(--accent);
      text-decoration:none;
    }
    .home-link:hover, .home-link:focus{
      text-decoration:underline;
      outline:none;
      text-shadow: 0 0 26px rgba(0,255,136,.65);
    }
    
    .manifesto-panel{
      margin-top: .75rem;
      padding: 1rem 1rem;
      border-radius: var(--radius);
      background: linear-gradient(180deg, rgba(12,16,22,.82), rgba(12,16,22,.62));
      border: 1px solid var(--border);
      box-shadow: var(--shadow2);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
    }
    
    .manifesto-text{
      text-align:left;
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono","Courier New", monospace;
      font-size: .78rem;
      line-height: 1.65;
    }
    .manifesto-text a{
      color: var(--muted);
      text-decoration:none;
    }
    .manifesto-text a:hover{ color: var(--fg); text-decoration: underline; }
    
    .manifesto-actions{ margin-top: .95rem; }
    .manifesto-actions-inner{
      display:inline-flex;
      gap: 10px;
      flex-wrap:wrap;
      align-items:center;
      justify-content:center;
    }
    
    .btn-icon{
      min-height: 34px;
      padding: .38rem .9rem;
      border-radius: 999px;
      border: 1px solid rgba(231,255,244,.28);
      background: rgba(10,14,20,.55);
      color: var(--fg);
      cursor:pointer;
      transition: transform .15s ease, box-shadow .15s ease, border-color .15s ease, background .15s ease, color .15s ease;
      box-shadow: 0 6px 20px rgba(0,0,0,.35);
    }
    .btn-icon:hover, .btn-icon:active{
      transform: translateY(-1px);
      border-color: rgba(0,255,136,.35);
      box-shadow: 0 0 18px rgba(0,255,136,.18);
      background: rgba(0,255,136,.06);
      color: var(--accent);
    }
    .btn-icon.exit{
      border-color: rgba(255,59,48,.35);
      color: rgba(255,220,220,.92);
    }
    .btn-icon.exit:hover{
      background: rgba(255,59,48,.12);
      border-color: rgba(255,59,48,.6);
      color: #ffe5e5;
    }
    
    .main-grid{
      display:grid;
      grid-template-columns: 1fr;
      gap: 16px;
      margin-top: 1.25rem;
      max-width: 980px;
      margin-inline: auto;
    }
    
    .panel{
      border-radius: var(--radius);
      padding: var(--pad);
      background: var(--panel);
      border: 1px solid var(--border);
      box-shadow: var(--shadow);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      overflow:hidden;
    }
    .panel:hover{
      border-color: rgba(0,255,136,.28);
      box-shadow: 0 10px 46px rgba(0,0,0,.6), 0 0 22px rgba(0,255,136,.12);
    }
    
    .panel h2{
      margin: 0 0 1rem;
      text-align:center;
      color: var(--accent);
      letter-spacing: .08em;
      text-transform: uppercase;
      font-size: clamp(1rem, 4vw, 1.25rem);
    }
    
    /* Form */
    .form-group{ margin-bottom: 1rem; }
    .form-group label{
      display:block;
      margin-bottom: .5rem;
      color: var(--accent);
      font-weight: 700;
      font-size: .9rem;
    }
    
    input, textarea{
      width:100%;
      min-height: var(--touch);
      padding: .75rem .85rem;
      border-radius: 12px;
      border: 1px solid rgba(231,255,244,.14);
      background: rgba(0,0,0,.32);
      color: var(--fg);
      outline:none;
      transition: border-color .15s ease, box-shadow .15s ease, background .15s ease;
    }
    input:focus, textarea:focus{
      border-color: rgba(0,255,136,.55);
      box-shadow: 0 0 0 2px rgba(0,255,136,.22);
      background: rgba(0,0,0,.38);
    }
    
    textarea{
      resize: vertical;
      min-height: 120px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono","Courier New", monospace;
    }
    
    /* Buttons */
    .btn{
      width:100%;
      min-height: var(--touch);
      border: none;
      border-radius: 999px;
      padding: .85rem 1rem;
      font-weight: 800;
      letter-spacing: .06em;
      text-transform: uppercase;
      cursor:pointer;
      background: linear-gradient(90deg, rgba(0,255,136,1), rgba(0,255,136,.78));
      color: #00140a;
      transition: transform .15s ease, box-shadow .15s ease, filter .15s ease;
    }
    .btn:hover, .btn:active{
      transform: translateY(-1px);
      box-shadow: 0 0 22px rgba(0,255,136,.28);
      filter: brightness(1.03);
    }
    .btn.btn-secondary, .btn-secondary{
      background: rgba(0,0,0,.18);
      border: 1px solid rgba(0,255,136,.42);
      color: var(--accent);
    }
    .btn-secondary:hover, .btn-secondary:active{
      background: rgba(0,255,136,.07);
      color: var(--fg);
    }
    
    /* Summary pill */
    .balance-summary{
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap: 10px;
      flex-wrap:wrap;
      padding: .85rem 1rem;
      border-radius: 999px;
      border: 1px dashed rgba(0,255,136,.55);
      background: rgba(0,255,136,.04);
      margin: 1rem 0;
    }
    .balance-item{ flex:1; min-width: 150px; text-align:center; }
    .balance-label{
      display:block;
      font-size: .75rem;
      opacity:.85;
      letter-spacing:.12em;
      text-transform: uppercase;
    }
    .balance-value{
      margin-top: .25rem;
      font-weight: 900;
      font-size: clamp(1rem, 3vw, 1.15rem);
      word-break: break-word;
    }
    .balance-in{ color: var(--accent); }
    .balance-out{ color: var(--accent2); }
    
    /* Covenant cards */
    .contracts-container{ margin-top: 1rem; }
    .contract-box{
      background: rgba(0,0,0,.28);
      border: 1px solid rgba(231,255,244,.16);
      border-radius: var(--radius2);
      padding: .85rem .9rem;
      margin-bottom: 1rem;
      box-shadow: 0 8px 26px rgba(0,0,0,.35);
      overflow:hidden;
    }
    .contract-box.input-role{
      border-color: rgba(0,255,136,.55);
      box-shadow: 0 0 22px rgba(0,255,136,.14);
    }
    .contract-box.output-role{
      border-color: rgba(59,130,246,.55);
      box-shadow: 0 0 22px rgba(59,130,246,.14);
    }
    .contract-box pre{
      margin: .25rem 0;
      white-space: pre-wrap;
      word-break: break-word;
      font-size: clamp(.7rem, 2.4vw, .86rem);
    }
    
    .nostr-info{ font-size: .8rem; color: var(--muted); }
    
    /* QR modal */
    .body-locked{ height:100dvh; overflow:hidden; }
    .qr-modal{
      position:fixed;
      inset:0;
      display:none;
      align-items:center;
      justify-content:center;
      z-index: 99999;
      background: rgba(0,0,0,.94);
      padding: env(safe-area-inset-top) 1rem env(safe-area-inset-bottom);
      backdrop-filter: blur(2px);
      -webkit-backdrop-filter: blur(2px);
    }
    .qr-video{ width:100vw; height:100vh; object-fit: cover; }
    .qr-close{
      position:fixed;
      top: max(12px, env(safe-area-inset-top));
      right: max(12px, env(safe-area-inset-right));
      z-index: 100000;
      border-radius: 999px;
      padding: .42rem .85rem;
      background: rgba(10,14,20,.6);
      border: 1px solid rgba(231,255,244,.24);
      color: var(--fg);
      cursor:pointer;
    }
    
    /* RPC */
    .rpc-buttons{
      display:grid;
      grid-template-columns: repeat(auto-fit, minmax(160px,1fr));
      gap: 10px;
      margin-bottom: 1rem;
    }
    .rpc-response{
      background: rgba(0,0,0,.3);
      border: 1px solid rgba(59,130,246,.35);
      border-radius: 12px;
      padding: .9rem;
      white-space: pre-wrap;
      word-break: break-word;
      max-height: 420px;
      overflow:auto;
      font-size: clamp(.7rem, 2.4vw, .84rem);
    }
    
    /* QR grid */
    .qr-codes{
      display:grid;
      grid-template-columns: repeat(auto-fit, minmax(200px,1fr));
      gap: 16px;
      margin-top: 1rem;
      align-items:center;
    }
    .qr-codes img{
      image-rendering: pixelated;
      max-width: 360px;
      width: 2.5in;
      height: 2.5in;
      border-radius: 12px;
      border: 1px solid rgba(231,255,244,.18);
      box-shadow: 0 0 22px rgba(0,255,136,.18);
    }
    .qr-codes figcaption{
      margin-top: .5rem;
      color: var(--accent);
      font-weight: 700;
      font-size: clamp(.7rem, 2.4vw, .82rem);
      word-break: break-word;
      text-align:center;
    }
    
    /* Mobile */
    @media (max-width: 767px){
      .container{ padding: 3.5rem 1rem 1.5rem; }
      .balance-summary{ border-radius: var(--radius); }
      .rpc-buttons{ grid-template-columns: 1fr; }
      .qr-codes{ grid-template-columns: 1fr; }
    }
    
    /* Reduced motion */
    @media (prefers-reduced-motion: reduce){
      *{ animation:none !important; transition:none !important; }
      #matrix-bg{ display:none !important; }
    }
        </style></head>
    
    <body data-access-level="{{ access_level }}">
        <!-- Matrix canvas -->
        <canvas id="matrix-bg" aria-hidden="true"></canvas>
    
        <!-- QR Scan Modal -->
        <div id="qr-modal" class="qr-modal">
            <video id="qr-video" class="qr-video" autoplay playsinline></video>
            <button onclick="stopScan()" class="qr-close">✕ Close</button>
            <canvas id="qr-canvas" style="display:none;"></canvas>
        </div>
    
        <div class="container">
            <!-- Header & manifesto -->
            <div class="header">
                <h1 class="app-title">
                    <a class="home-link" href="{{ url_for('home') }}">HODLXXI</a>
                </h1>
    
                {% if not session.get('manifesto_hidden') %}
    <div class="manifesto-panel" id="manifestoPanel">
                    <p class="manifesto-text">
                        <a href="https://github.com/hodlxxi/Universal-Bitcoin-Identity-Layer.git" rel="noopener">
                            This is a Game Theory and Mathematics–driven Design Framework for decentralized financial support
                            networks, leveraging Bitcoin smart contracts and integrating Nostr for social trust. It fosters a system
                            where mutual care, financial incentives, and social responsibility are embedded in every
                            transaction—aiming to create financially stable and independent communities. Beyond technological
                            advancements, this framework envisions a reimagined form of human cooperation and economic interaction,
                            promoting transparency and equity. It merges technology with human values, challenging traditional
                            notions of trust and community in the digital age. It also raises philosophical questions about the role
                            of technology in enhancing human capabilities, governance, and social structures. Ultimately, success
                            depends on both technological feasibility and ethical foundations, advocating a balanced integration of
                            innovation and tradition to shape future societal evolution. This crypto-centric platform is built as a
                            robust, scalable model of decentralized trust by embedding financial cooperation directly in
                            cryptographic agreements. It uses a Bitcoin full node as its backbone, leveraging descriptor-based
                            wallets and script covenants to enforce long-term, trust-based contracts. The system eliminates
                            centralized intermediaries in favor of immutable, transparent blockchain agreements. Here, cooperation is
                            mathematically reinforced, transparency is the default, and power flows back to individuals. Built on
                            math, guided by ethics, designed for generations. Let’s make covenants great again!!!
                        </a>
                    </p>
                
          <!-- HIDE_MANIFESTO_V1: session-scoped hide button -->
          <div style="margin-top:12px; display:flex; justify-content:flex-end;">
            <button id="hideManifestoBtn" type="button"
              style="padding:10px 14px; border:1px solid #00ff66; background:rgba(0,0,0,0.45); color:#00ff66; border-radius:12px; cursor:pointer;">
              Hide
            </button>
          </div>
          <script>
          (function(){
            const btn = document.getElementById('hideManifestoBtn');
            if(!btn) return;
            btn.addEventListener('click', async () => {
              try{
                const r = await fetch('/api/ui/hide_manifesto', {
                  method:'POST',
                  credentials:'include',
                  headers:{'Content-Type':'application/json'},
                  body:'{}'
                });
                if (r.ok){
                  const panel = document.getElementById('manifestoPanel');
                  if(panel) panel.remove();
                }
              }catch(e){}
            });
          })();
          </script>
    </div>
    {% endif %}
    
                <div class="manifesto-actions">
                    <div class="manifesto-actions-inner">
                        <button id="btnExplorer" class="btn-icon">🔍 Explorer</button>
                        <button id="btnOnboard"  class="btn-icon">🔧 Onboard</button>
                        <button id="btnChat"     class="btn-icon">💬 Chat</button>
                        <button id="btnScreensaver" class="btn-icon">🖥️ Screensaver</button>
                        <button id="btnExit"     class="btn-icon exit">🚪 Exit</button>
                    </div>
                </div>
            </div>
    
            <!-- Main grid: home text panel -->
            <div class="main-grid">
                <div class="panel" id="homePanel">
                    <h2>Welcome to the Covenant Viewer</h2>
                    <p style="font-size:0.9rem;color:var(--muted);margin-top:0.2rem;text-align:center;">
                        Start with <strong>Explorer</strong> to see who is locked in covenants, or open
                        <strong>Converter &amp; Decoder</strong> to verify scripts and generate QR packs.
                    </p>
                </div>
            </div>
    
            <!-- Explorer Panel -->
            <div class="panel hidden" id="explorerPanel">
                <h2>🔍 Explorer</h2>
    
                <div class="form-group">
                    <label for="pubKey">Enter Hex or NOSTR Key</label>
                    <input
                        type="text"
                        id="pubKey"
                        placeholder="Compressed Pub/NOSTR key"
                        autocomplete="off"
                        autocorrect="off"
                        autocapitalize="off"
                        spellcheck="false"
                    />
                </div>
    
                <button class="btn" onclick="handleCovenants()">Who Is</button>
    
                <div class="balance-summary" id="balance-summary">
                    <div class="balance-item">
                        <span class="balance-label">Incoming</span>
                        <div class="balance-value balance-in" id="input-balance">$0</div>
                    </div>
                    <div class="balance-item">
                        <span class="balance-label">Outgoing</span>
                        <div class="balance-value balance-out" id="output-balance">$0</div>
                    </div>
                </div>
    
                <div id="loading" class="loading">
                    <p class="loading-text">Processing... Please wait...</p>
                </div>
    
                <div id="contracts-container" class="contracts-container"></div>
            </div>
    
            <!-- Onboard Panel -->
            <div class="panel hidden" id="onboardPanel">
                <h2>🔧 Converter &amp; Decoder</h2>
    
                <div class="form-group">
                    <label for="initialScript">Raw Script</label>
                    <textarea
                        id="initialScript"
                        placeholder="Enter your script…"
                        autocomplete="off"
                        autocorrect="off"
                        autocapitalize="off"
                        spellcheck="false"
                    ></textarea>
                </div>
    
                <div class="form-group">
                    <label for="newPubKey1">Public Key (Who you care about)</label>
                    <input
                        type="text"
                        id="newPubKey1"
                        placeholder="Enter public key"
                        autocomplete="off"
                        autocorrect="off"
                        autocapitalize="off"
                        spellcheck="false"
                    />
                </div>
    
                <div class="form-group">
                    <label for="newPubKey2">Public Key (Who cares about you)</label>
                    <input
                        type="text"
                        id="newPubKey2"
                        placeholder="Enter public key"
                        autocomplete="off"
                        autocorrect="off"
                        autocapitalize="off"
                        spellcheck="false"
                    />
                </div>
    
                <button class="btn" onclick="handleUpdateScript()">Verify Witness</button>
    
                <div class="form-group">
                    <label>New P2WSH Script:</label>
                    <div id="updatedScript" class="contract-box" contenteditable="true"></div>
                </div>
    
                <h3 style="color: var(--accent); margin: var(--spacing-unit) 0; text-align:center;">Decoded Results:</h3>
                <pre id="decodedWitness" class="rpc-response"></pre>
    
                <div id="qr-codes" class="qr-codes"></div>
            </div>
    
            {% if access_level == 'full' %}
            <!-- RPC Full Node Section -->
            <div class="panel rpc-section">
                <h2>⚡ RPC Node</h2>
    
                <!-- Import Descriptor Panel -->
                <div class="panel" style="margin-bottom: var(--spacing-unit);">
                    <h2>Import Covenant Descriptor</h2>
                    <div class="form-group">
                        <textarea id="descriptorInput" placeholder="Paste descriptor here raw(...)checksum"></textarea>
                    </div>
                    <button class="btn" onclick="handleImportDescriptor()">Import</button>
                    <div id="importResult" class="rpc-response" style="margin-top: var(--spacing-unit);"></div>
                </div>
    
                <!-- Set Labels Panel -->
                <div class="panel" style="margin-bottom: var(--spacing-unit);">
                    <h2>Set Checking Labels</h2>
                    <div class="form-group">
                        <input type="text" id="zpubInput" placeholder="Enter your zpub" />
                    </div>
                    <div class="form-group">
                        <input type="text" id="labelInput" placeholder="Enter label" />
                    </div>
                    <button class="btn" onclick="handleSetLabels()">Label</button>
                    <div id="setLabelsResult" class="rpc-response" style="margin-top: var(--spacing-unit);"></div>
                </div>
    
                <!-- RPC Commands -->
                <div class="rpc-buttons">
                    <button class="btn btn-secondary" onclick="callRPC('listreceivedbyaddress')">Received by Address</button>
                    <button class="btn btn-secondary" onclick="callRPC('listtransactions')">Transactions</button>
                    <button class="btn btn-secondary" onclick="callRPC('listdescriptors')">Descriptors</button>
                    <button class="btn btn-secondary" onclick="callRPC('listunspent')">Unspent</button>
                    <button class="btn btn-secondary" onclick="callRPC('listlabels')">Labels</button>
                    <button class="btn btn-secondary" onclick="callRPC('getwalletinfo')">Wallet Info</button>
                    <button class="btn btn-secondary" onclick="callRPC('rescanblockchain')">Rescan</button>
                    <button class="btn btn-secondary" onclick="callRPC('listaddressgroupings')">Groupings</button>
                    <button class="btn btn-secondary" onclick="callRPC('listreceivedbylabel')">Received by Label</button>
                    <button class="btn btn-secondary" onclick="exportDescriptors()">Export Descriptors</button>
                    <button class="btn btn-secondary" onclick="exportWallet()">Export Wallet</button>
                </div>
    
                <pre id="rpcResponse" class="rpc-response"></pre>
            </div>
            {% endif %}
        </div>
    
        <!-- JS: logic same as before, with small fixes & palette alignment -->
        <script>
            // global: cache most recent covenant hex
            window.lastScriptHex = window.lastScriptHex || null;
            const accessLevel = document.body.dataset.accessLevel || 'limited';
    
            // QR scanner
            let scanning = false;
            let currentStream = null;
    
            async function startScan(inputElem, onResult) {
                const secure = location.protocol === 'https:' || location.hostname === 'localhost';
                if (!secure || !navigator.mediaDevices?.getUserMedia) {
                    alert('Camera only works on HTTPS or localhost.');
                    return;
                }
    
                const modal  = document.getElementById('qr-modal');
                const video  = document.getElementById('qr-video');
                const canvas = document.getElementById('qr-canvas');
                const ctx    = canvas.getContext('2d');
    
                document.body.classList.add('body-locked');
                modal.style.display = 'flex';
                requestAnimationFrame(() => window.scrollTo(0,0));
    
                video.setAttribute('playsinline', 'true');
                video.muted = true;
    
                try {
                    currentStream = await navigator.mediaDevices.getUserMedia({
                        video: { facingMode: { ideal: 'environment' } },
                        audio: false
                    });
                } catch (e) {
                    modal.style.display = 'none';
                    document.body.classList.remove('body-locked');
                    alert('Camera blocked. Check HTTPS and iOS Settings → Safari → Camera.');
                    return;
                }
    
                video.srcObject = currentStream;
                await video.play().catch(()=>{});
                scanning = true;
    
                window.stopScan = function stopScan() {
                    scanning = false;
                    try { currentStream?.getTracks().forEach(t => t.stop()); } catch {}
                    currentStream = null;
                    video.srcObject = null;
                    modal.style.display = 'none';
                    document.body.classList.remove('body-locked');
                };
    
                (function tick() {
                    if (!scanning) return;
                    if (video.readyState >= video.HAVE_CURRENT_DATA) {
                        canvas.width  = video.videoWidth;
                        canvas.height = video.videoHeight;
                        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
                        try {
                            const img  = ctx.getImageData(0, 0, canvas.width, canvas.height);
                            const code = jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' });
                            if (code && code.data) {
                                stopScan();
                                inputElem.value = code.data;
                                if (typeof onResult === 'function') onResult();
                                return;
                            }
                        } catch {}
                    }
                    requestAnimationFrame(tick);
                })();
            }
    
            function handleCovenants() {
                const inp = document.getElementById('pubKey');
                if (!inp.value.trim()) startScan(inp, verifyAndListContracts);
                else verifyAndListContracts();
            }
    
            function handleUpdateScript() {
                const inp = document.getElementById('initialScript');
                if (!inp.value.trim()) startScan(inp, updateScript);
                else updateScript();
            }
    
            function handleImportDescriptor() {
                const inp = document.getElementById('descriptorInput');
                if (!inp || !inp.value.trim()) {
                    if (inp) startScan(inp, importDescriptor);
                    return;
                }
                importDescriptor();
            }
    
            function handleSetLabels() {
                const zpubInp  = document.getElementById('zpubInput');
                const labelInp = document.getElementById('labelInput');
    
                if (!zpubInp.value.trim()) {
                    startScan(zpubInp, setLabelsFromZpub);
                    return;
                }
                if (!labelInp.value.trim()) {
                    alert('Please enter a label for your zpub.');
                    labelInp.focus();
                    return;
                }
                setLabelsFromZpub();
            }
    
            const chatSound = new Audio('{{ url_for("static", filename="sounds/message.mp3") }}');
            chatSound.preload = 'auto';
            chatSound.playsInline = true;
    
            function callRPC(cmd, param) {
                let url = `/rpc/${cmd}`;
                if (param !== undefined && param !== '') {
                    url += `?p=${encodeURIComponent(param)}`;
                }
                const out = document.getElementById('rpcResponse');
                if (out) out.textContent = '⏳ sending…';
                fetch(url)
                    .then(r => r.json())
                    .then(json => {
                        if (out) out.textContent = JSON.stringify(json, null, 2);
                    })
                    .catch(e => {
                        if (out) out.textContent = 'Error: ' + e;
                    });
            }
    
            function showLoading() {
                document.getElementById('loading').style.display = 'block';
                document.getElementById('contracts-container').innerHTML = '';
            }
    
            function hideLoading() {
                document.getElementById('loading').style.display = 'none';
            }
    
            function verifyAndListContracts(clickedPubKey = null) {
                let pubKey = clickedPubKey || document.getElementById('pubKey').value.trim();
                if (!pubKey) {
                    alert('Please enter a public key');
                    return;
                }
    
                const isNpub    = pubKey.startsWith("npub") && pubKey.length >= 10;
                const isHexFull = /^[0-9a-fA-F]{66,130}$/.test(pubKey);
                const isHex32   = /^[0-9a-fA-F]{64}$/.test(pubKey);
    
                // If we got a bare 32-byte hex (no 02/03 prefix),
                // normalize to a compressed-style key with 0x02 prefix.
                if (!isNpub && !isHexFull && isHex32) {
                    pubKey = "02" + pubKey;
                }
    
                const isHexFinal = /^[0-9a-fA-F]{66,130}$/.test(pubKey);
                if (!isNpub && !isHexFinal) {
                    alert('Invalid public key format. Please enter a Nostr npub or hex public key.');
                    return;
                }
    
                showLoading();
                fetch(`/verify_pubkey_and_list?pubkey=${encodeURIComponent(pubKey)}`)
                    .then(r => r.json())
                    .then(data => {
                        hideLoading();
                        if (!data.valid) {
                            alert(data.error || "No descriptor found matching the public key.");
                            return;
                        }
    
                        const sorted = data.descriptors.slice().sort((a, b) => {
                            const aOnline = !!a.counterparty_online;
                            const bOnline = !!b.counterparty_online;
                            if (aOnline !== bOnline) return aOnline ? -1 : 1;
    
                            const totalA = (parseFloat(a.saving_balance_usd) || 0) + (parseFloat(a.checking_balance_usd) || 0);
                            const totalB = (parseFloat(b.saving_balance_usd) || 0) + (parseFloat(b.checking_balance_usd) || 0);
                            return totalB - totalA;
                        });
    
                        const container = document.getElementById('contracts-container');
                        container.innerHTML = '';
    
                        let inputTotal = 0;
                        let outputTotal = 0;
    
                        const entered   = pubKey.trim();
                        const isEnteredNpub = entered.startsWith('npub');
                        const enteredLC = entered.toLowerCase();
    
                        sorted.forEach(descriptor => {
                            const save  = parseFloat(descriptor.saving_balance_usd) || 0;
                            const check = parseFloat(descriptor.checking_balance_usd) || 0;
                            const total = save + check;
    
                            const ifHex  = descriptor.op_if_pub   ? descriptor.op_if_pub.toLowerCase()    : null;
                            const elHex  = descriptor.op_else_pub ? descriptor.op_else_pub.toLowerCase()  : null;
                            const ifNpub = descriptor.op_if_npub  || null;
                            const elNpub = descriptor.op_else_npub|| null;
    
                            let role = null;
                            if (isEnteredNpub) {
                                if (ifNpub && ifNpub === entered)        role = 'input';
                                else if (elNpub && elNpub === entered)   role = 'output';
                                else if (!ifNpub && !elNpub && descriptor.nostr_npub === entered) {
                                    role = 'input';
                                }
                            } else {
                                if (ifHex && ifHex === enteredLC)        role = 'input';
                                else if (elHex && elHex === enteredLC)   role = 'output';
                            }
    
                            if (role === 'input')  inputTotal  += total;
                            if (role === 'output') outputTotal += total;
    
                            const box = document.createElement('div');
                            box.className = 'contract-box';
                            if (role) box.classList.add(role + '-role');
    
                            let nostrSection = '';
                            if (descriptor.nostr_npub) {
                                if (accessLevel === "full") {
                                    nostrSection = `
                                      <div class="nostr-info" style="text-align:center;margin:0.5rem 0;">
                                        <strong>Nostr:</strong><br>
                                        <a href="https://advancednostrsearch.vercel.app/?npub=${descriptor.nostr_npub}"
                                           style="color:var(--neon-blue); text-decoration:none; display:inline-block; margin-top:0.25rem;">
                                           ${descriptor.nostr_npub_truncated}
                                        </a>
                                      </div>`;
                                } else {
                                    nostrSection = `
                                      <div class="nostr-info" style="text-align:center;margin:0.5rem 0;">
                                        <strong>Nostr:</strong><br>${descriptor.nostr_npub_truncated}
                                      </div>`;
                                }
                            }
    
                            const counterpartyOnline = descriptor.counterparty_online;
                            let counterpartyNote = '';
                            if (counterpartyOnline && descriptor.counterparty_pubkey) {
                                counterpartyNote = `
                                  <div style="text-align:center; color:lime; font-size:0.8rem; margin-top:0.25rem;">
                                    🟢 online
                                  </div>`;
                            }
    
                            const deeplink = (accessLevel === "full" && (descriptor.onboard_link || descriptor.raw_script))
                                ? (descriptor.onboard_link || `#onboard?raw=${encodeURIComponent(descriptor.raw_script)}&autoverify=1`)
                                : null;
    
                            const imgTag = descriptor.qr_code
                                ? `<img src="data:image/png;base64,${descriptor.qr_code}" alt="Address QR"
                                         style="max-width:180px;border:1px solid #111827;border-radius:8px;box-shadow:0 0 10px rgba(0,255,0,.15);" />`
                                : '';
    
                            const addrQR = descriptor.qr_code
                                ? `<div style="text-align:center;margin:.5rem 0;">
                                     ${
                                       deeplink
                                         ? `<a href="${deeplink}"
                                               class="qr-link"
                                               title="Open in Converter & Decoder"
                                               data-raw="${descriptor.raw_script || ''}"
                                               onclick="return jumpOnboard(this.dataset.raw)">${imgTag}</a>`
                                         : imgTag
                                     }
                                   </div>`
                                : '';
    
                            box.innerHTML = `
                                <pre><strong>!</strong> ${descriptor.desc || descriptor.raw}</pre>
                                <div style="text-align:center; margin:0.5rem 0;">
                                    <pre><strong>Address:</strong> ${descriptor.truncated_address}</pre>
                                </div>
                                <div style="text-align:center;"><strong>HEX</strong> ${descriptor.script_hex}</div>
                                ${addrQR}
                                ${counterpartyNote}
                                ${nostrSection}
                                <div style="text-align:center; margin-top:1rem;">
                                    <div style="display:inline-block;">
                                        <strong>Save:</strong> $${descriptor.saving_balance_usd}
                                        &nbsp;&nbsp;
                                        <strong>Check:</strong> $${descriptor.checking_balance_usd}
                                    </div>
                                </div>`;
    
                            container.appendChild(box);
                        });
    
    
                        // FIX_WHOIS_TOTALS_FROM_BACKEND_V1: prefer server totals (works for hex clicks + limited users)
                        try {
                            const inUsd  = parseFloat((data && (data.in_usd ?? data.incoming_usd)) ?? "");
                            const outUsd = parseFloat((data && (data.out_usd ?? data.outgoing_usd)) ?? "");
                            if (!Number.isNaN(inUsd) && !Number.isNaN(outUsd)) {
                                inputTotal = inUsd;
                                outputTotal = outUsd;
                            }
                        } catch (e) {}
                        document.getElementById('input-balance').innerText  = '$' + inputTotal.toFixed(2);
                        document.getElementById('output-balance').innerText = '$' + outputTotal.toFixed(2);
                    })
                    .catch(err => {
                        hideLoading();
                        console.error(err);
                        alert("Error verifying public key. Please try again.");
                    });
            }
    
            
            window.handlePubKeyClickRef = async function(ref) {
                try {
                    const r = await fetch(`/api/pubkey/resolve?ref=${encodeURIComponent(ref)}`, { credentials: "same-origin" });
                    const j = await r.json();
                    if (!r.ok || !j.pubkey) throw new Error(j.error || "resolve failed");
                    verifyAndListContracts(j.pubkey);
                } catch (e) {
                    console.error("resolve pubkey ref failed:", e);
                    alert("Link expired — refresh the page and try again.");
                }
            }
    
    window.handlePubKeyClick = function(pubKey) {
      // Back-compat: if we were passed a ref token, resolve it server-side
      if (!/^(02|03)[0-9a-fA-F]{64}$/.test(pubKey || "")) {
        return window.handlePubKeyClickRef ? window.handlePubKeyClickRef(pubKey) : null;
      }
      return verifyAndListContracts(pubKey);
    }
    
    
            function updateScript() {
                const tpl = document.getElementById('initialScript').value.trim();
    
                // Extract pubkeys from raw-script HEX robustly:
                //   0x21 <33-byte pubkey>  OR  0x41 <65-byte pubkey>
                // (works for single-sig, multisig, nested IFs, dual-ELSE, etc.)
                const baked = (() => {
                    const hex = (tpl || '').replace(/[^0-9A-Fa-f]/g, '');
                    const out = [];
                    const rePk = /(?:21([0-9A-Fa-f]{66})|41([0-9A-Fa-f]{130}))/g;
                    let m;
                    while ((m = rePk.exec(hex)) !== null) {
                        const pk = (m[1] || m[2] || '').toLowerCase();
                        if (pk && !out.includes(pk)) out.push(pk);
                    }
                    return out;
                })();
    
                // Inputs: keep your existing two fields, but they must be HEX pubkeys.
                let k1 = (document.getElementById('newPubKey1')?.value || '').trim().toLowerCase() || baked[0] || '';
                let k2 = (document.getElementById('newPubKey2')?.value || '').trim().toLowerCase() || baked[1] || '';
    
                function validHexPubkey(key) {
                    return /^[0-9a-f]{66}$/.test(key) || /^[0-9a-f]{130}$/.test(key);
                }
    
                // IMPORTANT: npub cannot be embedded into script HEX.
                if (k1 && !validHexPubkey(k1)) { alert("Invalid key 1. Use HEX pubkey (66/130 hex). npub cannot be inserted into raw script hex."); return; }
                if (k2 && !validHexPubkey(k2)) { alert("Invalid key 2. Use HEX pubkey (66/130 hex). npub cannot be inserted into raw script hex."); return; }
    
                // Replace globally so scripts where the same key appears twice (dual-ELSE) update correctly.
                function replaceAll(hay, oldKey, newKey) {
                    if (!oldKey || !newKey || oldKey === newKey) return hay;
                    return hay.split(oldKey).join(newKey);
                }
    
                let rawScript = (tpl || '').replace(/[^0-9A-Fa-f]/g, '');
                if (baked[0] && k1) rawScript = replaceAll(rawScript.toLowerCase(), baked[0], k1);
                if (baked[1] && k2) rawScript = replaceAll(rawScript.toLowerCase(), baked[1], k2);
    
                // Pretty display with highlights (also global)
                let displayScript = (tpl || '').replace(/</g,'&lt;').replace(/>/g,'&gt;');
                if (baked[0] && k1) displayScript = displayScript.split(baked[0]).join(`<span style="color:var(--neon-blue);">${k1}</span>`);
                if (baked[1] && k2) displayScript = displayScript.split(baked[1]).join(`<span style="color:var(--neon-green);">${k2}</span>`);
                document.getElementById('updatedScript').innerHTML = displayScript;
    
                fetch('/decode_raw_script', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                    body: JSON.stringify({
                        raw_script: rawScript,
                        label_hint: (document.getElementById('labelInput')?.value || '').trim() || null
                    })
                })
                .then(async (r) => {
                    const ct = r.headers.get('content-type') || '';
                    const text = await r.text();
                    return ct.includes('application/json') ? JSON.parse(text) : { error: text || `${r.status} ${r.statusText}` };
                })
                .then(d => {
                    const out = document.getElementById('decodedWitness');
                    out.textContent = d.error ? `Error: ${d.error}` : JSON.stringify(d.decoded, null, 2);
    
                    // ----- NEW: show branch metadata (dual-ELSE visibility) -----
                    let meta = document.getElementById('scriptMeta');
                    if (!meta) {
                        meta = document.createElement('div');
                        meta.id = 'scriptMeta';
                        meta.style.marginTop = '0.5rem';
                        meta.style.whiteSpace = 'pre-wrap';
                        meta.style.fontFamily = 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace';
                        meta.style.fontSize = '12px';
                        meta.style.opacity = '0.95';
                        const qrContainer0 = document.getElementById('qr-codes');
                        if (qrContainer0 && qrContainer0.parentNode) {
                            qrContainer0.parentNode.insertBefore(meta, qrContainer0);
                        }
                    }
    
                    if (d && !d.error) {
                        const lines = [];
                        if (d.op_if)  lines.push(`OP_IF key:  ${d.op_if}`);
                        if (d.op_else) lines.push(`OP_ELSE key: ${d.op_else}`);
                        if (d.else_early_lock != null) lines.push(`ELSE early: lock=${d.else_early_lock} pub=${d.else_early_pub || ''}`);
                        if (d.else_late_lock  != null) lines.push(`ELSE late:  lock=${d.else_late_lock} pub=${d.else_late_pub || ''}`);
    
                        if (Array.isArray(d.op_else_branches) && d.op_else_branches.length) {
                            lines.push("ELSE branches:");
                            for (const b of d.op_else_branches) {
                                lines.push(`  - lock=${b.lock} pub=${b.pubkey}`);
                            }
                        }
                        meta.textContent = lines.length ? lines.join("\n") : "";
                    } else {
                        meta.textContent = "";
                    }
                    // ----------------------------------------------------------
    
                    const qrContainer = document.getElementById('qr-codes');
                    qrContainer.innerHTML = '';
    
                    if (d && d.script_hex) window.lastScriptHex = d.script_hex;
    
                    if (!d.error && d.qr) {
                        function makeQR(label, b64) {
                            if (!b64) return '';
                            return `
                              <figure>
                                <img src="data:image/png;base64,${b64}" alt="${label} QR"/>
                                <figcaption>${label}</figcaption>
                              </figure>`;
                        }
    
                        qrContainer.innerHTML =
                            makeQR('Receiver Pubkey', d.qr.pubkey_if) +
                            makeQR('Giver Pubkey', d.qr.pubkey_else) +
                            makeQR('Raw Script (hex)', d.qr.raw_script_hex) +
                            makeQR('HODL Address', d.qr.segwit_address);
    
                        if (d.qr.first_unused_addr) {
                            qrContainer.innerHTML += makeQR('First Unused Address', d.qr.first_unused_addr);
                        } else {
                            const warning = d.warning || 'No unused address found. Label your zpub in "Set Checking Labels" to enable detection.';
                            qrContainer.innerHTML += `
                              <div style="text-align:center; color: var(--accent); margin-top: 0;">
                                <strong style="color: var(--red);">Warning:</strong> ${warning}
                              </div>`;
                        }
    
                        if (d.qr.full_descriptor) {
                            qrContainer.innerHTML += makeQR('Descriptor (checksummed)', d.qr.full_descriptor);
                        }
                    }
                })
                .catch(e => {
                    document.getElementById('decodedWitness').textContent = `Error: ${e}`;
                });
            }
    
            function jumpOnboard(rawHex) {
                try {
                    ['homePanel','explorerPanel','onboardPanel'].forEach(id => {
                        const el = document.getElementById(id);
                        if (!el) return;
                        el.classList.toggle('hidden', id !== 'onboardPanel');
                    });
    
                    const ta = document.getElementById('initialScript');
                    if (ta) ta.value = rawHex || '';
    
                    if (location.hash !== '#onboard') location.hash = 'onboard';
    
                    setTimeout(() => {
                        try {handleUpdateScript();} catch (e) { console.error(e); }
                    }, 0);
                } catch (e) {
                    console.error('jumpOnboard error:', e);
                }
                return false;
            }
    
            function importDescriptor() {
                const inputEl = document.getElementById("descriptorInput");
                if (!inputEl) return;
                const input = inputEl.value.trim();
                if (!input) { alert("Please enter a descriptor."); return; }
    
                fetch('/import_descriptor', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ descriptor: input })
                })
                .then(r => r.json())
                .then(async data => {
                    const out = document.getElementById("importResult");
                    if (data.script_hex) window.lastScriptHex = data.script_hex;
                    if (out) out.innerHTML = "Imported ✔️<br><small>script_hex: " + (data.script_hex || "n/a") + "</small>";
    
                    if (data.raw_hex) {
                        const res = await fetch('/decode_raw_script', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                            body: JSON.stringify({ raw_script: data.raw_hex })
                        }).then(r => r.json()).catch(()=>null);
    
                        if (res && res.qr) {
                            const qrContainer = document.getElementById('qr-codes');
                            const label = (t,b64) => (b64
                                ? `<figure><img src="data:image/png;base64,${b64}"><figcaption>${t}</figcaption></figure>`
                                : ""
                            );
                            qrContainer.innerHTML =
                                label('Receiver Pubkey', res.qr.pubkey_if) +
                                label('Giver Pubkey',    res.qr.pubkey_else) +
                                label('Raw Script (hex)',res.qr.raw_script_hex) +
                                label('HODL Address',    res.qr.segwit_address) +
                                (res.qr.first_unused_addr
                                    ? label('First Unused Address', res.qr.first_unused_addr)
                                    : `<div style="text-align:center;color:var(--accent)">
                                         <strong style="color:var(--red)">Warning:</strong> ${res.warning||'No unused address yet.'}
                                       </div>`);
                        }
                    }
                })
                .catch(err => {
                    const out = document.getElementById("importResult");
                    if (out) out.innerHTML = "Error: " + err;
                });
            }
    
            function setLabelsFromZpub() {
                const zpub  = document.getElementById("zpubInput")?.value.trim();
                const label = document.getElementById("labelInput")?.value.trim();
    
                if (!zpub) {
                    alert("zpub is required.");
                    return;
                }
    
                const body = { zpub };
                if (label) body.label = label;
                if (window.lastScriptHex) body.script_hex = window.lastScriptHex;
    
                fetch('/set_labels_from_zpub', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify(body)
                })
                .then(async (r) => {
                    const ct   = r.headers.get('content-type') || '';
                    const text = await r.text();
                    let data;
                    try {
                        data = ct.includes('application/json') ? JSON.parse(text) : { error: text };
                    } catch (e) {
                        data = { error: text || e.message };
                    }
                    if (!r.ok || data.error) {
                        throw new Error(data.error || `${r.status} ${r.statusText}`);
                    }
                    return data;
                })
                .then((data) => {
                    if (data.script_hex) window.lastScriptHex = data.script_hex;
    
                    let msg = "";
                    msg += `<div><strong>Script HEX:</strong> ${data.script_hex || '(unknown)'}</div>`;
                    if (data.descriptor) {
                        msg += "<strong>Imported Descriptor:</strong><br><pre>" + data.descriptor + "</pre><br>";
                    }
                    if (data.labeled_addresses) {
                        msg += "<strong>Labeled Addresses:</strong><ul style='padding-left:1em;'>";
                        data.labeled_addresses.forEach(entry => {
                            const obj  = (typeof entry === 'object') ? entry : { address: entry };
                            const idx  = (obj.index !== undefined) ? `[${obj.index}] ` : "";
                            const addr = obj.address || "";
                            const b64  = obj.qr || obj.qr_base64 || null;
                            const src  = b64 ? (b64.startsWith("data:") ? b64 : `data:image/png;base64,${b64}`) : null;
                            const lab  = obj.label ? `<br><small>${obj.label}</small>` : "";
                            msg += `<li>${idx}${addr}${lab}${
                              src ? `<br><img src="${src}" alt="QR for ${addr}" style="max-width:140px;border:1px solid #333;border-radius:6px;margin-top:4px;" />` : ""
                            }</li>`;
                        });
                        msg += "</ul>";
                    } else if (data.addresses) {
                        msg += "<strong>Addresses:</strong><ul style='padding-left:1em;'>";
                        data.addresses.forEach(addr => { msg += `<li>${addr}</li>`; });
                        msg += "</ul>";
                    }
                    if (!msg && data.success) msg = "Operation successful.";
                    const out = document.getElementById("setLabelsResult");
                    if (out) out.innerHTML = msg || "No specific results to display.";
                })
                .catch(err => {
                    const out = document.getElementById("setLabelsResult");
                    if (out) out.innerHTML = "Error: " + err.message;
                });
            }
    
            function exportDescriptors() {
                fetch('/export_descriptors')
                    .then(res => res.json())
                    .then(data => {
                        if (data.error) { alert(data.error); return; }
                        const txt  = data.descriptors.map(d => `"${d}"`).join(',');
                        const blob = new Blob([txt], { type: 'text/plain' });
                        const url  = URL.createObjectURL(blob);
                        const a    = document.createElement('a');
                        a.href = url; a.download = 'descriptors.txt';
                        document.body.appendChild(a); a.click(); a.remove();
                        URL.revokeObjectURL(url);
                    })
                    .catch(err => alert('Export failed: ' + err));
            }
    
            function exportWallet() {
                window.location.href = '/export_wallet';
            }
    
            // Initial pubkey from URL
            document.addEventListener('DOMContentLoaded', () => {
                const initialPk = "{{ initial_pubkey }}";
                if (initialPk) {
                    verifyAndListContracts(initialPk);
                }
            });
    
            // Login sound on entry from login page
    
        // === SOUND_HELPER_V2: autoplay-safe + keep-alive pool + queue ===
    ;(function(){
          const POOL = [];
          let pending = null;
    
          function _play(url, volume){
            try{
              const a = new Audio(url);
              a.preload = "auto";
              a.playsInline = true;
              if (typeof volume === "number") a.volume = Math.max(0, Math.min(1, volume));
    
              // keep reference so GC can't stop playback
              const idx = POOL.push(a) - 1;
              const cleanup = () => { POOL[idx] = null; };
              a.addEventListener("ended", cleanup, {once:true});
              a.addEventListener("error", cleanup, {once:true});
    
              const pr = a.play();
              if (pr && pr.catch) pr.catch((e)=>{
                pending = url;
                cleanup();
                console.warn("[sound blocked]", url, e);
              });
            }catch(e){
              pending = url;
              console.warn("[sound exception]", url, e);
            }
          }
    
          window.HODLXXI_PLAY_SOUND = function(url, volume){
            if(!url) return;
            _play(url, volume);
          };
    
          function flush(){
            if(!pending) return;
            const u = pending;
            pending = null;
            _play(u);
          }
    
          ["pointerdown","touchstart","click","keydown"].forEach((ev)=>{
            window.addEventListener(ev, flush, {passive:true});
          });
        })();
        // === /SOUND_HELPER_V2 ===
    
    
    if (sessionStorage.getItem('playLoginSound') === '1') {
      sessionStorage.removeItem('playLoginSound');
      window.HODLXXI_PLAY_SOUND('/static/sounds/message.mp3', 0.9);
    }
    
            // Matrix background (warp)
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
    
                    width = cssW;
                    height = cssH;
    
                    particles = [];
                    for (let i = 0; i < (isMobile ? 120 : 400); i++) {
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
                        const x2 = width  / 2 + p.x * scale;
                        const y2 = height / 2 + p.y * scale;
                        const size = Math.max(8 * scale, 1);
    
                        ctx.font = size + 'px monospace';
                        ctx.fillText(CHARS[(Math.random() > 0.5) | 0], x2, y2);
    
                        p.z -= (isMobile ? 2 : 5);
                        if (p.z < 1) {
                            p.x = (Math.random() - 0.5) * width;
                            p.y = (Math.random() - 0.5) * height;
                            p.z = 800;
                        }
                    }
    
                    raf = requestAnimationFrame(draw);
                }
    
                function onVis() {
                    if (document.hidden) {
                        if (raf) { cancelAnimationFrame(raf); raf = null; }
                    } else {
                        if (!raf) raf = requestAnimationFrame(draw);
                    }
                }
    
                window.addEventListener('resize', resize);
                document.addEventListener('visibilitychange', onVis);
    
                resize();
                raf = requestAnimationFrame(draw);
            })();
    
            // Small nav helpers for the top icon row
            window.openPanel = function(which) {
                const url = `${location.origin}${location.pathname}#${which}`;
                window.location.href = url;
            };
    ;(function(){
      function bindTopButtons(){
        try{
          const btnExplorer    = document.getElementById('btnExplorer');
          const btnOnboard     = document.getElementById('btnOnboard');
          const btnChat        = document.getElementById('btnChat');
          const btnExit        = document.getElementById('btnExit');
          const btnScreensaver = document.getElementById('btnScreensaver');
    
          btnExplorer?.addEventListener('click', () => window.openPanel('explorer'));
          btnOnboard?.addEventListener('click', () => window.openPanel('onboard'));
          btnChat?.addEventListener('click', () => { window.location.href = "/app"; });
          btnExit?.addEventListener('click', () => { window.location.href = "/logout"; });
          btnScreensaver?.addEventListener('click', () => { window.location.href = "/screensaver"; });
    
          // debug marker
          window.__HODLXXI_TOPBTN_BOUND = 1;
          console.log("[HODLXXI] top buttons bound", {
            hasExplorer: !!btnExplorer, hasOnboard: !!btnOnboard, hasChat: !!btnChat, hasExit: !!btnExit, hasScreensaver: !!btnScreensaver
          });
        }catch(e){
          console.error("[HODLXXI] bindTopButtons failed", e);
        }
    ;(() => {
      // FIX_TOTALS_BAR_V2: show Total Out / Total In / Ratio based on /verify_pubkey_and_list JSON
      function ensureTotalsBar(){
        let bar = document.getElementById('hodlxxiTotalsBar');
        if (bar) return bar;
    
        bar = document.createElement('div');
        bar.id = 'hodlxxiTotalsBar';
        // FORCE_VISIBLE: keep totals bar above everything and readable
        bar.style.position = 'fixed';
        bar.style.top = '8px';
        bar.style.left = '50%';
        bar.style.transform = 'translateX(-50%)';
        bar.style.zIndex = '999999';
        bar.style.width = 'min(980px, calc(100% - 24px))';
        bar.style.pointerEvents = 'none';
        bar.style.color = 'var(--neon-green, #00ff88)';
        bar.style.background = 'rgba(0,0,0,0.75)';
        bar.style.color = 'var(--neon-green)';
        bar.style.color = 'var(--neon-green)';
        bar.style.cssText = "margin:.6rem auto .2rem;max-width:980px;padding:.55rem .7rem;border:1px solid rgba(0,255,136,.35);border-radius:12px;background:rgba(0,0,0,.25);box-shadow:0 0 18px rgba(0,255,136,.18);font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;letter-spacing:.2px";
        bar.innerHTML = "Totals: <span style='opacity:.8'>loading…</span>";
    
        const host = document.querySelector('.main-grid') || document.body;
        host.prepend(bar);
        return bar;
      }
    
      function renderTotals(t){
        if (!t) return;
        window.__HODLXXI_LAST_TOTALS = t;
        const bar = ensureTotalsBar();
        // HODLXXI_TOTALS_FORCE_FIXED_V5: pin bar to viewport so it is always visible
        try {
          Object.assign(bar.style, {
            position: 'fixed',
            top: '8px',
            left: '50%',
            transform: 'translateX(-50%)',
            zIndex: '999999',
            width: 'min(980px, calc(100% - 24px))',
            pointerEvents: 'none',
            background: 'rgba(0,0,0,0.75)',
          });
        } catch (e) {}
    
        const out_btc = (t.out_total ?? t.out_btc ?? t.out_total_btc ?? "0");
        const in_btc  = (t.in_total  ?? t.in_btc  ?? t.in_total_btc  ?? "0");
        const ratio   = (t.ratio   ?? "0");
        bar.innerHTML =
          `Out: <strong>${out_btc}</strong> BTC &nbsp; | &nbsp; ` +
          `In: <strong>${in_btc}</strong> BTC &nbsp; | &nbsp; ` +
          `Ratio: <strong>${ratio}</strong>`;
      }
    
      
      // FIX_TOTALS_BAR_V2_INIT: make bar visible immediately + expose helpers for debugging
    
      // AUTO_TOTALS_FROM_SESSION_V1: on /home load, fetch session pubkey and pull totals automatically
      (function(){
        if (window.__HODLXXI_AUTO_TOTALS_FROM_SESSION) return;
        window.__HODLXXI_AUTO_TOTALS_FROM_SESSION = 1;
    
        function _parseJsonSafe(txt){
          try{ return JSON.parse(txt); }catch(e){ return null; }
        }
        async function _fetchJson(url, init){
          try{
            const r = await fetch(url, Object.assign({credentials:"same-origin"}, init||{}));
            const txt = await r.text();
            const j = _parseJsonSafe(txt);
            if (j !== null) return j;
            return {ok:false, _status:r.status, _raw:txt};
          }catch(e){
            return {ok:false, _error:String(e)};
          }
        }
        function _pickTotals(j){
          if(!j) return null;
          if (("in_total" in j) || ("out_total" in j) || ("ratio" in j) || ("in_btc" in j) || ("out_btc" in j)) return j;
          if (j.totals_v2) return j.totals_v2;
          if (j.totals) return j.totals;
          if (j.total) return j.total;
          return null;
        }
        function _f2(x){
          const n = Number(x||0);
          return n.toLocaleString(undefined,{minimumFractionDigits:2, maximumFractionDigits:2});
        }
        function _f8(x){
          const n = Number(x||0);
          return n.toLocaleString(undefined,{minimumFractionDigits:8, maximumFractionDigits:8});
        }
    
        // Update the big INCOMING/OUTGOING pills if we can find them by their labels.
        function _updateWhoIsPanels(t){
          try{
            const in_btc  = (t.in_btc ?? t.in_total_btc ?? t.in_total ?? 0);
            const out_btc = (t.out_btc ?? t.out_total_btc ?? t.out_total ?? 0);
            const in_usd  = (t.in_usd ?? t.incoming_usd ?? null);
            const out_usd = (t.out_usd ?? t.outgoing_usd ?? null);
    
            const in_txt  = (in_usd  !== null && in_usd  !== undefined) ? ("$"+_f2(in_usd))  : (_f8(in_btc)+" BTC");
            const out_txt = (out_usd !== null && out_usd !== undefined) ? ("$"+_f2(out_usd)) : (_f8(out_btc)+" BTC");
    
            function setLabel(label, text){
              const nodes = Array.from(document.querySelectorAll("div,span,strong,p,h1,h2,h3"))
                .filter(n => (n.textContent||"").trim().toUpperCase()===label && n.childElementCount===0);
    
              for(const n of nodes){
                const p = n.parentElement;
                if(!p) continue;
    
                // 1) next sibling (common pattern)
                const sib = n.nextElementSibling;
                if (sib && sib !== n){
                  sib.textContent = text;
                  return true;
                }
    
                // 2) find a nearby value node under same parent
                const cand = Array.from(p.querySelectorAll("strong,span,div"))
                  .find(x => x!==n && /\$?\s*[\d,]+(\.\d+)?/.test((x.textContent||"").trim()));
                if (cand){
                  cand.textContent = text;
                  return true;
                }
              }
              return false;
            }
    
            setLabel("INCOMING", in_txt);
            setLabel("OUTGOING", out_txt);
          }catch(e){
            console.warn("[HODLXXI] AUTO_TOTALS_FROM_SESSION_V1 panels failed", e);
          }
        }
    
        async function refresh(){
          try{
            const sess = await _fetchJson("/api/debug/session");
            const pk = sess.pubkey || sess.logged_in_pubkey || sess.pof_pubkey;
            if(!pk) return;
    
            // Pull totals using existing endpoint (also feeds totals-bar fetch hook)
            const j = await _fetchJson("/verify_pubkey_and_list?pubkey="+encodeURIComponent(pk));
            const t = _pickTotals(j) || j || {};
    
            if (t && window.__HODLXXI_renderTotals) window.__HODLXXI_renderTotals(t);
            _updateWhoIsPanels(t);
          }catch(e){
            console.warn("[HODLXXI] AUTO_TOTALS_FROM_SESSION_V1 refresh failed", e);
          }
        }
    
        setTimeout(refresh, 120);
        document.addEventListener("visibilitychange", function(){
          if(!document.hidden) setTimeout(refresh, 80);
        });
    
        window.__HODLXXI_refreshTotalsFromSession = refresh; // debug hook
      })();
      try {
        window.__HODLXXI_renderTotals = renderTotals;
        window.__HODLXXI_ensureTotalsBar = ensureTotalsBar;
        ensureTotalsBar();
        console.log("[HODLXXI] totals bar initialized");
      } catch (e) {}
    const origFetch = window.fetch;
      if (!origFetch || origFetch.__HODLXXI_TOTALS_HOOKED) return;
    
      window.fetch = async function(...args){
        const res = await origFetch.apply(this, args);
        try{
          const u = String(args[0] && args[0].url ? args[0].url : args[0] || "");
          if (u.includes("/verify_pubkey_and_list")) {
            const c = res.clone();
            c.json().then((j)=>{
              if (!j) return;
              // accept top-level totals from backend: {in_total,out_total,ratio}
              if (("in_total" in j) || ("out_total" in j) || ("ratio" in j)) { renderTotals(j); return; }
              if (j.totals || j.total || j.totals_v2) renderTotals(j.totals || j.totals_v2 || j.total);
            }).catch(()=>{});
          }
        }catch(e){}
        return res;
      };
      window.fetch.__HODLXXI_TOTALS_HOOKED = 1;
    })();
      }
    
      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", bindTopButtons);
      } else {
        bindTopButtons();
      }
    })();
            function switchPanelByHash() {
                const h = (location.hash || '').slice(1);
                const showId =
                      h === 'explorer' ? 'explorerPanel'
                    : h === 'onboard'  ? 'onboardPanel'
                    : 'homePanel';
    
                ['homePanel','explorerPanel','onboardPanel'].forEach(id => {
                    const el = document.getElementById(id);
                    if (!el) return;
                    el.classList.toggle('hidden', id !== showId);
                });
    
                const rpc = document.querySelector('.rpc-section');
                if (rpc) rpc.classList.toggle('hidden', showId === 'homePanel');
    
                window.scrollTo({ top: 0 });
            }
    
            window.addEventListener('hashchange', switchPanelByHash);
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', switchPanelByHash);
    } else {
      try { switchPanelByHash(); } catch(e){ console.error("[HODLXXI] switchPanelByHash failed", e); }
    }
    function maskDeepLinkedKeyForLimited() {
                try {
                    // Only mask for non-full users
                    if (typeof accessLevel !== 'undefined' && accessLevel === 'full') return;
    
                    const hash = window.location.hash || '';
                    if (!hash || hash.indexOf('#explorer') !== 0) return;
    
                    let target = null;
                    try {target = localStorage.getItem('hodlxxi_explorer_target') || null;} catch (e) {
                        target = null;
                    }
                    if (!target) return;
    
                    const inp = document.getElementById('pubKey');
                    if (!inp) return;
    
                    const last4 = target.slice(-4);
                    inp.value = '…' + last4;
                } catch (e) {
                    if (window.console && console.warn) {
                        console.warn('maskDeepLinkedKeyForLimited failed', e);
                    }
                }
            }
    
            // Run after all other DOMContentLoaded handlers (including deep-link loader)
            document.addEventListener('DOMContentLoaded', () => {
                setTimeout(maskDeepLinkedKeyForLimited, 0);
            });
    
            function autoLoadExplorerFromDeepLink() {
                try {
                    const hash = window.location.hash || '';
                    // Only act on /home#explorer
                    if (!hash || hash.indexOf('#explorer') !== 0) return;
    
                    let target = null;
                    try {target = localStorage.getItem('hodlxxi_explorer_target') || null;} catch (e) {
                        target = null;
                    }
                    if (!target) return;
    
                    // Put the pubkey into the Explorer input
                    const inp = document.getElementById('pubKey');
                    if (inp) inp.value = target;
    
                    // Run the covenant lookup immediately
                    verifyAndListContracts(target);
                } catch (err) {
                    if (window.console && console.warn) {
                        console.warn('Explorer deep-link failed', err);
                    }
                }
            }
    
            document.addEventListener('DOMContentLoaded', autoLoadExplorerFromDeepLink);
        </script>
    <script>
    (function(){
      // FIX_TOTALS_BAR_V1: render Total In/Out from /verify_pubkey_and_list responses (no edits to big inline JS)
      function renderTotalsBar(t){
        try{
          if(!t) return;
          const host = document.getElementById('explorerPanel') || document.getElementById('homePanel') || document.body;
          let bar = document.getElementById('hodlxxiTotalsBar');
          if(!bar){
            bar = document.createElement('div');
            bar.id = 'hodlxxiTotalsBar';
            bar.style.cssText = [
              "margin:.6rem auto 0",
              "padding:.45rem .65rem",
              "max-width:980px",
              "border:1px solid rgba(0,255,136,.25)",
              "border-radius:14px",
              "background:rgba(0,0,0,.35)",
              "box-shadow:0 0 20px rgba(0,255,136,.12)",
              "font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace",
              "font-size:.85rem"
            ].join(";");
            const anchor = document.getElementById('pubKey') || host.firstElementChild;
            if(anchor && anchor.parentNode) anchor.parentNode.insertBefore(bar, anchor);
            else host.prepend(bar);
          }
          const f8 = (x)=> (typeof x === 'number' && isFinite(x)) ? x.toFixed(8).replace(/0+$/,'').replace(/\.$/,'') : String(x ?? 0);
          const f2 = (x)=> (typeof x === 'number' && isFinite(x)) ? x.toFixed(2) : String(x ?? 0);
          const ratio = (typeof t.ratio === 'number' && isFinite(t.ratio)) ? t.ratio.toFixed(2) : "0.00";
          bar.innerHTML =
            `<span style="opacity:.8">Total In</span> <strong>${f8(t.in_btc ?? t.in_total_btc ?? t.in_total)}</strong> BTC <span style="opacity:.65">($${f2(t.in_usd)})</span>` +
            ` &nbsp; | &nbsp; <span style="opacity:.8">Total Out</span> <strong>${f8(t.out_btc ?? t.out_total_btc ?? t.out_total)}</strong> BTC <span style="opacity:.65">($${f2(t.out_usd)})</span>` +
            ` &nbsp; | &nbsp; <span style="opacity:.8">Ratio</span> <strong>${ratio}</strong>`;
        }catch(e){ console.warn("[HODLXXI] renderTotalsBar failed", e); }
      }
    
      const _fetch = window.fetch;
      if (typeof _fetch !== "function") return;
    
      window.fetch = function(input, init){
        const p = _fetch(input, init);
        try{
          const url = (typeof input === "string") ? input : (input && input.url) ? input.url : "";
          if (url && url.indexOf("/verify_pubkey_and_list") !== -1) {
            return Promise.resolve(p).then((resp)=>{
              try{
                const c = resp.clone();
                c.json().then((data)=>{
                  if (data && data.totals) renderTotalsBar(data.totals);
                }).catch(()=>{});
              }catch(e){}
              return resp;
            });
          }
        }catch(e){}
        return p;
      };
    })();
    </script>
    </body>
    </html>
    
        """
        logger.debug("home → access_level=%s", access_level)
        
        return render_template_string(html, access_level=access_level, initial_pubkey=initial_pubkey)
    
    _BROWSER_ROUTE_HANDLERS["home"] = home_page



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
    
