from flask import redirect, request, render_template_string, session


def render_browser_home_page(*, logger=None):
    if not session.get("logged_in_pubkey"):
        return redirect(f"/login?next={request.path}")

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
            fetch(url, {
                credentials: 'same-origin'
            })
                .then(async r => {
                    const text = await r.text();
                    try {
                        return { status: r.status, data: JSON.parse(text) };
                    } catch {
                        return { status: r.status, data: text };
                    }
                })
                .then(({status, data}) => {
                    if (status !== 200) {
                        if (out) out.textContent = 'Error (' + status + '): ' + JSON.stringify(data, null, 2);
                        return;
                    }
                    if (out) out.textContent = JSON.stringify(data, null, 2);
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

            fetch('/api/decode_raw_script', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({
                    script: rawScript
                })
            })
            .then(async (r) => {
                const ct = r.headers.get('content-type') || '';
                const text = await r.text();
                try {
                    return ct.includes('application/json')
                        ? JSON.parse(text)
                        : { error: text || `${r.status} ${r.statusText}` };
                } catch (e) {
                    return { error: text || e.message || 'Invalid JSON response' };
                }
            })
            .then(d => {
                const out = document.getElementById('decodedWitness');
                if (d.error) {
                    out.textContent = `Error: ${d.error}`;
                } else {
                    const decoded = d.decoded || {};
                    const segwit = decoded.segwit || {};
                    const summary = [];

                    if (decoded.asm) summary.push(`ASM: ${decoded.asm}`);
                    if (d.npub_if) summary.push(`Receiver npub: ${d.npub_if}`);
                    if (d.npub_else) summary.push(`Giver npub: ${d.npub_else}`);
                    if (segwit.address) summary.push(`HODL address: ${segwit.address}`);
                    if (d.first_unused_addr_text) summary.push(`First unused address: ${d.first_unused_addr_text}`);
                    if (d.script_hex) summary.push(`Script hex: ${d.script_hex}`);

                    if (d.else_early_lock || d.else_early_pub) {
                        summary.push(`Early exit: lock=${d.else_early_lock || 'n/a'} pub=${d.else_early_pub || 'n/a'}`);
                    }
                    if (d.else_late_lock || d.else_late_pub) {
                        summary.push(`Late exit: lock=${d.else_late_lock || 'n/a'} pub=${d.else_late_pub || 'n/a'}`);
                    }

                    if (d.warning) summary.push(`Warning: ${d.warning}`);

                    out.textContent = summary.length ? summary.join("\n") : "Decoded OK";
                }

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
            .then(async (r) => {
                const ct = r.headers.get('content-type') || '';
                const text = await r.text();
                let data;
                try {
                    data = ct.includes('application/json') ? JSON.parse(text) : { error: text };
                } catch (e) {
                    data = { error: text || e.message };
                }

                const out = document.getElementById("importResult");

                if (!r.ok || data.error || data.success === false) {
                    if (out) out.innerHTML = "Error: " + (data.error || "Import failed");
                    return;
                }

                if (data.script_hex) window.lastScriptHex = data.script_hex;
                if (out) {
                    out.innerHTML =
                        "Imported ✔️<br><small>script_hex: " + (data.script_hex || "n/a") + "</small>" +
                        (data.address ? "<br><small>address: " + data.address + "</small>" : "");
                }

                const scriptToDecode = data.script_hex || window.lastScriptHex;
                if (scriptToDecode) {
                    const res = await fetch('/api/decode_raw_script', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                        credentials: 'same-origin',
                        body: JSON.stringify({ script: scriptToDecode })
                    }).then(async (r) => {
                        const ct = r.headers.get('content-type') || '';
                        const text = await r.text();
                        try {
                            return ct.includes('application/json') ? JSON.parse(text) : { error: text };
                        } catch (e) {
                            return { error: text || e.message };
                        }
                    }).catch((e) => ({ error: String(e) }));

                    const qrContainer = document.getElementById('qr-codes');
                    if (qrContainer) {
                        if (res && !res.error) {
                            qrContainer.innerHTML =
                                "<pre style='white-space:pre-wrap'>" +
                                JSON.stringify(res, null, 2) +
                                "</pre>";
                        } else {
                            qrContainer.innerHTML =
                                "<div style='color:var(--red)'>Decode error: " +
                                ((res && res.error) || "unknown") +
                                "</div>";
                        }
                    }
                }
            })
            .catch(err => {
                const out = document.getElementById("importResult");
                if (out) out.innerHTML = "Error: " + (err?.message || err);
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
    if logger is not None:
        logger.debug("home → access_level=%s", access_level)

    return render_template_string(html, access_level=access_level, initial_pubkey=initial_pubkey)
