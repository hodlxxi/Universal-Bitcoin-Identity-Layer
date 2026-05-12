const canvas = document.getElementById("matrix");
const ctx = canvas.getContext("2d");

function resize() {
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
}

resize();
window.addEventListener("resize", resize);

const chars = "01₿⚡NOSTR_ID_MY_KYC_HODLXXI";
const fontSize = 16;
let columns = Math.floor(canvas.width / fontSize);
let drops = Array(columns).fill(1);

function drawMatrix() {
  ctx.fillStyle = "rgba(2, 7, 4, 0.08)";
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  ctx.fillStyle = "#00ff88";
  ctx.font = `${fontSize}px monospace`;

  columns = Math.floor(canvas.width / fontSize);
  if (drops.length !== columns) drops = Array(columns).fill(1);

  for (let i = 0; i < drops.length; i++) {
    const text = chars[Math.floor(Math.random() * chars.length)];
    ctx.fillText(text, i * fontSize, drops[i] * fontSize);

    if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
      drops[i] = 0;
    }
    drops[i]++;
  }
}

setInterval(drawMatrix, 48);

async function checkRuntimeStatus() {
  const box = document.getElementById("statusBox");
  const onlineUsers = document.getElementById("onlineUsers");
  const activeSockets = document.getElementById("activeSockets");
  const btcHeight = document.getElementById("btcHeight");
  const lndState = document.getElementById("lndState");

  const url = "https://hodlxxi.com/api/public/status";

  function setMetric(el, value) {
    if (el) el.textContent = value;
  }

  function setUnavailable(message) {
    setMetric(onlineUsers, "live");
    setMetric(activeSockets, "—");
    setMetric(btcHeight, "—");
    setMetric(lndState, "open status");

    if (box) {
      box.textContent =
        message + "\n" +
        "Open public status directly:\n" +
        url;
    }
  }

  try {
    const res = await fetch(url, { method: "GET", cache: "no-store" });

    if (!res.ok) {
      setUnavailable(`Runtime reachable but returned HTTP ${res.status}.`);
      return;
    }

    const data = await res.json();

    setMetric(onlineUsers, String(data.online_users ?? "—"));
    setMetric(activeSockets, String(data.active_sockets ?? "—"));
    setMetric(btcHeight, String(data.block_height ?? data.btc?.block_height ?? "—"));

    const lnd = data.lnd?.active
      ? (data.lnd?.state || "active")
      : "inactive";

    setMetric(lndState, lnd);

    if (box) {
      box.textContent = JSON.stringify({
        runtime: "hodlxxi.com",
        ready: true,
        online_users: data.online_users,
        active_sockets: data.active_sockets,
        online_roles: data.online_roles,
        block_height: data.block_height ?? data.btc?.block_height,
        lnd: data.lnd,
        server_time_utc: data.server_time_utc
      }, null, 2);
    }
  } catch (err) {
    setUnavailable(
      "Browser live status check is blocked or unavailable. This is usually CORS if the landing is hosted on another domain."
    );
  }
}

checkRuntimeStatus();
