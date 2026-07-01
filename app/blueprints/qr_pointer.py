"""Safe QR pointer landing pages.

The QR pointer surface is intentionally discovery-only. It renders a bounded,
non-redirecting landing page for static QR pointer fixtures and never mutates
jobs, issues receipts, or calls receipt verification automatically.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from html import escape
from importlib import resources
from typing import Any
from urllib.parse import urlsplit

from flask import Blueprint, abort, render_template_string

qr_pointer_bp = Blueprint("qr_pointer", __name__)

_ALLOWED_STATIC_TARGETS = {
    "/.well-known/agent.json",
    "/agent/capabilities",
    "/agent/discovery",
}
_ALLOWED_STATUSES = {"active", "revoked", "expired"}
_SECRET_LIKE_KEYS = {
    "api_key",
    "mnemonic",
    "password",
    "private_key",
    "privkey",
    "secret",
    "seed",
    "wif",
    "xprv",
}
_JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

_LANDING_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HODLXXI QR Pointer</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #070706;
      --panel: #12100c;
      --panel-strong: #1d1810;
      --text: #f6efe1;
      --muted: #c8bfae;
      --line: rgba(245, 177, 66, 0.24);
      --gold: #f5b142;
      --gold-soft: rgba(245, 177, 66, 0.14);
      --inactive: #ff6b5f;
      --inactive-soft: rgba(255, 107, 95, 0.12);
    }

    * { box-sizing: border-box; }

    body {
      min-height: 100vh;
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(245, 177, 66, 0.18), transparent 34rem),
        linear-gradient(135deg, #070706 0%, #11100e 48%, #060605 100%);
    }

    main {
      width: min(46rem, calc(100% - 2rem));
      margin: 0 auto;
      padding: 8vh 0;
    }

    .card {
      overflow: hidden;
      border: 1px solid var(--line);
      border-radius: 28px;
      background: linear-gradient(180deg, rgba(29, 24, 16, 0.94), rgba(13, 12, 10, 0.96));
      box-shadow: 0 24px 80px rgba(0, 0, 0, 0.42);
    }

    .hero { padding: clamp(1.5rem, 5vw, 3rem); }

    .eyebrow {
      margin: 0 0 0.75rem;
      color: var(--gold);
      font-size: 0.78rem;
      font-weight: 700;
      letter-spacing: 0.16em;
      text-transform: uppercase;
    }

    h1 {
      margin: 0;
      font-size: clamp(2rem, 7vw, 3.6rem);
      line-height: 0.98;
      letter-spacing: -0.055em;
    }

    .status-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      align-items: center;
      margin: 1.35rem 0 0;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      border: 1px solid currentColor;
      border-radius: 999px;
      padding: 0.45rem 0.72rem;
      font-size: 0.84rem;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }

    .badge::before {
      width: 0.58rem;
      height: 0.58rem;
      border-radius: 999px;
      background: currentColor;
      content: "";
    }

    .badge-active { color: var(--gold); background: var(--gold-soft); }
    .badge-inactive { color: var(--inactive); background: var(--inactive-soft); }

    .copy {
      color: var(--muted);
      font-size: 1.05rem;
      line-height: 1.65;
    }

    .target-panel {
      margin-top: 1.5rem;
      border: 1px solid var(--line);
      border-radius: 20px;
      padding: 1rem;
      background: rgba(0, 0, 0, 0.2);
    }

    .target-label {
      margin: 0 0 0.6rem;
      color: var(--gold);
      font-size: 0.76rem;
      font-weight: 800;
      letter-spacing: 0.12em;
      text-transform: uppercase;
    }

    code {
      display: block;
      overflow-wrap: anywhere;
      color: var(--text);
      font: 0.98rem/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }

    .action {
      display: inline-flex;
      margin-top: 1.25rem;
      border-radius: 999px;
      padding: 0.85rem 1.1rem;
      color: #130d04;
      background: var(--gold);
      font-weight: 900;
      text-decoration: none;
      box-shadow: 0 10px 32px rgba(245, 177, 66, 0.22);
    }

    .footer-note {
      border-top: 1px solid var(--line);
      padding: 1rem clamp(1.5rem, 5vw, 3rem);
      color: var(--muted);
      background: rgba(0, 0, 0, 0.16);
      font-size: 0.95rem;
      line-height: 1.55;
    }
  </style>
</head>
<body>
  <main>
    <section class="card" aria-labelledby="qr-title">
      <div class="hero">
        <p class="eyebrow">HODLXXI</p>
        <h1 id="qr-title">{{ label }}</h1>
        <div class="status-row">
          {% if active %}
            <span class="badge badge-active">Active pointer</span>
          {% else %}
            <span class="badge badge-inactive">Inactive pointer</span>
          {% endif %}
        </div>

        {% if active %}
          <p class="copy">
            QR discovery landing. This read-only page shows the target before any navigation.
            The browser will not redirect automatically.
          </p>
          <div class="target-panel">
            <p class="target-label">Target to review</p>
            <code>{{ target }}</code>
          </div>
          <a class="action" href="{{ target }}" rel="nofollow noopener">Open target</a>
        {% else %}
          <p class="copy">
            This QR pointer is no longer active. The page fails closed and no target-opening
            action is available.
          </p>
        {% endif %}
      </div>
      <p class="footer-note">
        QR pages are discovery-only and non-authoritative. Use the target runtime surface for
        job or receipt review; /agent/verify/&lt;job_id&gt; remains the authority for job and receipt checks.
      </p>
    </section>
  </main>
</body>
</html>
"""


def _contains_secret_like_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            lowered = str(key).lower()
            if any(secret_key in lowered for secret_key in _SECRET_LIKE_KEYS):
                return True
            if _contains_secret_like_key(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_secret_like_key(item) for item in value)
    return False


def is_allowed_qr_target(target: object) -> bool:
    """Return whether a QR target is a bounded local discovery URL."""
    if not isinstance(target, str) or not target.startswith("/"):
        return False
    if target.startswith("//"):
        return False

    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        return False
    if ".." in parsed.path.split("/"):
        return False
    if target in _ALLOWED_STATIC_TARGETS:
        return True

    prefix = "/agent/verify/"
    if not target.startswith(prefix):
        return False
    job_id = target[len(prefix) :]
    return "/" not in job_id and bool(_JOB_ID_RE.fullmatch(job_id))


def _normalize_pointer(token: str, value: Any) -> dict[str, str] | None:
    if not isinstance(value, dict):
        return None
    if _contains_secret_like_key(value):
        return None
    if value.get("token") != token:
        return None
    status = value.get("status")
    target = value.get("target")
    if status not in _ALLOWED_STATUSES or not is_allowed_qr_target(target):
        return None
    label = value.get("label")
    if not isinstance(label, str) or not label.strip():
        label = "HODLXXI QR Pointer"
    return {"label": label.strip(), "status": status, "target": target}


@lru_cache(maxsize=1)
def load_qr_pointers() -> dict[str, dict[str, str]]:
    """Load static QR pointer fixtures, failing closed on malformed data."""
    try:
        raw = resources.files(__package__).joinpath("qr_pointers.json").read_text()
        decoded = json.loads(raw)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return {}

    if not isinstance(decoded, dict) or _contains_secret_like_key(decoded):
        return {}

    pointers: dict[str, dict[str, str]] = {}
    for token, value in decoded.items():
        if not isinstance(token, str) or not token:
            continue
        normalized = _normalize_pointer(token, value)
        if normalized is not None:
            pointers[token] = normalized
    return pointers


@qr_pointer_bp.get("/qr/<token>")
def qr_pointer_landing(token: str):
    pointer = load_qr_pointers().get(token)
    if pointer is None:
        abort(404)

    active = pointer["status"] == "active"
    status_code = 200 if active else 410
    html = render_template_string(
        _LANDING_TEMPLATE,
        active=active,
        label=escape(pointer["label"]),
        status=escape(pointer["status"]),
        target=escape(pointer["target"]),
    )
    return html, status_code
