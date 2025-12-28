#!/usr/bin/env python3
"""
HODLXXI App Surface Mapper
Safe: read-only, runtime-accurate
"""

import inspect
import re
from pathlib import Path

# ✅ Correct import (same as gunicorn)
from wsgi import app

BASE = Path("/srv/ubid/app")
TPL = BASE / "templates"
STATIC = BASE / "static"

print("\n" + "="*80)
print("🌐 ROUTES & ENDPOINTS")
print("="*80)

for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
    endpoint = rule.endpoint
    methods = ",".join(sorted(m for m in rule.methods if m not in ("HEAD","OPTIONS")))
    view = app.view_functions.get(endpoint)

    src = ""
    try:
        src = inspect.getsource(view)
    except Exception:
        pass

    is_html = any(k in src for k in ("render_template", "<html", "text/html"))
    is_json = any(k in src for k in ("jsonify", "application/json"))

    kind = "HTML" if is_html else "JSON" if is_json else "UNKNOWN"

    print(f"{rule.rule:45} [{methods:10}] {kind:8} -> {endpoint}")

# -----------------------------------------------------------------------------

print("\n" + "="*80)
print("🔓 PUBLIC ROUTES (from check_auth)")
print("="*80)

check_auth = app.view_functions.get("check_auth")
if check_auth:
    src = inspect.getsource(check_auth)
    matches = re.findall(r'flask_request\.path\s+in\s+\((.*?)\)', src, re.S)
    if matches:
        for p in matches[0].split(","):
            print("PUBLIC:", p.strip())
    else:
        print("No explicit public allowlist found")
else:
    print("check_auth() not found")

# -----------------------------------------------------------------------------

print("\n" + "="*80)
print("📄 TEMPLATES")
print("="*80)

if TPL.exists():
    for p in sorted(TPL.rglob("*.html")):
        print(p.relative_to(TPL))
else:
    print("No templates directory")

# -----------------------------------------------------------------------------

print("\n" + "="*80)
print("📦 STATIC FILES")
print("="*80)

if STATIC.exists():
    for p in sorted(STATIC.rglob("*")):
        if p.is_file():
            print(p.relative_to(STATIC))
else:
    print("No static directory")

# -----------------------------------------------------------------------------

print("\n" + "="*80)
print("🧱 INLINE HTML (legacy)")
print("="*80)

text = (BASE / "app.py").read_text(errors="ignore")
count = len(re.findall(r'<html', text, re.I))
print(f"Inline <html> occurrences in app.py: {count}")

print("\nDONE.")
