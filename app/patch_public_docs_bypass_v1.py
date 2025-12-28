from pathlib import Path
import re

p = Path("/srv/ubid/app/app.py")
s = p.read_text(encoding="utf-8")

MARK = "PUBLIC_DOCS_BYPASS_V1"
if MARK in s:
    print("SKIP: already patched (PUBLIC_DOCS_BYPASS_V1)")
    raise SystemExit(0)

# We target the common pattern used by your app:
# redirect(url_for("login", next=...))
# We'll insert a bypass immediately BEFORE that redirect in the SAME function.
login_redirect_pat = re.compile(
    r'(?m)^(?P<indent>\s*)return\s+redirect\(\s*url_for\(\s*[\'"]login[\'"]\s*,\s*next\s*=\s*[^)]*\)\s*(?:,\s*code\s*=\s*\d+)?\s*\)\s*$'
)

m = login_redirect_pat.search(s)
if not m:
    print("SAFE-STOP: could not find a 'return redirect(url_for(\"login\", next=...))' line to patch.")
    print("Run: grep -n \"url_for(\\\"login\\\"\" -n /srv/ubid/app/app.py | head")
    raise SystemExit(2)

indent = m.group("indent")

bypass = (
    f"{indent}# === {MARK}: allow public docs routes ===\n"
    f"{indent}try:\n"
    f"{indent}    _path = request.path or \"\"\n"
    f"{indent}    # Public docs + docs assets (viral/shareable)\n"
    f"{indent}    if _path == \"/docs\" or _path.startswith(\"/docs/\") or _path.startswith(\"/static/docs/\"):\n"
    f"{indent}        return None\n"
    f"{indent}except Exception:\n"
    f"{indent}    pass\n"
    f"{indent}# === /{MARK} ===\n"
)

# Insert bypass right before the redirect-to-login return
s2 = s[:m.start()] + bypass + s[m.start():]
p.write_text(s2, encoding="utf-8")
print(f"OK: inserted {MARK} before first redirect-to-login guard at offset {m.start()}")
