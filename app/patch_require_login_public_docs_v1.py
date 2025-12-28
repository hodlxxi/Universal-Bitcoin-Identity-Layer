from pathlib import Path
import re

APP = Path("/srv/ubid/app/app.py")
s = APP.read_text(encoding="utf-8")

MARK = "REQUIRE_LOGIN_PUBLIC_DOCS_V1"
if MARK in s:
    print("SKIP: already patched (REQUIRE_LOGIN_PUBLIC_DOCS_V1)")
    raise SystemExit(0)

# Find require_login definition
m = re.search(r'(?m)^def\s+require_login\s*\(\s*view_func\s*\)\s*:\s*$', s)
if not m:
    raise SystemExit("SAFE-STOP: could not find def require_login(view_func):")

# Find the wrapper function inside require_login (common pattern: def wrapper(*args, **kwargs):)
# Search after require_login start for first "def wrapper"
m2 = re.search(r'(?m)^\s+def\s+wrapper\s*\(.*\)\s*:\s*$', s[m.end():])
if not m2:
    raise SystemExit("SAFE-STOP: could not find wrapper() inside require_login")

wrapper_start = m.end() + m2.end()

# Insert allowlist near the top of wrapper
insert = r'''
        # === REQUIRE_LOGIN_PUBLIC_DOCS_V1 ===
        try:
            _p = request.path or ""
            # Public, shareable docs (no login)
            if _p in ("/docs", "/docs/", "/docs2") or _p.startswith("/docs/") or _p.startswith("/static/docs/"):
                return view_func(*args, **kwargs)
        except Exception:
            pass
        # === /REQUIRE_LOGIN_PUBLIC_DOCS_V1 ===

'''

# Ensure request is in scope; if not, require_login already uses it elsewhere.
# We will just insert; if request isn't imported, app would already be broken in current code.

s2 = s[:wrapper_start] + insert + s[wrapper_start:]
APP.write_text(s2, encoding="utf-8")
print("OK: inserted REQUIRE_LOGIN_PUBLIC_DOCS_V1 inside require_login.wrapper()")
