from pathlib import Path
import re

APP = Path("/srv/ubid/app/app.py")
s = APP.read_text(encoding="utf-8")

MARK = "DOCS_INDEX_DYNAMIC_V1"
if MARK in s:
    print("SKIP: already patched (DOCS_INDEX_DYNAMIC_V1)")
    raise SystemExit(0)

# Find the existing docs_alias() function block start
m = re.search(r'(?ms)@app\.route\("/docs"\)\s*\n@app\.route\("/docs/"\)\s*\ndef\s+docs_alias\(\):\s*\n', s)
if not m:
    raise SystemExit("SAFE-STOP: could not locate docs_alias() route block")

start = m.end()

# Replace the body of docs_alias() up to the next top-level @app.route decorator
# We'll locate the next decorator after docs_alias definition.
n = re.search(r'(?m)^\s*@app\.(route|get|post|put|delete)\(', s[start:])
if not n:
    raise SystemExit("SAFE-STOP: could not locate next route decorator after docs_alias()")
end = start + n.start()

new_body = r'''
    # === DOCS_INDEX_DYNAMIC_V1: dynamic docs index from /static/docs/docs ===
    import os
    import re as _re
    from flask import render_template

    docs_dir = os.path.join(app.static_folder, "docs", "docs")

    # Curated ordering: put the "start here" set on top if present
    curated = [
        "README",
        "what_is_hodlxxi",
        "about_short",
        "how_it_works",
        "architecture",
        "faq",
        "crt_theory",
        "principles",
        "ethics",
        "threat_model_and_failure_modes",
        "research_status",
        "auth0_comparison",
        "academic_references_and_prior_art",
        "bibliography",
    ]

    md_items = []
    pdf_items = []

    def _title_from_md(text: str, fallback: str) -> str:
        # first markdown heading like "# Title"
        for line in (text or "").splitlines():
            line = line.strip()
            if line.startswith("#"):
                return line.lstrip("#").strip() or fallback
            if line:
                break
        return fallback

    def _desc_from_md(text: str) -> str:
        # first non-empty paragraph-ish line (not heading)
        for line in (text or "").splitlines():
            t = line.strip()
            if not t:
                continue
            if t.startswith("#"):
                continue
            if t.startswith(">"):
                t = t.lstrip(">").strip()
            if len(t) < 8:
                continue
            return t[:220]
        return ""

    try:
        names = sorted(os.listdir(docs_dir))
    except Exception:
        names = []

    # Build md list
    md_map = {}
    for name in names:
        low = name.lower()
        p = os.path.join(docs_dir, name)
        if low.endswith(".md") and os.path.isfile(p):
            slug = name[:-3]
            md_map[slug] = p

    # Order: curated first, then the rest alpha
    ordered_slugs = []
    for c in curated:
        if c in md_map:
            ordered_slugs.append(c)
    for slug in sorted(md_map.keys()):
        if slug not in ordered_slugs:
            ordered_slugs.append(slug)

    for slug in ordered_slugs:
        p = md_map[slug]
        try:
            raw = Path(p).read_text(encoding="utf-8", errors="replace")
        except Exception:
            raw = ""
        display = _title_from_md(raw, slug.replace("_", " ").replace("-", " ").title())
        desc = _desc_from_md(raw)
        try:
            size_kb = int((Path(p).stat().st_size + 1023) / 1024)
        except Exception:
            size_kb = None
        md_items.append({"slug": slug, "display": display, "desc": desc, "size_kb": size_kb})

    # PDFs
    for name in names:
        low = name.lower()
        p = os.path.join(docs_dir, name)
        if low.endswith(".pdf") and os.path.isfile(p):
            try:
                size_kb = int((Path(p).stat().st_size + 1023) / 1024)
            except Exception:
                size_kb = None
            pdf_items.append({"name": name, "size_kb": size_kb})

    return render_template("docs_index.html", title="HODLXXI Docs", md_items=md_items, pdf_items=pdf_items)
    # === /DOCS_INDEX_DYNAMIC_V1 ===
'''

# Ensure function indentation is 4 spaces in body
# (We wrote it with 4-space indentation already.)
patched = s[:start] + new_body + "\n\n" + s[end:]
APP.write_text(patched, encoding="utf-8")
print("OK: patched docs_alias() -> dynamic docs index (DOCS_INDEX_DYNAMIC_V1)")
