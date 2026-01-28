import re
from pathlib import Path

import markdown
from flask import abort, render_template

STATIC_DOCS_DIR = Path(__file__).resolve().parent / "static" / "docs" / "docs"

DOC_ALIASES = {
    "manifesto": "about_short",
    "about": "what_is_hodlxxi",
    "what": "what_is_hodlxxi",
}


def register_docs_routes(app):
    @app.route("/docs/<slug>")
    def docs_slug(slug: str):
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", slug or ""):
            abort(404)

        key = DOC_ALIASES.get(slug, slug)
        md_path = STATIC_DOCS_DIR / f"{key}.md"
        if not md_path.exists():
            abort(404)

        text = md_path.read_text(encoding="utf-8")
        html = markdown.markdown(text, extensions=["extra", "toc", "tables"])
        title = key.replace("_", " ").replace("-", " ").title()
        return render_template("doc_page.html", content=html, title=title)
