# HODLXXI / KeyAuth BTC – Ops Cheat Sheet

Location: `/srv/ubid`  
Python venv: `/srv/ubid/venv`  
Main app module: `wsgi:app` (imports `from app.app import app`)  
Current JWT mode: **HS256** (uses `JWT_SECRET` from `.env`)

---

## 1. Directory Layout

```text
/srv/ubid
  ├─ app/                # Flask app package
  │   └─ app.py          # Main Flask app
  ├─ venv/               # Python virtualenv
  ├─ wsgi.py             # WSGI entry (wsgi:app)
  ├─ logs/
  │   └─ gunicorn.log    # App / gunicorn log
  ├─ ubid.db             # Main app DB (Postgres is separate)
  ├─ pof_attest.db       # PoF demo DB
  ├─ jwt_private.pem?    # (optional RS256 keys, currently unused)
  ├─ jwt_public.pem?     # (optional RS256 keys, currently unused)
  ├─ .env                # Environment config
  ├─ HODLXXI OAuth2 Live Demo.sh
  ├─ PRODUCTION VALIDATION.sh
  └─ HODLXXI-OPS-CHEATSHEET.md  # this file
