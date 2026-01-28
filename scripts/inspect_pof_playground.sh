#!/usr/bin/env bash
set -euo pipefail

echo "================= GENERAL ================="
echo "PWD: $(pwd)"
echo
echo "== ls . =="
ls
echo

echo "== git status =="
git status -sb || echo "no git repo?"
echo

echo "================= /srv LAYOUT ================="
ls -ld /srv/* || true
echo

echo "================= POF DB PATHS IN CODE ================="
grep -n "POF_DB_PATH" app/app.py pof_enhanced.py || true
echo

echo "================= FLASK ROUTES (POF + PLAYGROUND) ================="
source venv/bin/activate
python - << 'PY'
from app.app import app
print("Root path:", app.root_path)
print("Static folder:", app.static_folder)
print("Template folder:", app.template_folder)
print("\nRoutes:")
for rule in app.url_map.iter_rules():
    if "pof" in rule.rule or "playground" in rule.rule:
        print(f"{rule.rule:40} => {rule.endpoint:30} {sorted(rule.methods)}")
PY
echo

cd app

echo "================= templates/pof ================="
if [ -d templates/pof ]; then
  ls -R templates/pof
  echo
  for f in templates/pof/*.html; do
    echo "----- $f (md5sum) -----"
    md5sum "$f" || true
    echo "----- FIRST 80 LINES of $f -----"
    sed -n '1,80p' "$f" || true
    echo
  done
else
  echo "NO templates/pof directory found"
fi
echo

echo "================= templates/playground.html ================="
if [ -f templates/playground.html ]; then
  md5sum templates/playground.html || true
  echo "----- FIRST 80 LINES of templates/playground.html -----"
  sed -n '1,80p' templates/playground.html || true
else
  echo "NO templates/playground.html file"
fi
echo

echo "================= static/playground ================="
if [ -d static/playground ]; then
  ls -R static/playground
  echo
  if [ -f static/playground/index.html ]; then
    echo "----- static/playground/index.html (md5sum) -----"
    md5sum static/playground/index.html || true
    echo "----- FIRST 80 LINES of static/playground/index.html -----"
    sed -n '1,80p' static/playground/index.html || true
    echo
  else
    echo "NO static/playground/index.html file"
  fi
else
  echo "NO static/playground directory"
fi
echo

echo "================= NGINX + SYSTEMD (quick pointers) ================="
echo "(this just lists candidate files; paste contents separately if needed)"
ls -1 /etc/systemd/system | sed -n '1,50p' 2>/dev/null || true
echo
ls -1 /etc/nginx/sites-enabled /etc/nginx/conf.d 2>/dev/null || true
echo

echo "DONE."
