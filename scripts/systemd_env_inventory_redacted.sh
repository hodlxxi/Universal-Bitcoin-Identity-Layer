#!/usr/bin/env bash
set -euo pipefail

UNIT="${1:-hodlxxi}"
DROPIN_DIR="/etc/systemd/system/${UNIT}.service.d"

if [[ ! -d "$DROPIN_DIR" ]]; then
  echo "error: drop-in directory not found: $DROPIN_DIR" >&2
  exit 1
fi

echo "== ${UNIT} EnvironmentFile refs =="
systemctl cat "$UNIT" \
  | grep -E '^[[:space:]]*EnvironmentFile=' \
  | sed -E 's#(EnvironmentFile=).*#\1<redacted-path>#' \
  || true

echo
echo "== ${UNIT} env file variable names =="
systemctl show "$UNIT" -p EnvironmentFiles \
  | sed 's/^EnvironmentFiles=//' \
  | grep -oE '/[^ ]+' \
  | while IFS= read -r envfile; do
      [[ -z "$envfile" ]] && continue
      if [[ -r "$envfile" ]]; then
        awk -F= '
          /^[A-Za-z_][A-Za-z0-9_]*=/ {print FILENAME ":" $1 "=<redacted>"}
        ' "$envfile"
      else
        echo "$envfile:<unreadable>"
      fi
    done \
  | sort -u

echo
echo "== ${UNIT} direct Environment keys by active drop-in =="
for f in "$DROPIN_DIR"/*.conf; do
  [[ -e "$f" ]] || continue
  awk -v file="$f" '
    /^[[:space:]]*Environment=/ {
      line=$0
      sub(/^[[:space:]]*Environment=/, "", line)
      gsub(/"/, "", line)
      n=split(line, parts, " ")
      for (i=1; i<=n; i++) {
        split(parts[i], kv, "=")
        if (kv[1] ~ /^[A-Za-z_][A-Za-z0-9_]*$/) {
          print file ":" FNR ":" kv[1] "=<redacted>"
        }
      }
    }
  ' "$f"
done | sort

echo
echo "== ${UNIT} disabled/bak drop-ins =="
find "$DROPIN_DIR" -maxdepth 1 -type f \( -name '*.DISABLED' -o -name '*.bak*' \) -print | sort || true
