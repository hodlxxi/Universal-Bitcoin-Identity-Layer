#!/usr/bin/env bash
# Run on a Linux test host with PostgreSQL 16 and the project's test dependencies.
set -Eeuo pipefail
umask 077
if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 PATH_TO_TEST_PYTHON PATH_TO_SCHEMA_ONLY_DUMP [PATH_TO_SOCIAL_CHECKOUT]" >&2
  exit 2
fi
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
python=$(realpath -- "$(dirname -- "$1")")/$(basename -- "$1")
dump=$(realpath -- "$2")
social=${3:+$(realpath -- "$3")}
bin=/usr/lib/postgresql/16/bin
[[ -x "$python" && -f "$dump" && -x "$bin/initdb" ]]
if [[ -n "$social" ]]; then
  [[ -f "$social/src/server/social-authority-reader.mjs" ]]
fi
toc=$("$bin/pg_restore" --list "$dump")
if grep -Eq '^[0-9]+;.* (TABLE DATA|BLOBS|BLOB) ' <<<"$toc"; then
  echo 'The rehearsal requires a schema-only dump.' >&2
  exit 2
fi

env -i PATH=/usr/local/bin:/usr/sbin:/usr/bin:/bin LANG=C.UTF-8 \
  TEST_FILTER="${TASK2B_TEST_FILTER:-}" \
  REPO="$repo" TEST_PYTHON="$python" SCHEMA_DUMP="$dump" SOCIAL_CHECKOUT="$social" PG_BIN="$bin" \
  unshare --net --mount --propagation private /bin/bash <<'INNER'
set -Eeuo pipefail
umask 077
ip link set lo up
scratch=$(mktemp -d /tmp/hodlxxi-task2b-release.XXXXXXXX)
mkdir -m 700 "$scratch/pg"
chown postgres:postgres "$scratch/pg"
# postgres must traverse the parent but cannot read the test logs.
chmod 711 "$scratch"
started=0
cleanup() {
  status=$?
  trap - EXIT
  if (( started )); then
    if runuser -u postgres -- "$PG_BIN/pg_ctl" -D "$scratch/pg/data" -m immediate -w stop >>"$scratch/postgres-stop.log" 2>&1; then
      printf 'DISPOSABLE_POSTGRES_STOPPED=YES\n'
    else
      printf 'DISPOSABLE_POSTGRES_STOPPED=CHECK_REQUIRED\n'
      status=1
    fi
  fi
  printf 'EVIDENCE_DIRECTORY=%s\nTEST_EXIT=%s\n' "$scratch" "$status"
  exit "$status"
}
trap cleanup EXIT

port=$("$TEST_PYTHON" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
password=$("$TEST_PYTHON" -c 'import secrets; print(secrets.token_hex(24))')
runuser -u postgres -- "$PG_BIN/initdb" -D "$scratch/pg/data" \
  --auth-local=peer --auth-host=scram-sha-256 --encoding=UTF8 --no-instructions >"$scratch/initdb.log" 2>&1
runuser -u postgres -- "$PG_BIN/pg_ctl" -D "$scratch/pg/data" -l "$scratch/pg/postgres.log" \
  -o "-c listen_addresses=127.0.0.1 -c port=$port -c unix_socket_directories=$scratch/pg -c ssl=off" \
  -w start >"$scratch/postgres-start.log" 2>&1
started=1

sql=(runuser -u postgres -- "$PG_BIN/psql" -Xq -v ON_ERROR_STOP=1 -h "$scratch/pg" -p "$port" -d postgres)
{
  printf "CREATE ROLE canonv2test LOGIN SUPERUSER PASSWORD '%s';\n" "$password"
  printf "CREATE DATABASE canonv2test OWNER postgres;\n"
  printf "COMMENT ON DATABASE canonv2test IS 'hodlxxi-canon-v2-disposable-pg16-v1';\n"
} | "${sql[@]}" >/dev/null

suites=(
  tests/integration/test_automatic_sponsored_import_postgres_v1.py
  tests/integration/test_automatic_sponsored_admission_postgres_v1.py
)
if [[ -n "$SOCIAL_CHECKOUT" ]]; then
  printf '127.0.0.1 localhost ubid-preview.hodlxxi.test\n' >"$scratch/hosts"
  mount --bind "$scratch/hosts" /etc/hosts
  suites+=(tests/integration/test_automatic_sponsored_social_https.py)
fi
suites+=(tests/integration/test_task2b_postgres_release.py)

cd "$REPO"
export PATH="$(dirname "$TEST_PYTHON"):$PATH"
export PYTHONPATH="$REPO" PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
export HOME="$scratch" TMPDIR="$scratch" REDIS_URL="unix://$scratch/no-redis.sock" SOCKETIO_ASYNC_MODE=threading
export CANON_V2_DISPOSABLE_PG_ACK=1 CANON_V2_DISPOSABLE_PG_PORT="$port"
export CANON_V2_TEST_DATABASE_URL="postgresql+psycopg2://canonv2test:$password@127.0.0.1:$port/canonv2test"
export TASK2B_PG_SCHEMA_DUMP="$SCHEMA_DUMP" TASK2B_PG_BIN="$PG_BIN" SOCIAL_AUTHORITY_TEST_CHECKOUT="$SOCIAL_CHECKOUT"
timeout --kill-after=5s 300s "$TEST_PYTHON" -m pytest -q -rP --tb=short -p no:cacheprovider -o addopts='' \
  -k "$TEST_FILTER" "${suites[@]}" |
  tee "$scratch/pytest.log"
INNER
