#!/usr/bin/env bash
# Real end-to-end for the web UI. Needs the stack (make up) and python3.
# Starts the server on an ephemeral port, offers tests/probe.php through it,
# polls to done, and checks the report. Skips if Docker is unavailable.
set -uo pipefail
cd "$(dirname "$0")/.."
if ! docker info >/dev/null 2>&1; then echo "SKIP: docker unavailable"; exit 0; fi

PORT=8097
LOG=$(mktemp "${TMPDIR:-/tmp}/kadath-web.XXXXXX")
# setsid (not on macOS by default) puts the server in its own process group.
# The engine runs in a session of its own, so also kill the whole descendant tree.
kill_tree() {
  local c
  for c in $(pgrep -P "$1" 2>/dev/null); do kill_tree "$c"; done
  kill "$1" 2>/dev/null
}
cleanup() {
  [ -n "${WEB_PID:-}" ] || return 0
  kill_tree "$WEB_PID"
  [ -n "${HAVE_SETSID:-}" ] && kill -- "-$WEB_PID" 2>/dev/null
  rm -f "$LOG"
}
trap cleanup EXIT
if command -v setsid >/dev/null 2>&1; then
  HAVE_SETSID=1
  setsid python3 bin/kadath web --port "$PORT" >"$LOG" 2>&1 &
else
  python3 bin/kadath web --port "$PORT" >"$LOG" 2>&1 &
fi
WEB_PID=$!
for _ in $(seq 1 20); do
  curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break
  sleep 0.5
done

CSRF=$(curl -s "http://127.0.0.1:$PORT/" | grep -o 'name="csrf" value="[^"]*"' | sed 's/.*value="//; s/"//')
[ -n "$CSRF" ] || { echo "FAIL: no csrf token"; exit 1; }

JOB=$(curl -s -F "csrf=$CSRF" -F "sample=@tests/probe.php" "http://127.0.0.1:$PORT/run" | python3 -c "import sys,json;print(json.load(sys.stdin)['job_id'])")
[ -n "$JOB" ] || { echo "FAIL: no job id"; exit 1; }

for _ in $(seq 1 180); do
  STATE=$(curl -s "http://127.0.0.1:$PORT/status/$JOB" | python3 -c "import sys,json;print(json.load(sys.stdin)['state'])")
  [ "$STATE" != "running" ] && break
  sleep 2
done
[ "$STATE" = "done" ] || { echo "FAIL: state=$STATE"; exit 1; }

curl -s "http://127.0.0.1:$PORT/report/$JOB" | python3 -c "
import sys,json; r=json.load(sys.stdin)
assert r['summary']['callchain'], 'empty callchain'
assert r['verdict']['level'] in ('red','amber','green'), 'no verdict'
print('E2E PASSED: verdict', r['verdict']['level'])
" || { echo "FAIL: report check"; exit 1; }
