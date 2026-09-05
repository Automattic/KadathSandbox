#!/usr/bin/env bash
# Real end-to-end for the web UI. Needs the stack (make up) and python3.
# Starts the server on an ephemeral port, detonates tests/probe.php through it,
# polls to done, and checks the report. Skips if Docker is unavailable.
set -uo pipefail
cd "$(dirname "$0")/.."
if ! docker info >/dev/null 2>&1; then echo "SKIP: docker unavailable"; exit 0; fi

PORT=8097
python3 bin/kadath web --port "$PORT" >/tmp/kadath-web.log 2>&1 &
WEB_PID=$!
trap 'kill $WEB_PID 2>/dev/null' EXIT
sleep 2

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
