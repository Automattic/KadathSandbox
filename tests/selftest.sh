#!/usr/bin/env bash
# Acceptance test: proves every observation and containment layer works before real malware is loaded.
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
check() {  # check "<name>" "<shell condition>"
  if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; else echo "FAIL: $1"; fail=$((fail+1)); fi
}

cp tests/probe.php samples/webroot/probe.php
echo "selftest: starting stack"
docker compose up -d --build --wait db gateway wpnet wordpress || { echo "FAIL: stack did not become healthy"; docker compose ps -a; exit 1; }
# Recreate wordpress so the entrypoint links the probe into the webroot.
docker compose up -d --force-recreate --wait wordpress || { echo "FAIL: wordpress did not become healthy after recreate"; exit 1; }

before_traces=$(ls artifacts/xdebug | grep -c '\.xt$')
out=$(curl -s --max-time 60 http://127.0.0.1:8088/probe.php)
echo "--- probe output ---"; echo "$out"; echo "--------------------"
sleep 3

check "probe: https via mitmproxy succeeded"        'grep -q "^https: ok" <<<"$out"'
check "probe: raw TCP 6667 was blocked"             'grep -q "^irc: blocked" <<<"$out"'
check "xdebug: new trace file written"              '[ "$(ls artifacts/xdebug | grep -c "\.xt$")" -gt "$before_traces" ]'
check "xdebug: latest trace records system()"       'grep -q "system" "$(ls -t artifacts/xdebug/*.xt | head -n1)"'
check "xdebug: latest trace records eval payload"   'grep -q "return 1+1" "$(ls -t artifacts/xdebug/*.xt | head -n1)"'
check "snuffleupagus: system() logged"              'grep -q "snuffleupagus.*system" artifacts/php/php-error.log'
check "snuffleupagus: dump directory non-empty"     '[ -n "$(ls artifacts/sp-dumps | grep -v .gitkeep)" ]'
check "mitmproxy: example.com flow recorded"        'grep -a -q "example.com" artifacts/mitm/flows.mitm'
check "gateway: SYN to 1.1.1.1:6667 in dropped.log" 'grep -q "1\.1\.1\.1\.6667" artifacts/dropped.log'
check "dnsmasq: selftest lookup logged"             'grep -q "selftest-" artifacts/dns/dns.log'
check "netns: only default route is via gateway"    '[ "$(docker compose exec -T wpnet ip route | grep -c "^default")" = 1 ] && docker compose exec -T wpnet ip route | grep -q "^default via 172.30.0.2"'
check "netns: OUTPUT policy is DROP"                'docker compose run --rm --no-deps --entrypoint sh netguard -c "iptables -S OUTPUT | grep -q -- \"-P OUTPUT DROP\""'

rm -f samples/webroot/probe.php
if [ "$fail" -eq 0 ]; then echo "SELFTEST PASSED"; else echo "SELFTEST FAILED ($fail)"; fi
exit "$fail"
