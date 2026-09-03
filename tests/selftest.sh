#!/usr/bin/env bash
# Acceptance test: proves every observation and containment layer works before real malware is loaded.
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
check() {  # check "<name>" "<shell condition>"
  if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; else echo "FAIL: $1"; fail=$((fail+1)); fi
}

filesize() { [ -f "$1" ] && wc -c < "$1" || echo 0; }  # byte count, 0 if the file doesn't exist yet

cp tests/probe.php samples/webroot/probe.php
trap 'rm -f samples/webroot/probe.php' EXIT
echo "selftest: starting stack"
docker compose up -d --build --wait db gateway wpnet wordpress || { echo "FAIL: stack did not become healthy"; docker compose ps -a; exit 1; }
# Recreate wordpress so the entrypoint links the probe into the webroot.
docker compose up -d --force-recreate --wait wordpress || { echo "FAIL: wordpress did not become healthy after recreate"; docker compose ps -a; exit 1; }

before_traces=$(ls artifacts/xdebug | grep -c '\.xt$')
# Snapshot byte offsets of the accumulating log/flow files right before the probe request, so the
# checks below only look at what this run appended, not matches left over from earlier runs.
before_sp=$(filesize artifacts/php/php-error.log)
before_mitm=$(filesize artifacts/mitm/flows.mitm)
before_drop=$(filesize artifacts/dropped.log)
before_dns=$(filesize artifacts/dns/dns.log)

out=$(curl -s --max-time 60 http://127.0.0.1:8088/probe.php)
echo "--- probe output ---"; echo "$out"; echo "--------------------"
sleep 3

# The exact hostname the probe printed, so the DNS check greps for this run's lookup only.
dns_host=$(grep -o 'selftest-[a-z0-9]*\.invalid' <<<"$out" | head -n1)
: "${dns_host:=NO_HOSTNAME_FOUND_IN_PROBE_OUTPUT}"

route_out=$(docker compose exec -T wpnet ip route)

check "probe: https via mitmproxy succeeded"        'grep -q "^https: ok" <<<"$out"'
check "probe: raw TCP 6667 was blocked"             'grep -q "^irc: blocked" <<<"$out"'
check "xdebug: new trace file written"              '[ "$(ls artifacts/xdebug | grep -c "\.xt$")" -gt "$before_traces" ]'
check "xdebug: latest trace records system()"       'grep -q "system" "$(ls -t artifacts/xdebug/*.xt | head -n1)"'
check "xdebug: latest trace records eval payload"   'grep -q "return 1+1" "$(ls -t artifacts/xdebug/*.xt | head -n1)"'
check "snuffleupagus: system() logged"              'tail -c +$((before_sp+1)) artifacts/php/php-error.log | grep -q "snuffleupagus.*system"'
check "snuffleupagus: dump directory non-empty"     '[ -n "$(ls artifacts/sp-dumps | grep -v \.gitkeep)" ]'
check "mitmproxy: example.com flow recorded"        'tail -c +$((before_mitm+1)) artifacts/mitm/flows.mitm | grep -a -q "example.com"'
check "gateway: SYN to 1.1.1.1:6667 in dropped.log" 'tail -c +$((before_drop+1)) artifacts/dropped.log | grep -q "1\.1\.1\.1\.6667"'
check "dnsmasq: selftest lookup logged"             'tail -c +$((before_dns+1)) artifacts/dns/dns.log | grep -q "$dns_host"'
check "netns: only default route is via gateway"    '[ "$(grep -c "^default" <<<"$route_out")" = 1 ] && grep -q "^default via 172.30.0.2" <<<"$route_out"'
check "netns: OUTPUT policy is DROP"                'docker compose run --rm --no-deps --entrypoint sh netguard -c "iptables -S OUTPUT | grep -q -- \"-P OUTPUT DROP\""'

if [ "$fail" -eq 0 ]; then echo "SELFTEST PASSED"; else echo "SELFTEST FAILED ($fail)"; fi
exit "$fail"
