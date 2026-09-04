#!/usr/bin/env bash
# Acceptance test: proves every observation and containment layer works before real malware is loaded.
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
check() {  # check "<name>" "<shell condition>"
  if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; else echo "FAIL: $1"; fail=$((fail+1)); fi
}

filesize() { [ -f "$1" ] && wc -c < "$1" || echo 0; }  # byte count, 0 if the file doesn't exist yet

# Run PHP inside the sample's own container and namespace. XDEBUG_MODE=off so these
# containment probes do not litter artifacts/xdebug with traces of the test itself.
sandbox_php() { docker compose exec -T -e XDEBUG_MODE=off wordpress php -r "$1" 2>&1; }

# Count SYNs from the sandbox to the database in netcap's capture files, summed over
# every rotation slice. Read from a throwaway netcap container: nothing on the host
# needs tcpdump, and the count comes from the pcap itself, not from a log line.
db_syn_count() {
  docker compose run --rm --no-deps --entrypoint sh netcap -c '
    total=0
    for f in /artifacts/pcap/sandbox-*; do
      [ -f "$f" ] || continue
      c=$(tcpdump -nr "$f" "tcp and src host 172.30.0.10 and dst host 172.30.0.3 and dst port 3306 and (tcp[tcpflags] & (tcp-syn|tcp-ack)) == tcp-syn" 2>/dev/null | wc -l)
      total=$((total + c))
    done
    echo "$total"' 2>/dev/null | tr -dc '0-9'
}

# A dump that names probe.php *and* the system() rule. Merely counting files in
# sp-dumps/ passes on WP-CLI's own install-time base64_decode dumps.
sp_dump_records_probe() {
  for f in artifacts/sp-dumps/sp_dump.*; do
    [ -f "$f" ] || continue
    if grep -q 'probe\.php' "$f" && grep -q 'function("system")' "$f"; then return 0; fi
  done
  return 1
}

cp tests/probe.php samples/webroot/probe.php
trap 'rm -f samples/webroot/probe.php' EXIT
echo "selftest: starting stack"
docker compose up -d --build --wait db gateway wpnet netcap wordpress || { echo "FAIL: stack did not become healthy"; docker compose ps -a; exit 1; }
# Recreate wordpress so the entrypoint links the probe into the webroot.
docker compose up -d --force-recreate --wait wordpress || { echo "FAIL: wordpress did not become healthy after recreate"; docker compose ps -a; exit 1; }

# Exact set of trace files that exist before the probe request, so the trace assertions
# below run against a file this run created rather than whatever `ls -t` happens to
# surface (a leftover newest trace from a previous run would pass for the wrong reason).
before_trace_list=$(ls artifacts/xdebug 2>/dev/null | grep '\.xt$' | sort)
# Snapshot byte offsets of the accumulating log/flow files right before the probe request, so the
# checks below only look at what this run appended, not matches left over from earlier runs.
before_sp=$(filesize artifacts/php/php-error.log)
before_mitm=$(filesize artifacts/mitm/flows.mitm)
before_drop=$(filesize artifacts/dropped.log)
before_dns=$(filesize artifacts/dns/dns.log)

out=$(curl -s --max-time 60 http://127.0.0.1:8088/probe.php)
echo "--- probe output ---"; echo "$out"; echo "--------------------"
sleep 3

after_trace_list=$(ls artifacts/xdebug 2>/dev/null | grep '\.xt$' | sort)
new_traces=$(comm -13 <(printf '%s\n' "$before_trace_list") <(printf '%s\n' "$after_trace_list"))
trace=/dev/null
if [ -n "$new_traces" ]; then
  # Newest of the traces this run created.
  trace=$(printf 'artifacts/xdebug/%s\n' $new_traces | tr '\n' '\0' | xargs -0 ls -t 2>/dev/null | head -n1)
  : "${trace:=/dev/null}"
fi
echo "selftest: probe trace = $trace"

# The exact hostname the probe printed, so the DNS check greps for this run's lookup only.
dns_host=$(grep -o 'selftest-[a-z0-9]*\.invalid' <<<"$out" | head -n1)
: "${dns_host:=NO_HOSTNAME_FOUND_IN_PROBE_OUTPUT}"

route_out=$(docker compose exec -T wpnet ip route)

# --- containment probes, run from inside the sample's container ---------------------
# RFC1918 through the gateway: the sample names the host, mitmproxy does the connecting,
# so this only fails if the gateway itself refuses private destinations (C1).
rfc1918_out=$(sandbox_php 'var_dump(@file_get_contents("http://192.168.0.1/"));')
# Docker host on the internal bridge. netguard DROPs it, so the connect must *time out*;
# without the rule the host answers with an instant RST and this would fail in 0.0s for
# the wrong reason. The elapsed time is what distinguishes dropped from refused.
hostconn_out=$(sandbox_php '$t=microtime(true); $s=@fsockopen("172.30.0.1",9999,$e,$m,3); printf("res=%s errno=%d elapsed=%.2f%s", var_export($s,true), $e, microtime(true)-$t, PHP_EOL);')
hostconn_elapsed=$(sed -n 's/.*elapsed=\([0-9.]*\).*/\1/p' <<<"$hostconn_out" | head -n1)
: "${hostconn_elapsed:=0}"

# Capture completeness: the sandbox->db path is invisible from the gateway's veth, so
# this only passes if capture really happens inside the sandbox namespace (C3).
before_db_syn=$(db_syn_count)
sandbox_php 'for ($i = 0; $i < 5; $i++) { $s = @fsockopen("172.30.0.3", 3306, $e, $m, 3); if ($s) { fclose($s); } usleep(200000); } echo "db connects done", PHP_EOL;' >/dev/null
sleep 3
after_db_syn=$(db_syn_count)
: "${before_db_syn:=x}" "${after_db_syn:=x}"
echo "selftest: db SYNs captured before=$before_db_syn after=$after_db_syn"

check "probe: https via mitmproxy succeeded"        'grep -q "^https: ok" <<<"$out"'
check "probe: raw TCP 6667 was blocked"             'grep -q "^irc: blocked" <<<"$out"'
check "xdebug: new trace file written"              '[ -n "$new_traces" ]'
check "xdebug: this run's trace records system()"   'grep -q "system" "$trace"'
check "xdebug: this run's trace records eval payload" 'grep -q "return 1+1" "$trace"'
check "snuffleupagus: system() logged"              'tail -c +$((before_sp+1)) artifacts/php/php-error.log | grep -q "snuffleupagus.*system"'
check "snuffleupagus: a dump records probe.php calling system()" 'sp_dump_records_probe'
check "mitmproxy: example.com flow recorded"        'tail -c +$((before_mitm+1)) artifacts/mitm/flows.mitm | grep -a -q "example.com"'
check "netcap: SYN to 1.1.1.1:6667 in dropped.log"  'tail -c +$((before_drop+1)) artifacts/dropped.log | grep -q "1\.1\.1\.1\.6667"'
check "dnsmasq: selftest lookup logged"             'tail -c +$((before_dns+1)) artifacts/dns/dns.log | grep -q "$dns_host"'
check "netns: only default route is via gateway"    '[ "$(grep -c "^default" <<<"$route_out")" = 1 ] && grep -q "^default via 172.30.0.2" <<<"$route_out"'
check "netns: OUTPUT policy is DROP"                'docker compose run --rm --no-deps --entrypoint sh netguard -c "iptables -S OUTPUT | grep -q -- \"-P OUTPUT DROP\""'
check "gateway: HTTP to RFC1918 192.168.0.1 refused" 'grep -q "bool(false)" <<<"$rfc1918_out"'
check "netns: TCP to docker host 172.30.0.1:9999 is dropped, not refused" \
      'grep -q "res=false" <<<"$hostconn_out" && awk -v e="$hostconn_elapsed" "BEGIN { exit !(e >= 2.5) }"'
check "netcap: 5 SYNs to the db appear as 5 captured packets" \
      '[ "$before_db_syn" -ge 0 ] 2>/dev/null && [ "$after_db_syn" -ge 0 ] 2>/dev/null && [ "$((after_db_syn - before_db_syn))" -eq 5 ]'

if [ "$fail" -eq 0 ]; then echo "SELFTEST PASSED"; else echo "SELFTEST FAILED ($fail)"; fi
exit "$fail"
