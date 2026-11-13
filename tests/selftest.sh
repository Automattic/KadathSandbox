#!/usr/bin/env bash
# Acceptance test: proves every observation and containment layer works before real malware is loaded.
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
total=0
check() {  # check "<name>" "<shell condition>"
  total=$((total+1))
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

# A dump written *after* the probe request that names probe.php *and* the system() rule.
# Merely counting files in sp-dumps/ passes on WP-CLI's own install-time base64_decode dumps, and
# a leftover probe dump from an earlier run would pass for the wrong reason. Snuffleupagus names a
# dump by a hash that does NOT change between requests (the same call site overwrites the same
# file), but the body carries REQUEST_TIME_FLOAT, so "new" means "a checksum not seen before".
sp_dump_sums() { cksum artifacts/sp-dumps/sp_dump.* 2>/dev/null | awk '{ print $1 "-" $2 }' | sort; }
sp_dump_records_probe() {
  local f
  for f in artifacts/sp-dumps/sp_dump.*; do
    [ -f "$f" ] || continue
    grep -qxF "$(cksum "$f" | awk '{ print $1 "-" $2 }')" <<<"$before_sp_dumps" && continue
    if grep -q 'probe\.php' "$f" && grep -q 'function("system")' "$f"; then return 0; fi
  done
  return 1
}

# Packet counter (column 1) of the first rule in chain $1 (listed with -x, so no K/M suffix)
# whose line satisfies the awk condition $2, read in the gateway's own namespace. 0 if absent.
gw_counter() {  # gw_counter <chain> <awk-condition>
  docker compose exec -T gateway iptables -nvxL "$1" 2>/dev/null | awk "$2 { print \$1; found=1; exit } END { if (!found) print 0 }"
}
# Non-local unicast arriving at the gateway (the sandbox's 1.1.1.1:853 SYNs: only 80/443/53 are
# REDIRECTed to local sockets) is discarded by the routing step because ip_forward is 0, before
# any iptables INPUT or FORWARD chain sees it -- so neither policy counter moves, and the kernel's
# own Ip InAddrErrors counter is where the drop shows up.
gw_inaddr_errors() {
  docker compose exec -T gateway awk '/^Ip:/ { if (!h) { for (i = 1; i <= NF; i++) if ($i == "InAddrErrors") c = i; h = 1 } else { print $c; exit } }' /proc/net/snmp 2>/dev/null
}
# Same, for netguard's OUTPUT rule that drops broadcast/multicast/anycast. netguard shares
# wpnet's namespace (network_mode), so a throwaway run of it sees the sandbox's counters.
ng_bcast_drop() {
  docker compose run --rm --no-deps --entrypoint iptables netguard -nvxL OUTPUT 2>/dev/null \
    | awk '/ADDRTYPE match dst-type BROADCAST/ { print $1; found=1; exit } END { if (!found) print 0 }'
}

cp tests/probe.php samples/webroot/probe.php
# Best-effort: also remove the .user.ini the php checks plant in the docroot (a volume, so it would persist).
trap 'rm -f samples/webroot/probe.php; docker compose exec -T wordpress rm -f /var/www/html/.user.ini >/dev/null 2>&1 || true' EXIT
echo "selftest: starting stack"
docker compose up -d --build --wait db gateway wpnet netcap wordpress || { echo "FAIL: stack did not become healthy"; docker compose ps -a; exit 1; }
# Recreate wordpress so the entrypoint links the probe into the webroot.
docker compose up -d --force-recreate --wait wordpress || { echo "FAIL: wordpress did not become healthy after recreate"; docker compose ps -a; exit 1; }

# Plant a .user.ini in the docroot as uid 33, exactly as a sample could. It tries to repoint
# error_log and prepend a file, and sets precision (pinned nowhere, so only user_ini.filename=
# keeps it at 14); the probe below must report the pinned error_log and precision 14.
docker compose exec -T wordpress sh -c 'printf "error_log=/dev/null\nauto_prepend_file=/dev/null\nprecision=3\n" > /var/www/html/.user.ini' \
  || { echo "FAIL: could not drop .user.ini into the docroot"; fail=$((fail+1)); }

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
before_sp_dumps=$(sp_dump_sums)
before_inaddr=$(gw_inaddr_errors)

out=$(curl -s --max-time 60 http://127.0.0.1:8088/probe.php)
echo "--- probe output ---"; echo "$out"; echo "--------------------"
sleep 3
after_inaddr=$(gw_inaddr_errors)

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
before_reject=$(gw_counter OUTPUT '/REJECT/ && $9 == "192.168.0.0/16"')
rfc1918_out=$(sandbox_php 'var_dump(@file_get_contents("http://192.168.0.1/"));')
after_reject=$(gw_counter OUTPUT '/REJECT/ && $9 == "192.168.0.0/16"')
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

# A connection straight to the proxy port (not REDIRECTed) must be dropped by the gateway:
# un-NATed, mitmproxy reads its own address as the original destination and loops on itself.
proxyport_out=$(sandbox_php '$s=@fsockopen("172.30.0.2",8080,$e,$m,3); echo $s ? "connected" : "blocked", PHP_EOL; if ($s) { fclose($s); }')
# WordPress's HTTP API verifies TLS against its own bundle; the entrypoint appends the
# mitmproxy CA to it so wp_remote_get() C2 traffic is decrypted like everything else.
wp_https_out=$(docker compose exec -T -e XDEBUG_MODE=off wordpress wp eval '$r = wp_remote_get("https://www.iana.org/", ["timeout" => 15]); echo is_wp_error($r) ? "WP_Error: " . $r->get_error_message() : "ok " . wp_remote_retrieve_response_code($r);' 2>&1 | tail -n1)
echo "selftest: wp_remote_get -> $wp_https_out"

# IPv6 and forwarding state, and the broadcast/multicast drop.
inet6_out=$(docker compose exec -T wpnet sh -c 'cat /proc/net/if_inet6; echo "rc=$?"' 2>&1)
fwd_out=$(docker compose exec -T gateway cat /proc/sys/net/ipv4/ip_forward 2>&1 | tr -d '[:space:]')
# so_broadcast lets the datagram reach netfilter (without it send() fails EACCES in the kernel
# before any rule sees it); the multicast one needs no option. Both end at the OUTPUT DROP rule.
before_bcast=$(ng_bcast_drop)
sandbox_php '$c = stream_context_create(["socket" => ["so_broadcast" => true]]); foreach (["udp://255.255.255.255:5353", "udp://224.0.0.251:5353"] as $u) { $s = @stream_socket_client($u, $e, $m, 2, STREAM_CLIENT_CONNECT, $c); if ($s) { @fwrite($s, "x"); fclose($s); } } echo "bcast done", PHP_EOL;' >/dev/null
after_bcast=$(ng_bcast_drop)
echo "selftest: broadcast/multicast DROP counter before=$before_bcast after=$after_bcast; gateway Ip InAddrErrors before=$before_inaddr after=$after_inaddr; RFC1918 REJECT before=$before_reject after=$after_reject"

# Informational, not a pass/fail: a child interpreter the sample starts is outside the pool pins and
# Xdebug (php -n loads no ini at all). The README documents this limit; this line shows it is true.
child_out=$(docker compose exec -T -u 33 wordpress php -n -r 'echo 1;' 2>&1)
echo "INFO: known limit -- error_reporting(0) and @ still work inside php-fpm (the pin only stops ini_set/.user.ini): $(grep '^error_reporting after' <<<"$out")"
echo "INFO: known limit -- uid 33 can run 'php -n' (child interpreter: no pool pins, no Xdebug); output='$child_out'"

check "probe: https via mitmproxy succeeded"        'grep -q "^https: ok" <<<"$out"'
check "probe: raw TCP 1.1.1.1:853 (open on the internet) was blocked" 'grep -q "^dot: blocked" <<<"$out"'
check "gateway: the 1.1.1.1:853 SYNs reached it and were discarded, not forwarded" '[ "${after_inaddr:-0}" -gt "${before_inaddr:-0}" ] 2>/dev/null'
check "php: observation ini keys are pinned (ini_set fails)" 'grep -q "^ini-pinned: yes" <<<"$out"'
check "php: error_reporting is pinned to E_ALL (32767, not 0)" 'grep -q "^error_reporting: 32767" <<<"$out"'
check "php: a .user.ini in the docroot is ignored"  'grep -q "^error_log: /var/log/sandbox/php/php-error.log" <<<"$out" && grep -q "^precision: 14" <<<"$out"'
check "xdebug: new trace file written"              '[ -n "$new_traces" ]'
check "xdebug: this run's trace records system()"   'grep -q "system" "$trace"'
check "xdebug: this run's trace records eval payload" 'grep -q "return 1+1" "$trace"'
check "snuffleupagus: system() logged"              'tail -c +$((before_sp+1)) artifacts/php/php-error.log | grep -q "snuffleupagus.*system"'
check "snuffleupagus: a NEW dump records probe.php calling system()" 'sp_dump_records_probe'
check "mitmproxy: probe's example.com flow recorded" 'tail -c +$((before_mitm+1)) artifacts/mitm/flows.mitm | grep -a -q "example\.com"'
check "mitmproxy: wp_remote_get's www.iana.org flow recorded" 'tail -c +$((before_mitm+1)) artifacts/mitm/flows.mitm | grep -a -q "www\.iana\.org"'
check "netcap: SYN to 1.1.1.1:853 in dropped.log"   'tail -c +$((before_drop+1)) artifacts/dropped.log | grep -q "1\.1\.1\.1\.853"'
check "dnsmasq: selftest lookup logged"             'tail -c +$((before_dns+1)) artifacts/dns/dns.log | grep -q "$dns_host"'
check "netns: only default route is via gateway"    '[ "$(grep -c "^default" <<<"$route_out")" = 1 ] && grep -q "^default via 172.30.0.2" <<<"$route_out"'
check "netns: OUTPUT policy is DROP"                'docker compose run --rm --no-deps --entrypoint sh netguard -c "iptables -S OUTPUT | grep -q -- \"-P OUTPUT DROP\""'
check "gateway: HTTP to RFC1918 192.168.0.1 refused" 'grep -q "bool(false)" <<<"$rfc1918_out"'
check "gateway: the 192.168.0.0/16 REJECT rule's counter rose" '[ "${after_reject:-0}" -gt "${before_reject:-0}" ] 2>/dev/null'
check "gateway: direct connection to the proxy port is dropped" 'grep -q "^blocked" <<<"$proxyport_out"'
check "wordpress: wp_remote_get over https is decrypted (WP trusts the proxy CA)" 'grep -q "^ok 200" <<<"$wp_https_out"'
check "netns: TCP to docker host 172.30.0.1:9999 is dropped, not refused" \
      'grep -q "res=false" <<<"$hostconn_out" && awk -v e="$hostconn_elapsed" "BEGIN { exit !(e >= 2.5) }"'
check "netcap: 5 SYNs to the db appear as 5 captured packets" \
      '[ "$before_db_syn" -ge 0 ] 2>/dev/null && [ "$after_db_syn" -ge 0 ] 2>/dev/null && [ "$((after_db_syn - before_db_syn))" -eq 5 ]'

check "netns: IPv6 is off (/proc/net/if_inet6 is empty)" '[ "$inet6_out" = "rc=0" ]'
check "gateway: ip_forward is 0" '[ "$fwd_out" = 0 ]'
check "netguard: broadcast + multicast datagrams hit the OUTPUT DROP rule" '[ "${after_bcast:-0}" -ge "$(( ${before_bcast:-0} + 2 ))" ] 2>/dev/null'

if [ "$fail" -eq 0 ]; then echo "SELFTEST PASSED ($total checks)"; else echo "SELFTEST FAILED ($fail of $total)"; fi
exit "$fail"
