#!/bin/sh
# Packet capture from *inside* the sandbox network namespace (network_mode: service:wpnet).
#
# Why here and not on the gateway: a capture on the gateway's veth only ever sees
# traffic addressed to the gateway. Sandbox->db (172.30.0.3) and sandbox->host
# (172.30.0.1, mgmt bridge) unicast never appears there, so a gateway-side drop log
# both misses real escape attempts and reports permitted db traffic as a false drop.
#
# This container shares only the network namespace with `wordpress`. It has its own
# PID and mount namespaces, so the sample can neither see nor signal these tcpdumps,
# and it has no mount of /artifacts.
set -eu

INT="$(ip -o -4 addr show | awk '$4 ~ /^172\.30\.0\.10\// {print $2}' | head -n1)"
MGMT="$(ip -o -4 addr show | awk '$4 ~ /^172\.31\.0\.10\// {print $2}' | head -n1)"

if [ -z "$INT" ] || [ -z "$MGMT" ]; then
  echo "FATAL: interfaces not found (internal='$INT' mgmt='$MGMT')" >&2
  ip -o -4 addr show >&2
  exit 1
fi
echo "netcap: internal=$INT mgmt=$MGMT"

mkdir -p /artifacts/pcap
TS="$(date +%Y%m%d-%H%M%S)"

SANDBOX_INT="172.30.0.10"
SANDBOX_MGMT="172.31.0.10"
GW="172.30.0.2"
DB="172.30.0.3"

# A pure SYN: SYN set, ACK clear. Reply SYN/ACKs and every packet of an established
# conversation are excluded, so one logged line means one connection attempt.
SYN='(tcp[tcpflags] & (tcp-syn|tcp-ack)) == tcp-syn'

# What the sandbox is *allowed* to originate on the internal interface. Everything else
# it sends there is either dropped by netguard or refused by the gateway, and is logged.
ALLOWED="(tcp and dst host $GW and (dst port 80 or dst port 443 or dst port 53)) \
  or (dst port 53 and (tcp or udp)) \
  or (tcp and dst host $DB and dst port 3306)"

DROP_FILTER="ip and not ip6 and src host $SANDBOX_INT and not ($ALLOWED) \
  and ((tcp and $SYN) or udp or (not tcp and not udp))"

# On the mgmt interface the sandbox should only ever answer the analyst's browser.
# Anything it *originates* there is an escape attempt towards the Docker host.
MGMT_FILTER="ip and not ip6 and src host $SANDBOX_MGMT \
  and ((tcp and $SYN) or udp or (not tcp and not udp))"

# No -Z/--relinquish-privileges: cap_drop [ALL] leaves this container without
# CAP_SETUID, so tcpdump cannot setuid even to the uid it already has ("Couldn't change
# to 'root' uid=0 gid=0: Operation not permitted") and exits. Alpine's tcpdump does not
# drop privileges on its own, and this container has nothing but NET_RAW/NET_ADMIN to
# drop anyway.

# 1. Full capture of the internal interface, rotated so a long detonation cannot fill
#    the disk: 20 files of 100 MB, oldest overwritten. Rotation appends a slice number,
#    so the files are sandbox-<ts>.pcap00, .pcap01, ...
tcpdump -i "$INT" -U -C 100 -W 20 -w "/artifacts/pcap/sandbox-${TS}.pcap" \
  >/dev/null 2>&1 &

# 2. Human-readable log of everything the sandbox sent that it was not supposed to.
tcpdump -i "$INT" -l -nn -tttt "$DROP_FILTER" >> /artifacts/dropped.log 2>/dev/null &

# 3. Same, on the management interface, tagged so the two are distinguishable.
tcpdump -i "$MGMT" -l -nn -tttt "$MGMT_FILTER" 2>/dev/null \
  | awk '{ print "mgmt " $0; fflush() }' >> /artifacts/dropped.log &

# Give tcpdump a moment to fail loudly (bad filter, missing interface) rather than
# leaving the healthcheck to discover it 30 seconds later.
sleep 2
running="$(pgrep -xc tcpdump || true)"
if [ "$running" != 3 ]; then
  echo "FATAL: expected 3 tcpdump processes, have ${running:-0}" >&2
  exit 1
fi
echo "netcap: 3 captures running (pcap+drop on $INT, drop on $MGMT)"

wait
