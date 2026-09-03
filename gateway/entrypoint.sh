#!/bin/bash
# Gateway startup: iptables policy, pcap, drop log, DNS logger, then mitmweb.
set -euo pipefail

INT_IP="172.30.0.2"
INT="$(ip -o -4 addr show | awk -v ip="$INT_IP" '$4 ~ "^"ip"/" {print $2}')"
EGR="$(ip -o -4 addr show | awk -v ifn="$INT" '$2 != "lo" && $2 != ifn {print $2}' | head -n1)"

if [ -z "$INT" ] || [ -z "$EGR" ]; then
  echo "FATAL: could not identify interfaces (internal='$INT' egress='$EGR')" >&2
  ip -o -4 addr show >&2
  exit 1
fi
echo "gateway: internal=$INT egress=$EGR"

mkdir -p /artifacts/pcap /artifacts/mitm /artifacts/dns /gateway-ca
TS="$(date +%Y%m%d-%H%M%S)"

# --- iptables: fail closed. Nothing is forwarded; only mitmproxy/dnsmasq may be reached.
# Only flush PREROUTING (ours) in the nat table -- a full `-t nat -F` also wipes
# Docker's own DOCKER_OUTPUT/DOCKER_POSTROUTING chains and the OUTPUT jump to them,
# which is what makes the embedded resolver at 127.0.0.11 reachable from this container.
iptables -t nat -F PREROUTING
iptables -F
iptables -t nat -A PREROUTING -i "$INT" -p tcp --dport 80  -j REDIRECT --to-ports 8080
iptables -t nat -A PREROUTING -i "$INT" -p tcp --dport 443 -j REDIRECT --to-ports 8080
iptables -t nat -A PREROUTING -i "$INT" -p udp --dport 53  -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -i "$INT" -p tcp --dport 53  -j REDIRECT --to-ports 53
iptables -P FORWARD DROP
iptables -P INPUT DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i "$INT" -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -i "$INT" -p udp --dport 53 -j ACCEPT
iptables -A INPUT -i "$INT" -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -i "$EGR" -p tcp --dport 8081 -j ACCEPT
echo "gateway: iptables installed"
iptables -t nat -S PREROUTING
iptables -S INPUT

# --- full packet capture of the sandbox side
tcpdump -i "$INT" -U -w "/artifacts/pcap/sandbox-${TS}.pcap" >/dev/null 2>&1 &

# --- human-readable log of everything that is not HTTP/HTTPS/DNS (all of it gets dropped)
tcpdump -i "$INT" -l -nn -tttt \
  '(tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn and not dst port 80 and not dst port 443 and not dst port 53) or (udp and not dst port 53) or (not tcp and not udp and not arp)' \
  >> /artifacts/dropped.log 2>/dev/null &

# --- DNS: every lookup from the sandbox is answered here and logged.
# --filter-AAAA: this gateway only intercepts IPv4 (no ip6tables rules, and the
# docker networks here have no IPv6 route out), so a real AAAA answer would either
# fail outbound or, worse, be an uncontrolled egress path around mitmproxy. Return
# NODATA for AAAA so clients fall back to the IPv4 address we actually intercept.
dnsmasq --keep-in-foreground --no-resolv --server=127.0.0.11 --filter-AAAA \
  --listen-address="$INT_IP" --bind-interfaces --no-hosts --cache-size=0 \
  --log-queries=extra --log-facility=/artifacts/dns/dns.log &

# --- mitmweb in transparent mode. The CA lives in the gateway_ca volume so it is stable.
exec mitmweb \
  --mode transparent --showhost \
  --listen-host 0.0.0.0 --listen-port 8080 \
  --set web_host=0.0.0.0 --set web_port=8081 \
  --set web_password="${MITMWEB_PASSWORD:-sandbox}" \
  --set web_open_browser=false \
  --set ssl_insecure=true \
  --set confdir=/gateway-ca \
  -w +/artifacts/mitm/flows.mitm \
  ${MITM_EXTRA_ARGS:-}
