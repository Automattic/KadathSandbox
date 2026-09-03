#!/bin/sh
# Runs once inside the wpnet network namespace with NET_ADMIN.
# Forces all egress via the gateway and pins a firewall the sample cannot change.
set -eu

GW="172.30.0.2"
INT="$(ip -o -4 addr show | awk '$4 ~ /^172\.30\.0\./ {print $2}')"
MGMT="$(ip -o -4 addr show | awk '$4 ~ /^172\.31\.0\./ {print $2}')"

if [ -z "$INT" ] || [ -z "$MGMT" ]; then
  echo "FATAL: interfaces not found (internal='$INT' mgmt='$MGMT')" >&2
  ip -o -4 addr show >&2
  exit 1
fi

# 1. Only one way out: the gateway on the internal network.
ip route replace default via "$GW" dev "$INT"

# 2. Netns firewall. Default deny in every direction.
iptables -F
iptables -t nat -F
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# The analyst's browser, arriving through Docker's published port.
iptables -A INPUT  -i "$MGMT" -p tcp --dport 8080 -m conntrack --ctstate NEW -j ACCEPT
# Everything the sample originates must leave on the internal interface (gateway, db).
iptables -A OUTPUT -o "$INT" -j ACCEPT

echo "netguard: internal=$INT mgmt=$MGMT"
ip route
iptables -S
