"""Summarise the network artifacts for one run. Append-only logs (dns, dropped)
are scoped by byte offset captured before the trigger; flows are scoped by
timestamp inside the mitmdump addon."""
import json
import re

_DNS_Q = re.compile(r"query\[[A-Z]+\]\s+(\S+)\s+from")
_DROP = re.compile(r"IP\s+\S+\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):\s+Flags\s+\[S\]")


def _tail(path, offset):
    with open(path, "r", errors="replace") as f:
        f.seek(offset)
        return f.read()


def dns_from_log(path, offset=0):
    names = []
    seen = set()
    for line in _tail(path, offset).splitlines():
        m = _DNS_Q.search(line)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            names.append(m.group(1))
    return names


def dropped_from_log(path, offset=0):
    out = []
    seen = set()
    for line in _tail(path, offset).splitlines():
        m = _DROP.search(line)
        if m:
            key = (m.group(1), int(m.group(2)))
            if key not in seen:
                seen.add(key)
                out.append({"dst": m.group(1), "port": int(m.group(2))})
    return out


def flag_wp_core(host):
    h = (host or "").lower()
    return h == "wordpress.org" or h.endswith(".wordpress.org")


def parse_flowdump(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            out.append(json.loads(line))
    return out
