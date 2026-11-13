"""Summarise the network artifacts for one run. Append-only logs (dns, dropped)
are scoped by byte offset captured before the trigger; flows are scoped by
timestamp inside the mitmdump addon."""
import json
import re

_DNS_Q = re.compile(r"query\[[A-Z]+\]\s+(\S+)\s+from")
# dnsmasq: "<id> <client>/<port> reply|cached <name> is <ip | <CNAME> | name>"
_DNS_ANS = re.compile(r"dnsmasq\[\d+\]:\s+(?:(\d+)\s+\S+\s+)?(?:reply|cached)\s+(\S+)\s+is\s+(\S+)\s*$")
_IPV4 = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
# tcpdump -nn -tttt: "IP a.b.c.d[.port] > w.x.y.z[.port]: <what>"
_DROP = re.compile(r"\bIP\s+\d+\.\d+\.\d+\.\d+(?:\.\d+)?\s+>\s+"
                   r"(\d+\.\d+\.\d+\.\d+)(?:\.(\d+))?:\s*(.*)")
_CNAME_DEPTH = 5


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


def _norm(name):
    return (name or "").strip().lower().rstrip(".")


def dns_map_from_log(path, offset=0):
    """name -> set of IPs the gateway's resolver returned, from the dnsmasq
    `reply`/`cached` lines after offset. dnsmasq logs a CNAME hop as
    `<name> is <CNAME>` and the target's own answer on the next line of the
    same query id; hops (and literal `is <name>` targets) are followed up to
    five deep. Names are lowercased, without the trailing dot."""
    direct, alias, last_alias = {}, {}, {}
    for line in _tail(path, offset).splitlines():
        m = _DNS_ANS.search(line)
        if not m:
            continue
        qid, name, val = m.group(1) or "", _norm(m.group(2)), m.group(3)
        pending = last_alias.pop(qid, None)
        if pending and pending != name:
            alias[pending] = name
        if _IPV4.match(val) or ":" in val:
            direct.setdefault(name, set()).add(val)
        elif val.upper() == "<CNAME>":
            last_alias[qid] = name
        else:
            alias[name] = _norm(val)
    out = {}
    for name in set(direct) | set(alias):
        ips, cur = set(), name
        for _ in range(_CNAME_DEPTH + 1):
            ips |= direct.get(cur, set())
            if cur not in alias:
                break
            cur = alias[cur]
        out[name] = ips
    return out


def dropped_from_log(path, offset=0):
    """Blocked-egress attempts: [{"dst", "port", "proto"}] with proto tcp (a
    pure SYN), udp, icmp (port 0) or other (any other IP protocol, port 0);
    a line from the management interface (`mgmt ` prefix) adds "iface":
    "mgmt". Deduplicated per (iface, dst, port, proto)."""
    out = []
    seen = set()
    for line in _tail(path, offset).splitlines():
        mgmt = line.startswith("mgmt ")
        m = _DROP.search(line)
        if not m:
            continue
        dst, port, rest = m.group(1), m.group(2), m.group(3)
        if port is not None:
            if rest.startswith("Flags ["):
                if not re.match(r"Flags \[S\]", rest):
                    continue        # not a pure SYN: part of a conversation already logged
                proto = "tcp"
            else:
                proto = "udp"
            port = int(port)
        else:
            proto = "icmp" if rest.startswith("ICMP") else "other"
            port = 0
        key = (mgmt, dst, port, proto)
        if key in seen:
            continue
        seen.add(key)
        d = {"dst": dst, "port": port, "proto": proto}
        if mgmt:
            d["iface"] = "mgmt"
        out.append(d)
    return out


def flag_wp_core(host):
    h = (host or "").lower()
    return h == "wordpress.org" or h.endswith(".wordpress.org")


def verify_wp_core(flows, dns_map):
    """Decide wp_core from where the connection really went, not from what the
    sample wrote in its Host header (the proxy does not verify upstream certs,
    so `Host: api.wordpress.org` to 6.6.6.6 would otherwise pass as core). A
    flow is core only if its host looks like wordpress.org, its server IP is
    one the resolver returned for that name, and its SNI (when sent) agrees.
    Otherwise wp_core is False and host_spoofed is True. Sets both keys on
    every flow; returns the list."""
    for f in flows:
        host = f.get("host")
        if not flag_wp_core(host):
            f["wp_core"], f["host_spoofed"] = False, False
            continue
        ips = dns_map.get(_norm(host), set())
        sni = f.get("sni")
        ok = bool(f.get("dst")) and f["dst"] in ips and (not sni or flag_wp_core(sni))
        f["wp_core"], f["host_spoofed"] = ok, not ok
    return flows


def parse_flowdump_checked(text):
    """(flows, bad): the JSON-object lines that parse, and how many that look
    like flows did not."""
    out, bad = [], 0
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                v = json.loads(line)
            except ValueError:
                bad += 1
                continue
            if isinstance(v, dict):
                out.append(v)
            else:
                bad += 1
    return out, bad


def parse_flowdump(text):
    return parse_flowdump_checked(text)[0]
