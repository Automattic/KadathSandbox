"""Assemble summary.json and iocs.json from the component outputs."""


def build_summary(sample, run, db_diff, callchain, dangerous, files_written,
                  network, artifacts, warnings):
    return {
        "sample": sample, "run": run, "db_diff": db_diff,
        "callchain": callchain, "dangerous_calls": dangerous,
        "files_written": files_written, "network": network,
        "artifacts": artifacts, "warnings": warnings,
    }


def _is_core(flow):
    """The verified flag (network.verify_wp_core): a spoofed Host header is
    never core, whatever wp_core says."""
    return bool(flow.get("wp_core")) and not flow.get("host_spoofed")


def _network_observed(network):
    if any(not _is_core(f) for f in network.get("flows", [])):
        return True
    if network.get("dropped"):
        return True
    from kadath.network import flag_wp_core
    if any(not flag_wp_core(n) for n in network.get("dns", [])):
        return True
    return False


def build_iocs(sample, run_utc, classification, db_diff, files_written,
               network, credentials):
    indicators = []

    def add(t, v, notes=None, evidence=None):
        e = {"type": t, "value": v}
        if notes:
            e["notes"] = notes
        if evidence:
            e["evidence"] = evidence
        indicators.append(e)

    for u in db_diff["users_added"]:
        add("wp_user", u["login"], notes="roles: " + ",".join(u["roles"]), evidence="db_diff")
        if u.get("email"):
            add("wp_user_email", u["email"], evidence="db_diff")
    for c in credentials:
        add("wp_password", c["password"], notes="for " + c["login"], evidence="xdebug trace")
    for o in db_diff["options_added"]:
        add("wp_option", o["name"], evidence="db_diff")
    for c in db_diff["cron_added"]:
        add("wp_cron_hook", c["hook"], evidence="db_diff")
    for f in files_written:
        if f.get("op") == "truncated":      # traceparse's "...and N more" marker
            continue
        add("file_path", f["path"], notes=f["op"], evidence=f["caller"])
    domains, ips, urls = [], [], []
    for n in network.get("dns", []):
        from kadath.network import flag_wp_core
        if not flag_wp_core(n):
            domains.append(n)
            add("domain", n, evidence="dns.log")
    for f in network.get("flows", []):
        if _is_core(f):
            continue
        if f.get("host_spoofed") and f.get("dst"):
            # the Host header names a core host but the connection went elsewhere:
            # the address is the indicator, the claimed name is not
            if f["dst"] not in ips:
                ips.append(f["dst"])
                add("ip", f["dst"], notes=f"Host header spoofed as {f['host']}",
                    evidence="flows.mitm")
        else:
            u = f["host"] + f["path"]
            urls.append(u)
            notes = f["method"]
            if f.get("error"):
                notes += f" (connect failed: {f['error']})"
            add("url", u, notes=notes, evidence="flows.mitm")
    for d in network.get("dropped", []):
        ips.append(d["dst"])
        proto = d.get("proto", "tcp")
        notes = (f"blocked egress to port {d['port']}" if proto == "tcp" else
                 f"blocked egress ({proto}" + (f" port {d['port']}" if d.get("port") else "") + ")")
        if d.get("iface") == "mgmt":
            notes += " on the management interface"
        add("ip", d["dst"], notes=notes, evidence="dropped.log")

    return {
        "sample": sample,
        "offered_utc": run_utc,
        "classification": classification,
        "network": {"observed": _network_observed(network),
                    "domains": domains, "ips": ips, "urls": urls},
        "indicators": indicators,
    }


def validate_iocs(iocs):
    for k in ("sample", "offered_utc", "classification", "network", "indicators"):
        assert k in iocs, f"iocs missing required key: {k}"
    assert "observed" in iocs["network"], "iocs.network missing 'observed'"
    for ind in iocs["indicators"]:
        assert "type" in ind and "value" in ind, "indicator missing type/value"
