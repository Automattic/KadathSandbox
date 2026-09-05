"""Assemble summary.json and iocs.json from the component outputs."""


def build_summary(sample, run, db_diff, callchain, dangerous, files_written,
                  network, artifacts, warnings):
    return {
        "sample": sample, "run": run, "db_diff": db_diff,
        "callchain": callchain, "dangerous_calls": dangerous,
        "files_written": files_written, "network": network,
        "artifacts": artifacts, "warnings": warnings,
    }


def _network_observed(network):
    if any(not f.get("wp_core") for f in network.get("flows", [])):
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
        add("file_path", f["path"], notes=f["op"], evidence=f["caller"])
    domains, ips, urls = [], [], []
    for n in network.get("dns", []):
        from kadath.network import flag_wp_core
        if not flag_wp_core(n):
            domains.append(n)
            add("domain", n, evidence="dns.log")
    for f in network.get("flows", []):
        if not f.get("wp_core"):
            u = f["host"] + f["path"]
            urls.append(u)
            add("url", u, notes=f["method"], evidence="flows.mitm")
    for d in network.get("dropped", []):
        ips.append(d["dst"])
        add("ip", f"{d['dst']}:{d['port']}", notes="blocked egress", evidence="dropped.log")

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
