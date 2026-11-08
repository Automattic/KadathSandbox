"""Compute an at-a-glance verdict from a offering summary.json. Pure; the web
layer returns this so the client does not decide severity."""
from kadath.network import flag_wp_core


def _roles_have_admin(roles):
    return any(str(r).lower() == "administrator" for r in (roles or []))


def compute(summary):
    reasons = []
    db = summary.get("db_diff") or {}
    net = summary.get("network") or {}
    run = summary.get("run") or {}

    for u in db.get("users_added") or []:
        if _roles_have_admin(u.get("roles")):
            reasons.append(f"administrator '{u.get('login')}' created")
    for u in db.get("users_role_changed") or []:
        if _roles_have_admin(u.get("to")):
            reasons.append(f"'{u.get('login')}' promoted to administrator")
    for f in net.get("flows") or []:
        if f.get("host_spoofed"):
            reasons.append(f"outbound HTTP(S) to {f.get('dst') or '?'} "
                           f"with a spoofed Host header '{f.get('host')}'")
        elif not f.get("wp_core"):
            # WHY: a flow with no response is still an attempt to reach the host.
            if f.get("error"):
                reasons.append(f"outbound HTTP(S) attempt to {f.get('host')} ({f['error']})")
            else:
                reasons.append(f"outbound HTTP(S) to {f.get('host')}")
    for d in net.get("dropped") or []:
        proto = str(d.get("proto") or "tcp").upper()
        where = f"{d.get('dst')}" if proto == "ICMP" else f"{d.get('dst')}:{d.get('port')}"
        reasons.append(f"blocked {proto} to {where}")

    if reasons:
        return {"level": "red", "reasons": reasons}

    amber = []
    # WHY: coverage gaps fail closed: a run that was blind or unauthenticated
    # must not read as green.
    if run.get("login_ok") is False:
        amber.append("admin login failed; the sample ran unauthenticated")
    if run.get("wp_restarted"):
        amber.append("wordpress container restarted during the run")
    if run.get("fatal"):
        amber.append("PHP fatal during the run")
    for w in summary.get("warnings") or []:
        amber.append(f"warning: {w}")
    # WHY: a lookup without a connect is weaker evidence than a flow, so amber.
    for name in net.get("dns") or []:
        if not flag_wp_core(name):
            amber.append(f"DNS lookup of {name}")
    if summary.get("dangerous_calls"):
        amber.append(f"{len(summary['dangerous_calls'])} dangerous PHP call(s)")
    written = [f for f in summary.get("files_written") or [] if f.get("op") != "truncated"]
    if written:
        n = len(written)
        if any(f.get("op") == "truncated" for f in summary.get("files_written") or []):
            amber.append(f"more than {n} file(s) written (list truncated)")
        else:
            amber.append(f"{n} file(s) written")
    for key, label in (("users_added", "user"), ("users_removed", "user removed"),
                       ("users_role_changed", "role change"), ("options_added", "option"),
                       ("options_changed", "option changed"), ("cron_added", "cron event")):
        n = len(db.get(key) or [])
        if n:
            amber.append(f"{n} {label}(s)")
    if amber:
        return {"level": "amber", "reasons": amber}
    return {"level": "green", "reasons": []}
