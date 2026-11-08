"""Compute an at-a-glance verdict from a offering summary.json. Pure; the web
layer returns this so the client does not decide severity."""
from kadath.network import flag_wp_core


def _roles_have_admin(roles):
    return any(str(r).lower() == "administrator" for r in (roles or []))


def compute(summary):
    reasons = []
    db = summary.get("db_diff", {})
    net = summary.get("network", {})

    for u in db.get("users_added", []):
        if _roles_have_admin(u.get("roles")):
            reasons.append(f"administrator '{u.get('login')}' created")
    for u in db.get("users_role_changed", []):
        if _roles_have_admin(u.get("to")):
            reasons.append(f"'{u.get('login')}' promoted to administrator")
    for f in net.get("flows", []):
        if not f.get("wp_core"):
            # WHY: a flow with no response is still an attempt to reach the host.
            if f.get("error"):
                reasons.append(f"outbound HTTP(S) attempt to {f.get('host')} ({f['error']})")
            else:
                reasons.append(f"outbound HTTP(S) to {f.get('host')}")
    for d in net.get("dropped", []):
        reasons.append(f"blocked TCP to {d.get('dst')}:{d.get('port')}")

    if reasons:
        return {"level": "red", "reasons": reasons}

    amber = []
    # WHY: a lookup without a connect is weaker evidence than a flow, so amber.
    for name in net.get("dns", []):
        if not flag_wp_core(name):
            amber.append(f"DNS lookup of {name}")
    if summary.get("dangerous_calls"):
        amber.append(f"{len(summary['dangerous_calls'])} dangerous PHP call(s)")
    if summary.get("files_written"):
        amber.append(f"{len(summary['files_written'])} file(s) written")
    for key, label in (("users_added", "user"), ("users_removed", "user removed"),
                       ("users_role_changed", "role change"), ("options_added", "option"),
                       ("options_changed", "option changed"), ("cron_added", "cron event")):
        n = len(db.get(key, []))
        if n:
            amber.append(f"{n} {label}(s)")
    if amber:
        return {"level": "amber", "reasons": amber}
    return {"level": "green", "reasons": []}
