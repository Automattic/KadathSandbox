"""Compute an at-a-glance verdict from a offering summary.json. Pure; the web
layer returns this so the client does not decide severity."""


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
            reasons.append(f"outbound HTTP(S) to {f.get('host')}")
    for d in net.get("dropped", []):
        reasons.append(f"blocked TCP to {d.get('dst')}:{d.get('port')}")

    if reasons:
        return {"level": "red", "reasons": reasons}

    amber = []
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
