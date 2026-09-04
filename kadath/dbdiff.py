"""Diff WordPress DB ground-truth (users/options/cron) captured before and
after the trigger. All inputs come from `wp --skip-plugins ... --format=json`."""
import json
from dataclasses import dataclass


@dataclass
class DbState:
    users: list
    options: list
    cron: list


def _roles(v):
    if isinstance(v, list):
        return v
    return [r.strip() for r in str(v).split(",") if r.strip()]


def state_from_json(users_json, options_json, cron_json):
    return DbState(json.loads(users_json), json.loads(options_json), json.loads(cron_json))


def diff(before, after):
    bu = {u["user_login"]: u for u in before.users}
    au = {u["user_login"]: u for u in after.users}
    users_added = [
        {"id": au[l].get("ID"), "login": l, "email": au[l].get("user_email"),
         "roles": _roles(au[l].get("roles"))}
        for l in au if l not in bu
    ]
    users_removed = [
        {"id": bu[l].get("ID"), "login": l, "email": bu[l].get("user_email"),
         "roles": _roles(bu[l].get("roles"))}
        for l in bu if l not in au
    ]
    users_role_changed = []
    for l in au:
        if l in bu and _roles(bu[l].get("roles")) != _roles(au[l].get("roles")):
            users_role_changed.append(
                {"login": l, "from": _roles(bu[l].get("roles")), "to": _roles(au[l].get("roles"))})

    bo = {o["option_name"]: o.get("option_value") for o in before.options}
    ao = {o["option_name"]: o.get("option_value") for o in after.options}
    options_added = [{"name": n, "value": ao[n]} for n in ao if n not in bo]
    options_changed = [{"name": n, "from": bo[n], "to": ao[n]}
                       for n in ao if n in bo and bo[n] != ao[n]]

    bc = {c["hook"] for c in before.cron}
    cron_added = [{"hook": c["hook"], "next_run": c.get("next_run_gmt")}
                  for c in after.cron if c["hook"] not in bc]

    return {
        "users_added": users_added, "users_removed": users_removed,
        "users_role_changed": users_role_changed,
        "options_added": options_added, "options_changed": options_changed,
        "cron_added": cron_added,
    }
