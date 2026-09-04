from kadath import dbdiff

def _state(users, options, cron):
    import json
    return dbdiff.state_from_json(json.dumps(users), json.dumps(options), json.dumps(cron))

def test_user_added_and_role_change_and_option_and_cron():
    before = _state(
        [{"ID": 1, "user_login": "admin", "user_email": "a@x", "roles": "administrator"},
         {"ID": 2, "user_login": "bob", "user_email": "b@x", "roles": "subscriber"}],
        [{"option_name": "siteurl", "option_value": "http://x"}],
        [{"hook": "wp_version_check", "next_run_gmt": "2026-09-05 00:00:00"}],
    )
    after = _state(
        [{"ID": 1, "user_login": "admin", "user_email": "a@x", "roles": "administrator"},
         {"ID": 2, "user_login": "bob", "user_email": "b@x", "roles": "administrator"},
         {"ID": 3, "user_login": "sys_maint", "user_email": "s@x", "roles": "administrator"}],
        [{"option_name": "siteurl", "option_value": "http://x"},
         {"option_name": "_evil", "option_value": "1"}],
        [{"hook": "wp_version_check", "next_run_gmt": "2026-09-05 00:00:00"},
         {"hook": "evil_beacon", "next_run_gmt": "2026-09-04 20:00:00"}],
    )
    d = dbdiff.diff(before, after)
    assert [u["login"] for u in d["users_added"]] == ["sys_maint"]
    assert d["users_added"][0]["roles"] == ["administrator"]
    assert d["users_removed"] == []
    assert d["users_role_changed"] == [{"login": "bob", "from": ["subscriber"], "to": ["administrator"]}]
    assert [o["name"] for o in d["options_added"]] == ["_evil"]
    assert d["options_changed"] == []
    assert [c["hook"] for c in d["cron_added"]] == ["evil_beacon"]
