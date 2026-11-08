from kadath import web_verdict

def _summary(**over):
    base = {"db_diff": {"users_added": [], "users_removed": [], "users_role_changed": [],
                        "options_added": [], "options_changed": [], "cron_added": []},
            "dangerous_calls": [], "files_written": [],
            "network": {"dns": [], "flows": [], "dropped": []}}
    base.update(over)
    return base

def test_red_on_added_admin():
    s = _summary(db_diff={**_summary()["db_diff"],
                          "users_added": [{"login": "sys_maint", "roles": ["administrator"]}]})
    v = web_verdict.compute(s)
    assert v["level"] == "red"
    assert any("sys_maint" in r for r in v["reasons"])

def test_red_on_non_wpcore_flow():
    s = _summary(network={"dns": [], "flows": [{"host": "evil.example", "wp_core": False}], "dropped": []})
    assert web_verdict.compute(s)["level"] == "red"

def test_red_on_dropped():
    s = _summary(network={"dns": [], "flows": [], "dropped": [{"dst": "1.1.1.1", "port": 6667}]})
    v = web_verdict.compute(s)
    assert v["level"] == "red"
    assert any("6667" in r for r in v["reasons"])

def test_amber_on_files_written_only():
    s = _summary(files_written=[{"op": "file_put_contents", "path": "/tmp/x", "caller": "x:1"}])
    assert web_verdict.compute(s)["level"] == "amber"

def test_amber_on_benign_option_change():
    s = _summary(db_diff={**_summary()["db_diff"], "options_added": [{"name": "_x", "value": "1"}]})
    assert web_verdict.compute(s)["level"] == "amber"

def test_green_on_nothing():
    assert web_verdict.compute(_summary())["level"] == "green"

def test_red_on_errored_flow_with_reason():
    f = {"host": "dead-c2.example", "status": None, "error": "Connection refused", "wp_core": False}
    v = web_verdict.compute(_summary(network={"dns": [], "flows": [f], "dropped": []}))
    assert v["level"] == "red"
    assert "outbound HTTP(S) attempt to dead-c2.example (Connection refused)" in v["reasons"]

def test_errored_wpcore_flow_not_red():
    f = {"host": "api.wordpress.org", "status": None, "error": "timeout", "wp_core": True}
    assert web_verdict.compute(_summary(network={"dns": [], "flows": [f], "dropped": []}))["level"] == "green"

def test_amber_on_dns_only():
    v = web_verdict.compute(_summary(network={"dns": ["googlearticle.net"], "flows": [], "dropped": []}))
    assert v["level"] == "amber"
    assert "DNS lookup of googlearticle.net" in v["reasons"]

def test_dns_wpcore_ignored():
    v = web_verdict.compute(_summary(network={"dns": ["api.wordpress.org"], "flows": [], "dropped": []}))
    assert v["level"] == "green"

def test_red_flow_outranks_dns():
    f = {"host": "evil.example", "status": 200, "wp_core": False}
    v = web_verdict.compute(_summary(network={"dns": ["evil.example"], "flows": [f], "dropped": []}))
    assert v["level"] == "red"
    assert not any(r.startswith("DNS lookup") for r in v["reasons"])
