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


def test_amber_on_login_failed():
    v = web_verdict.compute(_summary(run={"login_ok": False}))
    assert v["level"] == "amber"
    assert "admin login failed; the sample ran unauthenticated" in v["reasons"]

def test_login_ok_true_or_absent_is_not_amber():
    assert web_verdict.compute(_summary(run={"login_ok": True}))["level"] == "green"
    assert web_verdict.compute(_summary(run={}))["level"] == "green"

def test_amber_on_wp_restarted():
    v = web_verdict.compute(_summary(run={"wp_restarted": True}))
    assert v["level"] == "amber"
    assert "wordpress container restarted during the run" in v["reasons"]

def test_amber_on_fatal():
    v = web_verdict.compute(_summary(run={"fatal": True}))
    assert v["level"] == "amber"
    assert "PHP fatal during the run" in v["reasons"]

def test_amber_on_warnings_verbatim():
    v = web_verdict.compute(_summary(warnings=["no pcap captured", "trace truncated"]))
    assert v["level"] == "amber"
    assert "warning: no pcap captured" in v["reasons"] and "warning: trace truncated" in v["reasons"]

def test_empty_warnings_is_green():
    assert web_verdict.compute(_summary(warnings=[]))["level"] == "green"

def test_red_beats_coverage_amber():
    f = {"host": "evil.example", "status": 200, "wp_core": False}
    v = web_verdict.compute(_summary(run={"login_ok": False, "fatal": True}, warnings=["w"],
                                     network={"dns": [], "flows": [f], "dropped": []}))
    assert v["level"] == "red"
    assert not any("login" in r or "warning" in r or "fatal" in r for r in v["reasons"])

def test_red_on_spoofed_host_flow():
    f = {"host": "api.wordpress.org", "dst": "6.6.6.6", "host_spoofed": True, "wp_core": False, "status": 200}
    v = web_verdict.compute(_summary(network={"dns": [], "flows": [f], "dropped": []}))
    assert v["level"] == "red"
    assert v["reasons"] == ["outbound HTTP(S) to 6.6.6.6 with a spoofed Host header 'api.wordpress.org'"]

def test_spoofed_host_without_dst_uses_question_mark():
    f = {"host": "x.example", "host_spoofed": True, "wp_core": False}
    v = web_verdict.compute(_summary(network={"dns": [], "flows": [f], "dropped": []}))
    assert v["reasons"] == ["outbound HTTP(S) to ? with a spoofed Host header 'x.example'"]

def test_missing_sections_do_not_crash():
    assert web_verdict.compute({})["level"] == "green"
    assert web_verdict.compute({"db_diff": None, "network": None, "run": None})["level"] == "green"
