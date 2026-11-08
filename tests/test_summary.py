from kadath import summary

def _db():
    return {"users_added": [{"id": 3, "login": "sys_maint", "email": "s@x", "roles": ["administrator"]}],
            "users_removed": [], "users_role_changed": [],
            "options_added": [{"name": "_evil", "value": "1"}], "options_changed": [],
            "cron_added": [{"hook": "beacon", "next_run": "..."}]}

def _net(observed):
    return {"dns": ["evil.example"] if observed else [],
            "flows": [{"host": "evil.example", "method": "GET", "path": "/", "status": 200, "wp_core": False}] if observed else [],
            "dropped": []}

def test_summary_shape():
    s = summary.build_summary(
        sample={"filename": "x.php", "sha256": "a"*64, "type": "plugin"},
        run={"epoch": 1, "utc": "t", "slug": "x", "trigger_actions": [], "reset": False},
        db_diff=_db(), callchain=[{"function": "wp_create_user", "file": "/samples/x", "line": 1}],
        dangerous=[], files_written=[{"op": "file_put_contents", "path": "/tmp/x", "caller": "x:1"}],
        network=_net(True), artifacts={"traces": ["t.xt"], "sp_dumps": [], "pcaps": []}, warnings=[])
    assert s["db_diff"]["users_added"][0]["login"] == "sys_maint"
    assert s["network"]["flows"][0]["host"] == "evil.example"

def test_iocs_conform_and_network_observed():
    i = summary.build_iocs(
        sample={"filename": "x.php", "sha256": "a"*64, "md5": "b"*32, "size_bytes": 10},
        run_utc="t", classification="wp-backdoor",
        db_diff=_db(), files_written=[{"op": "file_put_contents", "path": "/tmp/x", "caller": "x:1"}],
        network=_net(True), credentials=[{"login": "sys_maint", "password": "ChangeMe_Str0ng!"}])
    summary.validate_iocs(i)
    assert i["network"]["observed"] is True
    types = {ind["type"] for ind in i["indicators"]}
    assert {"wp_user", "wp_password", "wp_option", "wp_cron_hook", "file_path", "domain"} <= types

def test_iocs_network_not_observed_when_only_wpcore():
    i = summary.build_iocs(
        sample={"filename": "x.php", "sha256": "a"*64, "md5": "b"*32, "size_bytes": 10},
        run_utc="t", classification="c", db_diff=_db(), files_written=[],
        network={"dns": ["api.wordpress.org"], "flows": [{"host": "api.wordpress.org", "method": "POST", "path": "/x", "status": 200, "wp_core": True}], "dropped": []},
        credentials=[])
    assert i["network"]["observed"] is False

def _iocs(network):
    return summary.build_iocs(
        sample={"filename": "x.php", "sha256": "a"*64, "md5": "b"*32, "size_bytes": 10},
        run_utc="t", classification="c", db_diff=_db(), files_written=[],
        network=network, credentials=[])

def test_iocs_errored_flow_keeps_url_with_attempt_note():
    i = _iocs({"dns": [], "dropped": [], "flows": [
        {"host": "dead.example", "method": "GET", "path": "/x", "status": None,
         "error": "Connection refused", "wp_core": False}]})
    u = [x for x in i["indicators"] if x["type"] == "url"][0]
    assert u["value"] == "dead.example/x"
    assert u["notes"] == "GET (connect failed: Connection refused)"
    assert i["network"]["observed"] is True

def test_iocs_ok_flow_notes_unchanged():
    i = _iocs({"dns": [], "dropped": [], "flows": [
        {"host": "e.example", "method": "POST", "path": "/", "status": 200, "error": None, "wp_core": False}]})
    assert [x for x in i["indicators"] if x["type"] == "url"][0]["notes"] == "POST"

def test_iocs_ip_is_bare_address_port_in_notes():
    i = _iocs({"dns": [], "flows": [], "dropped": [{"dst": "1.1.1.1", "port": 6667}]})
    ip = [x for x in i["indicators"] if x["type"] == "ip"][0]
    assert ip["value"] == "1.1.1.1"
    assert ip["notes"] == "blocked egress to port 6667"
    assert i["network"]["ips"] == ["1.1.1.1"]


def _spoofed_net():
    return {"dns": [], "dropped": [],
            "flows": [{"host": "api.wordpress.org", "method": "POST", "path": "/x", "status": 200,
                       "error": None, "wp_core": False, "host_spoofed": True, "dst": "6.6.6.6"}]}


def test_spoofed_core_flow_is_an_ip_ioc_and_observed():
    i = summary.build_iocs(
        sample={"filename": "x.php", "sha256": "a"*64, "md5": "b"*32, "size_bytes": 10},
        run_utc="t", classification="c", db_diff=_db(), files_written=[], network=_spoofed_net(), credentials=[])
    assert i["network"]["observed"] is True and i["network"]["ips"] == ["6.6.6.6"]
    assert i["network"]["urls"] == []
    ips = [x for x in i["indicators"] if x["type"] == "ip"]
    assert ips == [{"type": "ip", "value": "6.6.6.6", "notes": "Host header spoofed as api.wordpress.org",
                    "evidence": "flows.mitm"}]
    assert not any("wordpress.org" in x["value"] for x in i["indicators"])


def test_wp_core_flag_alone_does_not_hide_a_spoofed_flow():
    n = _spoofed_net()
    n["flows"][0]["wp_core"] = True            # inconsistent input: the spoof flag still wins
    assert summary._network_observed(n) is True


def test_truncated_marker_is_not_an_ioc():
    i = summary.build_iocs(
        sample={"filename": "x.php", "sha256": "a"*64, "md5": "b"*32, "size_bytes": 10},
        run_utc="t", classification="c", db_diff=_db(),
        files_written=[{"op": "truncated", "path": "...and 5 more", "caller": ""}],
        network=_net(False), credentials=[])
    assert not any(x["type"] == "file_path" for x in i["indicators"])


def test_dropped_notes_name_the_protocol():
    i = summary.build_iocs(
        sample={"filename": "x.php", "sha256": "a"*64, "md5": "b"*32, "size_bytes": 10},
        run_utc="t", classification="c", db_diff=_db(), files_written=[],
        network={"dns": [], "flows": [], "dropped": [
            {"dst": "1.1.1.1", "port": 6667, "proto": "tcp"},
            {"dst": "9.9.9.9", "port": 0, "proto": "icmp", "iface": "mgmt"}]}, credentials=[])
    notes = [x["notes"] for x in i["indicators"] if x["type"] == "ip"]
    assert notes == ["blocked egress to port 6667", "blocked egress (icmp) on the management interface"]
