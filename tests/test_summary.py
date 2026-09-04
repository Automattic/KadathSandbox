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
