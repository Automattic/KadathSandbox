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
