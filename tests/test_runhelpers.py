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
