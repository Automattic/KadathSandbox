import json
import os
import zipfile
from kadath import stage, detect

def test_clear_samples_keeps_gitkeep(tmp_path):
    root = tmp_path
    for sub in ("plugins", "themes", "webroot"):
        d = root / "samples" / sub
        d.mkdir(parents=True)
        (d / ".gitkeep").write_text("")
    (root / "samples" / "plugins" / "old").mkdir()
    (root / "samples" / "webroot" / "old.php").write_text("x")
    stage.clear_samples(str(root))
    assert (root / "samples" / "plugins" / ".gitkeep").exists()
    assert not (root / "samples" / "plugins" / "old").exists()
    assert not (root / "samples" / "webroot" / "old.php").exists()

def test_place_plugin(tmp_path):
    root = tmp_path
    (root / "samples" / "plugins").mkdir(parents=True)
    src = tmp_path / "p.php"
    src.write_text("<?php\n/* Plugin Name: P */\n")
    d = detect.detect(str(src))
    staged = stage.place(str(root), str(src), d)
    assert os.path.isfile(os.path.join(staged, "p.php"))
    assert d.dest.startswith("samples/plugins/")

def test_isolate_deactivates_and_clears(tmp_path):
    root = tmp_path
    for sub in ("plugins", "themes", "webroot"):
        (root / "samples" / sub).mkdir(parents=True)
        (root / "samples" / sub / ".gitkeep").write_text("")
    (root / "samples" / "plugins" / "evil").mkdir()
    calls = []
    def fake_wp(args):
        calls.append(args)
        if args[:2] == ["plugin", "list"]:
            return "evil\nakismet\n"
        if args[:2] == ["user", "list"]:
            return "1\n8\n"
        return ""
    actions = stage.isolate(str(root), fake_wp)
    assert ["plugin", "deactivate", "evil"] in calls
    assert ["plugin", "deactivate", "akismet"] not in calls
    assert ["user", "delete", "8", "--yes"] in calls
    assert ["user", "delete", "1", "--yes"] not in calls
    assert not (root / "samples" / "plugins" / "evil").exists()

def _make_zip(path, files):
    with zipfile.ZipFile(path, "w") as z:
        for name, content in files.items():
            z.writestr(name, content)

def test_place_zip_wrapped_plugin(tmp_path):
    root = tmp_path; (root / "samples" / "plugins").mkdir(parents=True)
    z = tmp_path / "evil.zip"
    _make_zip(z, {"evil/evil.php": "<?php\n/* Plugin Name: Evil */\n"})
    d = detect.detect(str(z))            # type == "zip", slug == "evil"
    staged = stage.place(str(root), str(z), d)
    # the plugin main file must be exactly one level under samples/plugins/evil
    assert os.path.isfile(os.path.join(root, "samples/plugins/evil/evil.php"))

def test_place_zip_wrapped_theme(tmp_path):
    root = tmp_path; (root / "samples" / "themes").mkdir(parents=True)
    z = tmp_path / "th.zip"
    _make_zip(z, {"th/style.css": "/*\nTheme Name: Th\n*/\n", "th/index.php": "<?php"})
    d = detect.detect(str(z))
    staged = stage.place(str(root), str(z), d)
    assert os.path.isfile(os.path.join(root, "samples/themes/th/style.css"))

def test_place_zip_webshell(tmp_path):
    root = tmp_path; (root / "samples" / "webroot").mkdir(parents=True)
    z = tmp_path / "sh.zip"
    _make_zip(z, {"c99.php": "<?php echo 1;"})
    d = detect.detect(str(z))
    staged = stage.place(str(root), str(z), d)
    assert os.path.isfile(os.path.join(root, "samples/webroot/c99.php"))


def test_clear_run_artifacts_keeps_logs_and_gitkeep(tmp_path):
    from kadath import stage
    root = tmp_path
    for sub in ("xdebug", "sp-dumps", "dns", "pcap"):
        (root / "artifacts" / sub).mkdir(parents=True)
        (root / "artifacts" / sub / ".gitkeep").write_text("")
    (root / "artifacts" / "xdebug" / "trace.1.xt").write_text("t")
    (root / "artifacts" / "sp-dumps" / "sp_dump.abc").write_text("d")
    (root / "artifacts" / "dns" / "dns.log").write_text("q")      # container-held: keep
    (root / "artifacts" / "pcap" / "s.pcap00").write_bytes(b"p")  # container-held: keep
    stage.clear_run_artifacts(str(root))
    assert not (root / "artifacts" / "xdebug" / "trace.1.xt").exists()
    assert not (root / "artifacts" / "sp-dumps" / "sp_dump.abc").exists()
    assert (root / "artifacts" / "xdebug" / ".gitkeep").exists()
    assert (root / "artifacts" / "dns" / "dns.log").exists()      # untouched
    assert (root / "artifacts" / "pcap" / "s.pcap00").exists()    # untouched


def test_adopt_wraps_loose_file_as_plugin(tmp_path):
    src = tmp_path / "1.php"
    src.write_text("<?php\nadd_action('init', 'x');\n")
    d = stage.adopt(str(tmp_path), str(src), "FIO-1")
    assert d == os.path.join(str(tmp_path), ".kadath", "adopt", "FIO-1")
    wrapper = open(os.path.join(d, stage.ADOPT_WRAPPER)).read()
    assert "Plugin Name: kadath-adopted FIO-1" in wrapper
    assert wrapper.index("kadath-shims.php") < wrapper.index("'/sample.php'")
    assert open(os.path.join(d, stage.ADOPT_SHIMS)).read().startswith("<?php")
    assert open(os.path.join(d, stage.ADOPT_SAMPLE)).read() == src.read_text()
    assert not os.path.exists(os.path.join(d, "1.php"))
    assert detect.detect(d).type == "plugin"
    # re-adopting replaces the directory cleanly
    (tmp_path / ".kadath" / "adopt" / "FIO-1" / "stale").write_text("x")
    stage.adopt(str(tmp_path), str(src), "FIO-1")
    assert not os.path.exists(os.path.join(d, "stale"))


def test_adopt_never_interpolates_the_filename(tmp_path):
    evil = tmp_path / "x'; system($_GET[0]); #.php"
    evil.write_text("<?php echo 1;\n")
    d = stage.adopt(str(tmp_path), str(evil), "FIO-2")
    wrapper = open(os.path.join(d, stage.ADOPT_WRAPPER)).read()
    assert "system(" not in wrapper and "'/sample.php'" in wrapper
    # a sample named like our reserved files is not overwritten
    clash = tmp_path / stage.ADOPT_SHIMS
    clash.write_text("<?php echo 'i am the sample';\n")
    d = stage.adopt(str(tmp_path), str(clash), "FIO-3")
    assert open(os.path.join(d, stage.ADOPT_SAMPLE)).read() == clash.read_text()
    assert "i am the sample" not in open(os.path.join(d, stage.ADOPT_SHIMS)).read()


def test_adopt_defers_the_sample_to_plugins_loaded(tmp_path):
    src = tmp_path / "frag.php"
    src.write_text("<?php\nwp_footer();\n")
    d = stage.adopt(str(tmp_path), str(src), "FIO-4")
    w = open(os.path.join(d, stage.ADOPT_WRAPPER)).read()
    assert "add_action('plugins_loaded'" in w
    assert w.index("kadath-shims.php") < w.index("add_action('plugins_loaded'") < w.index("'/sample.php'")


def test_restore_docroot_script_and_single_exec():
    calls = []
    out = stage.restore_docroot(calls.append)
    assert calls == [stage.RESTORE_DOCROOT_SH]
    assert "pristine" in out
    sh = stage.RESTORE_DOCROOT_SH
    assert sh.startswith("set -e") and "cd /var/www/html" in sh
    assert "wp-config.php" not in sh.split("cp -a")[0].replace("# ", "")  # no exclusion: it is regenerated by the entrypoint
    assert "-print0" in sh and "IFS= read -r -d ''" in sh        # newline-safe names (bash)
    assert "chmod -R u+rwX" in sh
    assert "KadathSandbox mitmproxy CA" in sh and "/gateway-ca/mitmproxy-ca-cert.pem" in sh
    assert "find . -mindepth 1 -type d -empty -delete" in sh
    assert "cp -a /usr/src/wordpress/. /var/www/html/" in sh
    # order: make writable, drop links, prune files, then empty dirs, then restore core
    assert (sh.index("chmod -R") < sh.index("-type l -delete") < sh.index("rm -f --")
            < sh.index("-empty -delete") < sh.index("cp -a"))


def _run_script(script, doc, pristine, **kw):
    import subprocess
    script = script.replace("/var/www/html", str(doc)).replace("/usr/src/wordpress", str(pristine))
    return subprocess.run(["bash", "-c", script], **kw)


def test_restore_docroot_script_behaves(tmp_path):
    """Run the script against a fake docroot/pristine pair (paths rewritten)."""
    pristine, doc = tmp_path / "pristine", tmp_path / "html"
    (pristine / "wp-includes").mkdir(parents=True)
    (pristine / "wp-includes" / "core.php").write_text("clean")
    (pristine / "index.php").write_text("clean")
    (pristine / "wp-admin").mkdir()
    (pristine / "wp-admin" / "a.php").write_text("clean")
    (doc / "wp-includes").mkdir(parents=True)
    (doc / "wp-includes" / "core.php").write_text("PATCHED")
    (doc / "wp-content" / "uploads" / "x").mkdir(parents=True)
    (doc / "wp-content" / "uploads" / "x" / "shell.php").write_text("evil")
    (doc / "wp-content" / "mu.php").write_text("evil")
    (doc / "wp-config.php").write_text("define(1); // backdoor appended here")
    (doc / "link").symlink_to("/nonexistent")
    # a file name with a newline in it, in the docroot and under a nested dir
    (doc / "evil\nname.php").write_text("evil")
    (doc / "wp-content" / "a\nb\n.php").write_text("evil")
    # a read-only directory holding a planted file, and a read-only file
    ro = doc / "wp-content" / "ro"
    ro.mkdir()
    (ro / "planted.php").write_text("evil")
    os.chmod(ro, 0o555)
    (doc / "wp-content" / "ro2").mkdir()
    (doc / "wp-content" / "ro2" / "p.php").write_text("evil")
    os.chmod(doc / "wp-content" / "ro2" / "p.php", 0o444)
    os.chmod(doc / "wp-content" / "ro2", 0o555)
    # a file where the pristine tree has a directory, and a directory where it has a file
    import shutil
    shutil.rmtree(doc / "wp-admin", ignore_errors=True)
    (doc / "wp-admin").write_text("i am a file")
    (doc / "index.php").mkdir()
    (doc / "index.php" / "inner.php").write_text("evil")
    r = _run_script(stage.RESTORE_DOCROOT_SH, doc, pristine, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (doc / "wp-includes" / "core.php").read_text() == "clean"
    assert (doc / "index.php").read_text() == "clean" and (doc / "index.php").is_file()
    assert (doc / "wp-admin" / "a.php").read_text() == "clean"
    assert not (doc / "wp-config.php").exists()   # the entrypoint recreates it
    assert not (doc / "wp-content").exists()
    assert not os.path.lexists(doc / "link")
    assert sorted(os.listdir(doc)) == ["index.php", "wp-admin", "wp-includes"]


def test_restore_docroot_script_failure_is_visible(tmp_path):
    """A restore that cannot finish exits non-zero (run.py turns that into exit 3)."""
    pristine, doc = tmp_path / "pristine", tmp_path / "html"
    pristine.mkdir()
    r = _run_script(stage.RESTORE_DOCROOT_SH, doc, pristine, capture_output=True, text=True)
    assert r.returncode != 0          # no docroot to cd into


def _need_sha256sum(tmp_path, monkeypatch):
    import shutil
    if shutil.which("sha256sum"):
        return
    shim = tmp_path / "bin"
    shim.mkdir()
    (shim / "sha256sum").write_text('#!/bin/sh\nexec shasum -a 256 "$@"\n')
    os.chmod(shim / "sha256sum", 0o755)
    monkeypatch.setenv("PATH", f"{shim}:{os.environ['PATH']}")


def _local_exec(doc):
    import subprocess

    def sh_exec(script):
        return subprocess.run(["sh", "-c", script.replace("/var/www/html", str(doc))],
                              capture_output=True, text=True, check=True).stdout
    return sh_exec


def test_docroot_tainted_finds_persistence_and_wp_config_drift(tmp_path, monkeypatch):
    import hashlib
    _need_sha256sum(tmp_path, monkeypatch)
    doc = tmp_path / "html"
    (doc / "wp-content" / "plugins").mkdir(parents=True)
    (doc / "wp-config.php").write_text("<?php // clean")
    ex = _local_exec(doc)
    sha = hashlib.sha256(b"<?php // clean").hexdigest()
    assert stage.wp_config_sha(ex) == sha
    assert stage.docroot_tainted(ex, sha) == [] and stage.docroot_tainted(ex) == []
    # mu-plugin (nested, newline in the name), drop-ins, appended wp-config
    mu = doc / "wp-content" / "mu-plugins" / "sub"
    mu.mkdir(parents=True)
    (mu / "x\ny.php").write_text("<?php")
    (doc / "wp-content" / "db.php").write_text("<?php")
    (doc / "wp-content" / "object-cache.php").write_text("<?php")
    (doc / "wp-content" / "advanced-cache.php").write_text("<?php")
    (doc / "wp-content" / "sunrise.php").symlink_to("/nonexistent")
    (doc / "wp-config.php").write_text("<?php // clean\neval($_GET[1]);")
    out = stage.docroot_tainted(ex, sha)
    assert out == ["wp-content/mu-plugins/sub/x?y.php", "wp-content/db.php", "wp-content/object-cache.php",
                   "wp-content/advanced-cache.php", "wp-content/sunrise.php", "wp-config.php changed"]
    # no recorded sha: the wp-config comparison is skipped, the rest still reported
    assert "wp-config.php changed" not in stage.docroot_tainted(ex, "")
    assert len(stage.docroot_tainted(ex, "")) == 5
    # wp-config gone entirely
    (doc / "wp-config.php").unlink()
    assert "wp-config.php changed" in stage.docroot_tainted(ex, sha)
    assert stage.wp_config_sha(ex) == ""


def test_docroot_tainted_parsing_with_a_fake_exec():
    seen = []

    def fake(script):
        seen.append(script)
        return "wp-content/db.php\n\n  wp-config.php changed \n"
    assert stage.docroot_tainted(fake, "ab12") == ["wp-content/db.php", "wp-config.php changed"]
    assert seen[0].startswith("set -- ab12\n") and stage.TAINT_CHECK_SH in seen[0]
    # the sha is shell-quoted: a hostile value cannot add commands
    stage.docroot_tainted(fake, "x; rm -rf /")
    assert seen[1].startswith("set -- 'x; rm -rf /'\n")
    # a CompletedProcess-like result works too
    class R:
        stdout = "wp-content/db.php\n"
    assert stage.docroot_tainted(lambda s: R()) == ["wp-content/db.php"]
    assert stage.wp_config_sha(lambda s: R()) == ""
    h = "a" * 64
    assert stage.wp_config_sha(lambda s: f"{h}  /var/www/html/wp-config.php\n") == h


def test_place_zip_rejects_bombs(tmp_path, monkeypatch):
    root = tmp_path; (root / "samples" / "plugins").mkdir(parents=True)
    z = tmp_path / "evil.zip"
    _make_zip(z, {"evil/evil.php": "<?php\n/* Plugin Name: Evil */\n" + "A" * 1000})
    d = detect.detect(str(z))
    monkeypatch.setattr(stage, "MAX_ZIP_BYTES", 500)
    try:
        stage.place(str(root), str(z), d)
        assert False, "expected UnsupportedSample"
    except detect.UnsupportedSample as e:
        assert "expands" in str(e)
    assert not os.path.exists(root / ".kadath" / "unpack" / "evil")
    monkeypatch.setattr(stage, "MAX_ZIP_BYTES", 10 ** 9)
    monkeypatch.setattr(stage, "MAX_ZIP_ENTRIES", 1)
    _make_zip(z, {"evil/evil.php": "<?php\n/* Plugin Name: Evil */\n", "evil/b.php": "x"})
    try:
        stage.place(str(root), str(z), d)
        assert False, "expected UnsupportedSample"
    except detect.UnsupportedSample as e:
        assert "entries" in str(e)
    monkeypatch.setattr(stage, "MAX_ZIP_ENTRIES", 20000)
    stage.place(str(root), str(z), d)       # within limits it still works
    assert os.path.isfile(root / "samples/plugins/evil/evil.php")


# --- database residue -------------------------------------------------------

_STOCK_OPTIONS = ["siteurl", "home", "cron", "active_plugins", "recently_activated"]
_STOCK_CRON = ["wp_version_check", "wp_update_plugins"]
_STOCK_POSTS = ["1", "2", "3"]


class _FakeWp:
    """A wp-cli stand-in holding a tiny DB. Records every call."""

    def __init__(self, options=None, cron=None, posts=None, trashed=None, files=None,
                 active=None, install="2026-09-04 00:56:33"):
        self.options = list(options if options is not None else _STOCK_OPTIONS)
        self.cron = list(cron if cron is not None else _STOCK_CRON)
        self.posts = list(posts if posts is not None else _STOCK_POSTS)
        self.trashed = list(trashed or [])
        self.files = list(files if files is not None else ["akismet/akismet.php", "hello.php"])
        self.active = active if active is not None else []
        self.install = install
        self.calls = []

    def __call__(self, args):
        self.calls.append(args)
        if args[:2] == ["plugin", "list"] and "--field=file" in args:
            return "\n".join(self.files) + "\n"
        if args[:2] == ["plugin", "list"]:
            return ""
        if args[:2] == ["user", "list"]:
            return "1\n"
        if args[:3] == ["user", "get", "1"]:
            return self.install + "\n"
        if args[:2] == ["option", "list"]:
            return json.dumps([{"option_name": n} for n in self.options])
        if args[:3] == ["option", "get", "active_plugins"]:
            return json.dumps(self.active)
        if args[:3] == ["option", "update", "active_plugins"]:
            self.active = json.loads(args[3])
            return ""
        if args[:2] == ["option", "delete"]:
            self.options.remove(args[2])
            return ""
        if args[:3] == ["cron", "event", "list"]:
            return json.dumps([{"hook": h, "next_run_gmt": "x"} for h in self.cron])
        if args[:3] == ["cron", "event", "delete"]:
            self.cron = [h for h in self.cron if h != args[3]]
            return ""
        if args[:2] == ["post", "list"]:
            ids = self.trashed if "--post_status=trash,auto-draft" in args else self.posts
            return " ".join(ids)
        if args[:2] == ["post", "delete"]:
            assert args[-1] == "--force"
            for pid in args[2:-1]:
                if pid in self.posts:
                    self.posts.remove(pid)
                if pid in self.trashed:
                    self.trashed.remove(pid)
            return ""
        return ""


def _root(tmp_path):
    for sub in ("plugins", "themes", "webroot"):
        (tmp_path / "samples" / sub).mkdir(parents=True)
    return str(tmp_path)


def test_isolate_first_run_records_baseline_and_skips_reset(tmp_path, capsys):
    root = _root(tmp_path)
    wp = _FakeWp(options=_STOCK_OPTIONS + ["left_by_sample"], posts=_STOCK_POSTS + ["9"])
    actions = stage.isolate(root, wp)
    b = json.load(open(os.path.join(root, stage.DB_BASELINE)))
    assert b["options"] == _STOCK_OPTIONS + ["left_by_sample"]   # live DB, as found
    assert b["cron"] == sorted(_STOCK_CRON) and b["posts"] == ["1", "2", "3", "9"]
    assert b["install"] == "2026-09-04 00:56:33" and b["recorded"].endswith("Z")
    assert "left_by_sample" in wp.options and "9" in wp.posts        # nothing deleted
    assert not any(a[:2] in (["option", "delete"], ["post", "delete"]) or a[:3] == ["cron", "event", "delete"]
                   for a in wp.calls)
    assert "recorded db baseline (first run; db reset skipped)" in actions
    assert "no DB baseline" in capsys.readouterr().err


def test_isolate_deletes_residue_not_in_baseline(tmp_path):
    root = _root(tmp_path)
    stage.record_db_baseline(root, _FakeWp())
    wp = _FakeWp(options=_STOCK_OPTIONS + ["kadath_adopted_probe", "evil_cfg"],
                 cron=_STOCK_CRON + ["evil_beacon"],
                 posts=_STOCK_POSTS + ["12", "15"], trashed=["17"])
    actions = stage.isolate(root, wp)
    assert wp.options == _STOCK_OPTIONS
    assert wp.cron == _STOCK_CRON
    assert wp.posts == _STOCK_POSTS and wp.trashed == []
    assert ["option", "delete", "kadath_adopted_probe"] in wp.calls
    assert ["cron", "event", "delete", "evil_beacon"] in wp.calls
    assert ["post", "delete", "12", "15", "17", "--force"] in wp.calls
    for a in ("delete option kadath_adopted_probe", "delete option evil_cfg", "delete cron evil_beacon",
              "delete post 12", "delete post 15", "delete post 17"):
        assert a in actions
    assert not any("baseline" in a for a in actions)
    # stock options and posts are never touched
    assert not any(a[:2] == ["option", "delete"] and a[2] in _STOCK_OPTIONS for a in wp.calls)


def test_reset_db_skips_volatile_options(tmp_path):
    root = _root(tmp_path)
    stage.record_db_baseline(root, _FakeWp())
    volatile = ["_transient_doing_cron", "_transient_timeout_feed_x", "_site_transient_update_core",
                "cron", "recently_activated"]
    wp = _FakeWp(options=_STOCK_OPTIONS[:3] + volatile + ["sample_opt"])
    actions = stage.reset_db(wp, stage.load_db_baseline(root, wp))
    deleted = [a[2] for a in wp.calls if a[:2] == ["option", "delete"]]
    assert deleted == ["sample_opt"]
    assert all(v in wp.options for v in volatile)
    assert actions == ["delete option sample_opt"]
    # the pattern anchors: an option merely containing "cron" is a sample's
    assert stage.VOLATILE_OPTION.search("my_cron_jobs") is None
    assert stage.VOLATILE_OPTION.search("cronx") is None
    assert stage.VOLATILE_OPTION.search("_transient_x") and stage.VOLATILE_OPTION.search("cron")


def test_isolate_rewrites_active_plugins_to_existing_files(tmp_path):
    root = _root(tmp_path)
    stage.record_db_baseline(root, _FakeWp())
    wp = _FakeWp(active=["FIO-10172/kadath-wrapper.php", "akismet/akismet.php", "gone/gone.php"])
    actions = stage.isolate(root, wp)
    assert wp.active == ["akismet/akismet.php"]
    upd = [a for a in wp.calls if a[:3] == ["option", "update", "active_plugins"]]
    assert len(upd) == 1 and upd[0][4] == "--format=json"
    assert "remove stale active_plugins entry FIO-10172/kadath-wrapper.php" in actions
    assert "remove stale active_plugins entry gone/gone.php" in actions
    # the prune runs after samples/ is cleared and before the baseline is read
    i_prune = wp.calls.index(upd[0])
    i_list = next(i for i, a in enumerate(wp.calls) if a[:2] == ["option", "list"])
    assert i_prune < i_list


def test_prune_active_plugins_no_write_when_clean_and_handles_dict():
    wp = _FakeWp(active=["akismet/akismet.php"])
    assert stage.prune_active_plugins(wp) == []
    assert not any(a[:2] == ["option", "update"] for a in wp.calls)
    # WordPress serialises a non-sequential array as an object
    wp = _FakeWp(active={"0": "akismet/akismet.php", "3": "ghost/ghost.php"})
    assert stage.prune_active_plugins(wp) == ["ghost/ghost.php"]
    assert wp.active == ["akismet/akismet.php"]


def test_db_baseline_is_stale_after_a_manual_make_reset(tmp_path, capsys):
    root = _root(tmp_path)
    stage.record_db_baseline(root, _FakeWp(options=_STOCK_OPTIONS + ["kadath_adopted_probe"]))
    # `make reset` by hand: fresh DB (new install time), same stale baseline file
    wp = _FakeWp(install="2026-11-08 12:00:00", options=_STOCK_OPTIONS + ["kadath_adopted_probe"])
    assert stage.load_db_baseline(root, wp) is None
    actions = stage.isolate(root, wp)
    assert "recorded db baseline (first run; db reset skipped)" in actions
    assert json.load(open(os.path.join(root, stage.DB_BASELINE)))["install"] == "2026-11-08 12:00:00"
    # a baseline that is not ours is ignored too
    open(os.path.join(root, stage.DB_BASELINE), "w").write("not json")
    assert stage.load_db_baseline(root, wp) is None
    open(os.path.join(root, stage.DB_BASELINE), "w").write(json.dumps({"options": "x"}))
    assert stage.load_db_baseline(root, wp) is None


def test_db_helpers_tolerate_empty_wp_output(tmp_path):
    """The fake in the older isolate test answers "" to everything new."""
    wp = lambda args: ""
    assert stage.db_snapshot(wp) == {"options": [], "cron": [], "posts": []}
    assert stage.prune_active_plugins(wp) == []
    root = _root(tmp_path)
    stage.isolate(root, wp)
    assert os.path.exists(os.path.join(root, stage.DB_BASELINE))


def test_isolate_tolerates_a_missing_user_one(tmp_path, capsys):
    from kadath.shell import ShellError
    root = _root(tmp_path)
    stage.record_db_baseline(root, _FakeWp())

    class NoUser1(_FakeWp):
        def __call__(self, args):
            if args[:3] == ["user", "get", "1"]:
                raise ShellError(["wp"] + args, 1, "Error: Invalid user ID, email or login: '1'")
            return super().__call__(args)
    wp = NoUser1(options=_STOCK_OPTIONS + ["left_by_sample"])
    assert stage._install_id(wp) == ""
    warnings = []
    actions = stage.isolate(root, wp, warnings)
    assert warnings == ["db baseline could not be validated; residue may remain"]
    assert "left_by_sample" in wp.options                       # nothing deleted, nothing re-recorded
    assert not any("recorded db baseline" in a for a in actions)
    b = json.load(open(os.path.join(root, stage.DB_BASELINE)))
    assert "left_by_sample" not in b["options"]                 # the file was not overwritten from the live DB
    assert "could not be validated" in capsys.readouterr().err


# --- classification and webshell names ---

def test_classify_dir_prefers_top_level_plugin_over_nested_theme_header(tmp_path):
    d = tmp_path / "pkg"
    (d / "assets").mkdir(parents=True)
    (d / "assets" / "style.css").write_text("/*\nTheme Name: Decoy\n*/")
    (d / "real.php").write_text("<?php\n/* Plugin Name: Real */\n")
    assert stage._classify_dir(str(tmp_path)) == ("plugin", str(d))


def test_classify_dir_top_level_theme_beats_nested_plugin(tmp_path):
    d = tmp_path / "pkg"
    (d / "inc").mkdir(parents=True)
    (d / "style.css").write_text("/*\nTheme Name: T\n*/")
    (d / "inc" / "x.php").write_text("<?php\n/* Plugin Name: Nested */\n")
    assert stage._classify_dir(str(tmp_path)) == ("theme", str(d))


def test_classify_dir_deep_searches_plugin_before_theme(tmp_path):
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "b" / "style.css").write_text("Theme Name: T")
    (tmp_path / "c").mkdir()
    (tmp_path / "c" / "p.php").write_text("<?php /* Plugin Name: P */")
    (tmp_path / "top.txt").write_text("x")
    assert stage._classify_dir(str(tmp_path)) == ("plugin", str(tmp_path / "c"))
    (tmp_path / "c" / "p.php").unlink()
    (tmp_path / "c" / "q.php").write_text("<?php")
    assert stage._classify_dir(str(tmp_path)) == ("theme", str(tmp_path / "a" / "b"))


def test_place_zip_plugin_with_theme_header_in_assets_runs_as_plugin(tmp_path):
    root = tmp_path; (root / "samples" / "plugins").mkdir(parents=True)
    (root / "samples" / "themes").mkdir()
    z = tmp_path / "evil.zip"
    _make_zip(z, {"evil/evil.php": "<?php\n/* Plugin Name: Evil */\n",
                  "evil/assets/style.css": "/*\nTheme Name: Decoy\n*/"})
    d = detect.detect(str(z))
    staged = stage.place(str(root), str(z), d)
    assert staged == str(root / "samples" / "plugins" / "evil") and os.path.isfile(os.path.join(staged, "evil.php"))
    assert not os.listdir(root / "samples" / "themes")


import pytest


@pytest.mark.parametrize("name", ["index.php", "wp-config.php", ".htaccess.php", "wp-login.php", "xmlrpc.php",
                                  "wp-cron.php", "wp-settings.php", "wp-load.php", "wp-blog-header.php",
                                  "wp-activate.php", "wp-comments-post.php", "wp-links-opml.php", "wp-mail.php",
                                  "wp-signup.php", "wp-trackback.php", "readme.html", "license.txt"])
def test_place_refuses_loose_names_the_entrypoint_will_not_link(tmp_path, name):
    root = tmp_path / "root"; (root / "samples" / "webroot").mkdir(parents=True)
    src = tmp_path / name
    src.write_text("<?php echo 1;")
    d = detect.Detected("webshell", "x", f"samples/webroot/{name}")
    with pytest.raises(detect.UnsupportedSample) as e:
        stage.place(str(root), str(src), d)
    assert name in str(e.value)
    assert os.listdir(root / "samples" / "webroot") == []


def test_place_zip_webshell_with_a_core_name_is_refused(tmp_path):
    root = tmp_path / "root"; (root / "samples" / "webroot").mkdir(parents=True)
    z = tmp_path / "w.zip"
    _make_zip(z, {"wp-login.php": "<?php echo 1;"})
    with pytest.raises(detect.UnsupportedSample):
        stage.place(str(root), str(z), detect.detect(str(z)))
    assert os.listdir(root / "samples" / "webroot") == []


def test_place_ordinary_webshell_name_still_works(tmp_path):
    root = tmp_path / "root"; (root / "samples" / "webroot").mkdir(parents=True)
    src = tmp_path / "c99.php"
    src.write_text("<?php echo 1;")
    staged = stage.place(str(root), str(src), detect.detect(str(src)))
    assert staged.endswith("samples/webroot/c99.php") and os.path.isfile(staged)


def test_place_directory_sample_copies_symlinks_as_links(tmp_path):
    root = tmp_path / "root"; (root / "samples" / "plugins").mkdir(parents=True)
    secret = tmp_path / "secret.txt"
    secret.write_text("host secret")
    src = tmp_path / "plug"
    src.mkdir()
    (src / "p.php").write_text("<?php\n/* Plugin Name: P */\n")
    (src / "loot").symlink_to(secret)
    staged = stage.place(str(root), str(src), detect.detect(str(src)))
    assert os.path.islink(os.path.join(staged, "loot"))
    assert os.readlink(os.path.join(staged, "loot")) == str(secret)
