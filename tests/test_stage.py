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
