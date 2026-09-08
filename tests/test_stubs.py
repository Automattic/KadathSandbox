import os
import pytest
from kadath import stubs

FATAL_REQ = ("[07-Sep-2026 17:06:27 UTC] PHP Fatal error:  Uncaught Error: Failed opening required "
             "'/samples/webroot/functions/functions.php' (include_path='.:/usr/local/lib/php') "
             "in /samples/webroot/f44ce.php:5")
WARN_INC = ("[07-Sep-2026 17:06:27 UTC] PHP Warning:  include(/samples/webroot/inc/a.php): Failed to open "
            "stream: No such file or directory in /samples/webroot/f44ce.php on line 9")
WARN_INC2 = ("[07-Sep-2026 17:06:27 UTC] PHP Warning:  include(): Failed opening '/samples/webroot/inc/a.php' "
             "for inclusion (include_path='.:/usr/local/lib/php') in /samples/webroot/f44ce.php on line 9")
FATAL_FN = ("[07-Sep-2026 17:06:28 UTC] PHP Fatal error:  Uncaught Error: Call to undefined function "
            "helper_ping() in /samples/webroot/f44ce.php:12")
FATAL_FN_CORE = ("[07-Sep-2026 17:06:28 UTC] PHP Fatal error:  Uncaught Error: Call to undefined function "
                 "wp_foo() in /var/www/html/wp-includes/x.php:12")
FATAL_OUTSIDE = ("[07-Sep-2026 17:06:27 UTC] PHP Fatal error:  Uncaught Error: Failed opening required "
                 "'/var/www/html/wp-config.php' in /samples/webroot/f44ce.php:5")
TRAVERSAL = ("[07-Sep-2026 17:06:27 UTC] PHP Fatal error:  Uncaught Error: Failed opening required "
             "'/samples/webroot/../../etc/x.php' in /samples/webroot/f44ce.php:5")


def test_missing_includes_parses_fatal_and_warning_forms():
    lines = [FATAL_REQ, WARN_INC, WARN_INC2, FATAL_OUTSIDE, TRAVERSAL, "noise"]
    assert stubs.missing_includes(lines) == ["/samples/webroot/functions/functions.php",
                                             "/samples/webroot/inc/a.php"]


def test_undefined_functions_only_from_sample_frames():
    assert stubs.undefined_functions([FATAL_FN, FATAL_FN_CORE, "x"]) == ["helper_ping"]
    assert stubs.undefined_functions([FATAL_FN, FATAL_FN]) == ["helper_ping"]


def test_host_path_maps_and_rejects_escape(tmp_path):
    root = str(tmp_path)
    assert stubs.host_path("/samples/webroot/inc/a.php", root) == os.path.join(root, "samples", "webroot", "inc", "a.php")
    assert stubs.host_path("/samples/webroot/../../etc/x.php", root) is None
    assert stubs.host_path("/var/www/html/x.php", root) is None
    assert stubs.host_path("/samples/webroot", root) is None


def test_static_includes_relative_to_dir():
    src = ("<?php\nrequire_once __DIR__.'/functions/functions.php';\n"
           "include dirname(__FILE__) . \"/lib/b.php\";\nrequire('c.php');\n"
           "require $x . '/dyn.php';\ninclude_once __DIR__ . '/../up.php';\n")
    assert stubs.static_includes(src) == ["functions/functions.php", "lib/b.php", "c.php"]


def test_write_stub_and_shims(tmp_path):
    p = tmp_path / "samples" / "webroot" / "inc" / "a.php"
    assert stubs.write_stub(str(p)) is True
    assert p.read_text().startswith("<?php // kadath stub")
    assert stubs.write_stub(str(p)) is False          # already there, untouched
    stubs.add_shims(str(p), ["helper_ping", "bad-name", "helper_ping"])
    text = p.read_text()
    assert text.count("function helper_ping(") == 1 and "bad-name" not in text
    assert "function_exists('helper_ping')" in text


def test_new_lines_from_offset(tmp_path):
    log = tmp_path / "php-error.log"
    log.write_text("old\n")
    off = log.stat().st_size
    with open(log, "a") as f:
        f.write("new1\nnew2\n")
    assert stubs.new_lines(str(log), off) == ["new1", "new2"]
    assert stubs.new_lines(str(tmp_path / "missing.log"), 0) == []


def test_stub_rounds_stubs_then_shims_then_stops(tmp_path):
    root = tmp_path
    (root / "samples" / "webroot").mkdir(parents=True)
    log = root / "artifacts" / "php" / "php-error.log"
    log.parent.mkdir(parents=True)
    log.write_text("")
    script = [[FATAL_FN], []]                       # what each retrigger produces
    calls = []

    def retrigger():
        calls.append(1)
        with open(log, "a") as f:
            f.write("\n".join(script.pop(0)) + "\n")

    # round 0 output (the first trigger) is already in the log
    with open(log, "a") as f:
        f.write(FATAL_REQ + "\n")
    made, fatal = stubs.stub_rounds(str(root), str(log), 0, retrigger, max_rounds=3)
    assert [ (s["kind"], s["round"]) for s in made ] == [("include", 1), ("function", 2)]
    assert made[0]["path"] == "/samples/webroot/functions/functions.php"
    assert made[1]["path"] == "helper_ping"
    assert (root / "samples" / "webroot" / "functions" / "functions.php").exists()
    assert "helper_ping" in (root / "samples" / "webroot" / "functions" / "functions.php").read_text()
    assert fatal is False and len(calls) == 2


def test_stub_rounds_reports_remaining_fatal_and_caps(tmp_path):
    root = tmp_path
    (root / "samples" / "webroot").mkdir(parents=True)
    log = root / "artifacts" / "php" / "php-error.log"
    log.parent.mkdir(parents=True)
    log.write_text(FATAL_OUTSIDE + "\n")
    calls = []
    made, fatal = stubs.stub_rounds(str(root), str(log), 0, lambda: calls.append(1), max_rounds=3)
    assert made == [] and fatal is True and calls == []
    # an undefined function with no stub to attach to cannot be shimmed
    log.write_text(FATAL_FN + "\n")
    made, fatal = stubs.stub_rounds(str(root), str(log), 0, lambda: calls.append(1), max_rounds=3)
    assert made == [] and fatal is True and calls == []


def test_stub_rounds_cap(tmp_path):
    root = tmp_path
    (root / "samples" / "webroot").mkdir(parents=True)
    log = root / "artifacts" / "php" / "php-error.log"
    log.parent.mkdir(parents=True)
    log.write_text("")
    n = [0]

    def retrigger():
        n[0] += 1
        with open(log, "a") as f:
            f.write(FATAL_REQ.replace("functions/functions.php", f"m{n[0]}.php") + "\n")

    with open(log, "a") as f:
        f.write(FATAL_REQ.replace("functions/functions.php", "m0.php") + "\n")
    made, fatal = stubs.stub_rounds(str(root), str(log), 0, retrigger, max_rounds=3)
    assert len(made) == 3 and n[0] == 3 and fatal is True


def test_stub_rounds_shims_into_prescan_stub(tmp_path):
    """The engine's static pre-scan stubbed the include before the first trigger;
    the first fatal is then the undefined function — it must attach to that stub."""
    root = tmp_path
    pre = root / "samples" / "webroot" / "kit" / "helpers.php"
    assert stubs.write_stub(str(pre))
    log = root / "artifacts" / "php" / "php-error.log"
    log.parent.mkdir(parents=True)
    log.write_text(FATAL_FN + "\n")
    calls = []

    def retrigger():
        calls.append(1)                     # shimmed run: no more fatals

    made, fatal = stubs.stub_rounds(str(root), str(log), 0, retrigger, stub_files=[str(pre)])
    assert made == [{"path": "helper_ping", "kind": "function", "round": 1}]
    assert fatal is False and calls == [1]
    assert "function helper_ping(" in pre.read_text()


def test_static_includes_ignores_absolute_paths():
    src = "<?php\nrequire('/etc/x.php');\nrequire_once __DIR__ . '/a.php';\ninclude 'b.php';\n"
    assert stubs.static_includes(src) == ["a.php", "b.php"]


def test_write_stub_survives_oserror(tmp_path):
    blocker = tmp_path / "samples"
    blocker.write_text("i am a file, not a directory")
    assert stubs.write_stub(str(blocker / "webroot" / "x.php")) is False


FATAL_CLASS = ("[07-Sep-2026 19:52:06 UTC] PHP Fatal error:  Uncaught Error: Class \"WP_Error\" not found "
               "in /samples/plugins/x/a711.php:413")
FATAL_CLASS_CORE = ("[07-Sep-2026 19:52:06 UTC] PHP Fatal error:  Uncaught Error: Class 'Foo' not found "
                    "in /var/www/html/wp-includes/x.php:1")


def test_undefined_classes_and_shims(tmp_path):
    assert stubs.undefined_classes([FATAL_CLASS, FATAL_CLASS_CORE, FATAL_CLASS]) == ["WP_Error"]
    p = tmp_path / "kadath-shims.php"
    stubs.write_stub(str(p))
    stubs.add_class_shims(str(p), ["WP_Error", "Bad\\Ns", "WP_Error"])
    t = p.read_text()
    assert t.count("class WP_Error ") == 1 and "Bad" not in t and "__callStatic" in t


def test_stub_rounds_shims_classes(tmp_path):
    root = tmp_path
    shims = root / "samples" / "plugins" / "x" / "kadath-shims.php"
    stubs.write_stub(str(shims))
    log = root / "artifacts" / "php" / "php-error.log"
    log.parent.mkdir(parents=True)
    log.write_text(FATAL_CLASS + "\n")
    made, fatal = stubs.stub_rounds(str(root), str(log), 0, lambda: None, stub_files=[str(shims)])
    assert made == [{"path": "WP_Error", "kind": "class", "round": 1}] and fatal is False
    assert "class WP_Error " in shims.read_text()


def test_prescan_adopted_layout_keeps_shims_first(tmp_path):
    root = tmp_path
    staged = root / "samples" / "plugins" / "FIO-9"
    staged.mkdir(parents=True)
    (staged / "sample.php").write_text("<?php\nrequire_once __DIR__ . '/inc/a.php';\n")
    (staged / "kadath-shims.php").write_text("<?php\n")
    made, files = stubs.prescan(str(staged / "sample.php"), str(staged), str(root))
    assert made == [{"path": "/samples/plugins/FIO-9/inc/a.php", "kind": "include", "round": 0}]
    assert files == [str(staged / "inc" / "a.php")]
    assert stubs.prescan(str(root / "nope.php"), str(staged), str(root)) == ([], [])


def test_is_fatal_and_fatal_lines():
    parse = "[08-Sep-2026 11:10:36 UTC] PHP Parse error:  syntax error, unexpected token in /samples/plugins/X/sample.php on line 222"
    core = "[08-Sep-2026 10:38:27 UTC] PHP Fatal error:  Uncaught Error: Call to undefined function is_user_logged_in() in /var/www/html/wp-includes/admin-bar.php:1448"
    warn = "[08-Sep-2026 10:38:27 UTC] PHP Warning:  something"
    assert stubs.is_fatal(parse) and stubs.is_fatal(core) and not stubs.is_fatal(warn)
    assert stubs.fatal_lines([warn, core, parse, FATAL_REQ]) == [parse, FATAL_REQ]   # sample frames preferred
    assert stubs.fatal_lines([warn, core]) == [core]
    assert stubs.fatal_lines([warn]) == []


def test_stub_rounds_treats_parse_error_as_fatal(tmp_path):
    root = tmp_path
    (root / "samples" / "webroot").mkdir(parents=True)
    log = root / "artifacts" / "php" / "php-error.log"
    log.parent.mkdir(parents=True)
    log.write_text("[08-Sep-2026 11:10:36 UTC] PHP Parse error:  syntax error in /samples/webroot/s.php on line 2\n")
    made, fatal = stubs.stub_rounds(str(root), str(log), 0, lambda: None)
    assert made == [] and fatal is True
