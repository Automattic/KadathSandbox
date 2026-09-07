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
