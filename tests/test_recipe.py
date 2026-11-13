import pytest
from kadath import recipe

def test_parse_login_get_post():
    text = open("tests/fixtures/sample.kadath").read()
    acts = recipe.parse(text)
    assert acts[0] == recipe.Action("login", "admin", "sandbox")
    assert acts[1] == recipe.Action("get", "/shell.php?c=id")
    assert acts[2] == recipe.Action("post", "/wp-admin/admin-ajax.php", "action=foo&x=1")

def test_comments_and_blanks_skipped():
    assert recipe.parse("# hi\n\nGET /a\n") == [recipe.Action("get", "/a")]

def test_unknown_directive_raises_with_line():
    with pytest.raises(recipe.RecipeError) as e:
        recipe.parse("GET /a\nFROB /b\n")
    assert e.value.line_no == 2

def test_bare_post_raises():
    import pytest
    from kadath import recipe
    with pytest.raises(recipe.RecipeError) as e:
        recipe.parse("GET /a\nPOST\n")
    assert e.value.line_no == 2


@pytest.mark.parametrize("line", [
    "GET @evil.com/x", "GET //evil.com/x", "GET http://evil.com/", "GET x", "GET",
    "GET /a b", "POST @evil.com/x a=1", "POST //evil.com/x", "GET /a\x01b", "GET /a\x7fb",
])
def test_bad_paths_rejected_with_line(line):
    with pytest.raises(recipe.RecipeError) as e:
        recipe.parse("GET /ok\n" + line + "\n")
    assert e.value.line_no == 2


def test_discover_reads_only_regular_files(tmp_path):
    s = tmp_path / "shell.php"
    s.write_text("<?php")
    assert recipe.discover(str(s)) is None
    (tmp_path / "shell.php.kadath").write_text("GET /shell.php\n")
    assert recipe.discover(str(s)) == str(s) + ".kadath"
    s2 = tmp_path / "other.php"
    (tmp_path / "secret").write_text("GET /x\n")
    (tmp_path / "other.php.kadath").symlink_to(tmp_path / "secret")
    assert recipe.discover(str(s2)) is None
    s3 = tmp_path / "dirsample.php"
    (tmp_path / "dirsample.php.kadath").mkdir()
    assert recipe.discover(str(s3)) is None
