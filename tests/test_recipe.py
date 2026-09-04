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
