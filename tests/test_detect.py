import pytest
from kadath import detect

FX = "tests/fixtures"

def test_plugin_file():
    d = detect.detect(f"{FX}/plugin_sample.php")
    assert d.type == "plugin"
    assert d.dest == f"samples/plugins/{d.slug}"

def test_theme_dir():
    d = detect.detect(f"{FX}/theme_sample")
    assert d.type == "theme"
    assert d.dest == f"samples/themes/{d.slug}"

def test_loose_php_is_webshell():
    d = detect.detect(f"{FX}/shell_sample.php")
    assert d.type == "webshell"
    assert d.dest == "samples/webroot/shell_sample.php"

def test_slug_is_kebab():
    d = detect.detect(f"{FX}/plugin_sample.php")
    assert d.slug == "plugin-sample"

def test_missing_raises():
    with pytest.raises(detect.UnsupportedSample):
        detect.detect(f"{FX}/does-not-exist.php")
