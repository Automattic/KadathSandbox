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
