import io
from kadath import web_util

def _multipart(parts):
    # parts: list of (name, filename_or_None, value_bytes)
    b = b"BOUNDARY"
    out = io.BytesIO()
    for name, filename, val in parts:
        out.write(b"--" + b + b"\r\n")
        cd = f'form-data; name="{name}"'
        if filename is not None:
            cd += f'; filename="{filename}"'
        out.write(("Content-Disposition: " + cd + "\r\n\r\n").encode())
        out.write(val)
        out.write(b"\r\n")
    out.write(b"--" + b + b"--\r\n")
    return "multipart/form-data; boundary=BOUNDARY", out.getvalue()

def test_parse_multipart_fields_and_files():
    ct, body = _multipart([("csrf", None, b"tok123"),
                           ("reset", None, b"on"),
                           ("sample", "evil.php", b"<?php echo 1;")])
    fields, files = web_util.parse_multipart(ct, body)
    assert fields["csrf"] == "tok123"
    assert fields["reset"] == "on"
    assert files["sample"][0] == "evil.php"
    assert files["sample"][1] == b"<?php echo 1;"

def test_sanitize_filename():
    assert web_util.sanitize_filename("../../etc/passwd") == "passwd"
    assert web_util.sanitize_filename("a b/c;d.php") == "c_d.php"
    assert web_util.sanitize_filename("") == "sample"

def test_host_allowed():
    assert web_util.host_allowed("127.0.0.1:8090", 8090)
    assert web_util.host_allowed("localhost:8090", 8090)
    assert not web_util.host_allowed("evil.example:8090", 8090)
    assert not web_util.host_allowed("127.0.0.1:9999", 8090)
