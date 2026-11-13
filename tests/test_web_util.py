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


def test_sanitize_keeps_unicode_and_extension():
    assert web_util.sanitize_filename("日本語.php") == "日本語.php"
    assert web_util.sanitize_filename("café x.php") == "café_x.php"

def test_sanitize_leading_dots_and_empties():
    assert web_util.sanitize_filename(".htaccess") == "htaccess"
    assert web_util.sanitize_filename("...php") == "php"
    assert web_util.sanitize_filename("..") == "sample"
    assert web_util.sanitize_filename("!!!.php") == "sample.php"
    assert web_util.sanitize_filename(None) == "sample"

def test_sanitize_truncates_keeping_extension():
    got = web_util.sanitize_filename("a" * 500 + ".php")
    assert len(got) == 100 and got.endswith(".php")

def test_sanitize_accepts_rfc2231_tuple_and_bytes():
    assert web_util.sanitize_filename(("UTF-8", "", "x.php")) == "x.php"
    assert web_util.sanitize_filename(("UTF-8", "", b"y.php")) == "y.php"
    assert web_util.sanitize_filename(b"z.php") == "z.php"

def test_parse_multipart_rfc2231_filename_does_not_crash():
    ct = "multipart/form-data; boundary=B"
    body = (b'--B\r\nContent-Disposition: form-data; name="sample"; '
            b"filename*=UTF-8''%E6%97%A5%E6%9C%AC.php\r\n\r\nx\r\n--B--\r\n")
    _, files = web_util.parse_multipart(ct, body)
    assert files["sample"] == ("日本.php", b"x")

def test_parse_multipart_raw_utf8_filename():
    ct = "multipart/form-data; boundary=B"
    body = ('--B\r\nContent-Disposition: form-data; name="sample"; '
            'filename="日本語.php"\r\n\r\nx\r\n--B--\r\n').encode()
    _, files = web_util.parse_multipart(ct, body)
    assert files["sample"][0] == "日本語.php"

def test_origin_allowed():
    assert web_util.origin_allowed("http://127.0.0.1:8090", 8090)
    assert web_util.origin_allowed("http://localhost:8090", 8090)
    assert not web_util.origin_allowed("http://evil.example:8090", 8090)
    assert not web_util.origin_allowed("https://127.0.0.1:8090", 8090)
    assert not web_util.origin_allowed("null", 8090)
    assert not web_util.origin_allowed("", 8090)
