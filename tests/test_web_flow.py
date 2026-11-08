import http.client, json, os, threading, time, io
import http.server
from kadath import web

def _start_server(tmp_path):
    workdir = str(tmp_path)
    engine = os.path.join(os.path.dirname(__file__), "fixtures", "fake_engine.sh")
    os.chmod(engine, 0o755)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    httpd.manager = web.JobManager([engine], workdir)
    httpd.port = httpd.server_address[1]
    httpd.csrf = "testtoken"
    httpd.workdir = workdir
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]

def _conn(port):
    return http.client.HTTPConnection("127.0.0.1", port, timeout=5)

def _multipart(fields, files):
    b = "BOUND"
    out = io.BytesIO()
    for k, v in fields.items():
        out.write(f"--{b}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
    for k, (fn, data) in files.items():
        out.write(f"--{b}\r\nContent-Disposition: form-data; name=\"{k}\"; filename=\"{fn}\"\r\n\r\n".encode())
        out.write(data + b"\r\n")
    out.write(f"--{b}--\r\n".encode())
    return f"multipart/form-data; boundary={b}", out.getvalue()

def test_full_flow(tmp_path):
    httpd, port = _start_server(tmp_path)
    # host guard
    c = _conn(port); c.request("GET", "/", headers={"Host": "evil.example:%d" % port})
    assert c.getresponse().status == 421
    # bad csrf
    ct, body = _multipart({"csrf": "wrong", "reset": ""}, {"sample": ("x.php", b"<?php")})
    c = _conn(port); c.request("POST", "/run", body=body, headers={"Host": "127.0.0.1:%d" % port, "Content-Type": ct})
    assert c.getresponse().status == 403
    # good run
    ct, body = _multipart({"csrf": "testtoken", "reset": ""}, {"sample": ("x.php", b"<?php")})
    c = _conn(port); c.request("POST", "/run", body=body, headers={"Host": "127.0.0.1:%d" % port, "Content-Type": ct})
    r = c.getresponse(); assert r.status == 200
    job_id = json.loads(r.read())["job_id"]
    # poll to done
    for _ in range(100):
        c = _conn(port); c.request("GET", "/status/" + job_id, headers={"Host": "127.0.0.1:%d" % port})
        st = json.loads(c.getresponse().read())
        if st["state"] != "running": break
        time.sleep(0.05)
    assert st["state"] == "done"
    assert "triggering..." in st["phase_lines"]
    # report + verdict
    c = _conn(port); c.request("GET", "/report/" + job_id, headers={"Host": "127.0.0.1:%d" % port})
    rep = json.loads(c.getresponse().read())
    assert rep["verdict"]["level"] == "red"
    assert rep["summary"]["db_diff"]["users_added"][0]["login"] == "sys_maint"
    # method guard
    c = _conn(port); c.request("PUT", "/run", headers={"Host": "127.0.0.1:%d" % port})
    assert c.getresponse().status == 405
    httpd.shutdown()


def _post(port, fields, files, headers=None):
    ct, body = _multipart(fields, files)
    h = {"Host": "127.0.0.1:%d" % port, "Content-Type": ct}
    h.update(headers or {})
    c = _conn(port); c.request("POST", "/run", body=body, headers=h)
    return c.getresponse()

def test_uploads_land_under_tmp_workdir(tmp_path):
    httpd, port = _start_server(tmp_path)
    r = _post(port, {"csrf": "testtoken"}, {"sample": ("x.php", b"<?php")})
    assert r.status == 200
    r.read()
    assert os.path.isdir(tmp_path / ".kadath" / "web")
    for _ in range(100):
        if httpd.manager.current.state != "running": break
        time.sleep(0.05)
    httpd.shutdown()

def test_cross_origin_post_rejected_before_body(tmp_path):
    httpd, port = _start_server(tmp_path)
    for hdr in ({"Origin": "http://evil.example"}, {"Origin": "null"},
                {"Origin": "http://127.0.0.1:1"}, {"Sec-Fetch-Site": "cross-site"},
                {"Sec-Fetch-Site": "same-site"}):
        r = _post(port, {"csrf": "testtoken"}, {"sample": ("x.php", b"<?php")}, hdr)
        assert r.status == 403, hdr
    assert not os.path.exists(tmp_path / ".kadath" / "web")   # nothing was staged
    httpd.shutdown()

def test_same_origin_and_missing_origin_accepted(tmp_path):
    httpd, port = _start_server(tmp_path)
    r = _post(port, {"csrf": "testtoken"}, {"sample": ("x.php", b"<?php")},
              {"Origin": "http://127.0.0.1:%d" % port, "Sec-Fetch-Site": "same-origin"})
    assert r.status == 200
    r.read()
    for _ in range(100):
        if httpd.manager.current.state != "running": break
        time.sleep(0.05)
    r = _post(port, {"csrf": "testtoken"}, {"sample": ("x.php", b"<?php")})   # no Origin at all
    assert r.status == 200
    httpd.shutdown()

def test_non_ascii_csrf_token_is_403_not_crash(tmp_path):
    httpd, port = _start_server(tmp_path)
    r = _post(port, {"csrf": "t\u00f6ken\u65e5"}, {"sample": ("x.php", b"<?php")})
    assert r.status == 403
    httpd.shutdown()

def test_empty_sample_or_filename_is_400(tmp_path):
    httpd, port = _start_server(tmp_path)
    assert _post(port, {"csrf": "testtoken"}, {"sample": ("x.php", b"")}).status == 400
    assert _post(port, {"csrf": "testtoken"}, {"sample": ("", b"<?php")}).status == 400
    assert not os.path.exists(tmp_path / ".kadath" / "web")
    httpd.shutdown()

def test_busy_post_leaves_no_job_dir(tmp_path):
    httpd, port = _start_server(tmp_path)
    slow = tmp_path / "slow.sh"; slow.write_text("#!/usr/bin/env bash\nsleep 1\n"); os.chmod(slow, 0o755)
    httpd.manager = web.JobManager([str(slow)], str(tmp_path))
    r = _post(port, {"csrf": "testtoken"}, {"sample": ("x.php", b"<?php")})
    assert r.status == 200; r.read()
    r = _post(port, {"csrf": "testtoken"}, {"sample": ("y.php", b"<?php")})
    assert r.status == 409
    assert len(os.listdir(tmp_path / ".kadath" / "web")) == 1
    httpd.shutdown()

def test_unicode_sample_name_keeps_extension(tmp_path):
    httpd, port = _start_server(tmp_path)
    r = _post(port, {"csrf": "testtoken"}, {"sample": ("\u65e5\u672c\u8a9e.php", b"<?php")})
    assert r.status == 200; r.read()
    names = [n for d in (tmp_path / ".kadath" / "web").iterdir() for n in os.listdir(d)]
    assert names == ["\u65e5\u672c\u8a9e.php"]
    for _ in range(100):
        if httpd.manager.current.state != "running": break
        time.sleep(0.05)
    httpd.shutdown()
