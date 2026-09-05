import http.client, json, os, threading, time, io
import http.server
from kadath import web

def _start_server(tmp_path):
    engine = os.path.join(os.path.dirname(__file__), "fixtures", "fake_engine.sh")
    os.chmod(engine, 0o755)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    httpd.manager = web.JobManager([engine], web.REPO_ROOT)
    httpd.port = httpd.server_address[1]
    httpd.csrf = "testtoken"
    httpd.workdir = web.REPO_ROOT
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
    assert c.getresponse().status in (404, 405, 501)
    httpd.shutdown()
