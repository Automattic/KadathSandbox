import urllib.error
from kadath.wpsession import WpSession


def test_connection_failure_is_recorded_not_raised(monkeypatch):
    s = WpSession("http://127.0.0.1:1")

    class Opener:
        def open(self, r, timeout=60):
            raise urllib.error.URLError("connection refused")
    s.opener = Opener()
    assert s.get("/x.php") == "connection-failed"
    assert s.actions == ["GET /x.php -> connection-failed"]

    class Opener2:
        def open(self, r, timeout=60):
            raise ConnectionResetError("reset")
    s.opener = Opener2()
    assert s.post("/y.php", "a=1") == "connection-failed"


import http.server
import threading
from kadath.wpsession import WpSession


def _serve(cookie):
    class H(http.server.BaseHTTPRequestHandler):
        def _reply(self):
            self.send_response(200)
            if cookie and self.command == "POST":
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        do_GET = do_POST = _reply

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_login_detects_success_by_cookie():
    srv = _serve("wordpress_logged_in_abc=1; Path=/")
    try:
        s = WpSession(f"http://127.0.0.1:{srv.server_port}")
        assert s.logged_in is None
        s.login("admin", "sandbox")
        assert s.logged_in is True
        assert s.actions == ["LOGIN admin -> 200 ok"]
    finally:
        srv.shutdown(); srv.server_close()


def test_login_detects_failure_without_cookie():
    # a wrong password still answers 200 (the login form again)
    srv = _serve("wordpress_test_cookie=WP%20Cookie%20check; Path=/")
    try:
        s = WpSession(f"http://127.0.0.1:{srv.server_port}")
        s.login("admin", "wrong")
        assert s.logged_in is False
        assert s.actions == ["LOGIN admin -> 200 FAILED"]
    finally:
        srv.shutdown(); srv.server_close()


import http.server
import threading
import pytest


def _srv(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_redirect_is_not_followed():
    hits = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            if self.path == "/r":
                self.send_response(302)
                self.send_header("Location", "/followed")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        def log_message(self, *a):
            pass
    srv = _srv(H)
    try:
        s = WpSession(f"http://127.0.0.1:{srv.server_port}")
        assert s.get("/r") == 302
        assert hits == ["/r"]
        assert s.actions == ["GET /r -> 302"]
    finally:
        srv.shutdown(); srv.server_close()


@pytest.mark.parametrize("bad", ["//evil.example/x", "http://evil.example/", "@evil.example/x",
                                 "x", "", ":80/x"])
def test_path_must_be_a_single_slash_path(bad):
    s = WpSession("http://127.0.0.1:1")
    with pytest.raises(ValueError):
        s.get(bad)
    with pytest.raises(ValueError):
        s.post(bad, "a=1")
    assert s.actions == []


def test_env_proxy_is_ignored(monkeypatch):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass
    srv = _srv(H)
    try:
        for k in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
            monkeypatch.setenv(k, "http://127.0.0.1:9")  # dead port
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        s = WpSession(f"http://127.0.0.1:{srv.server_port}")
        assert s.get("/x") == 204
    finally:
        srv.shutdown(); srv.server_close()


def test_cookie_from_plain_get_is_not_a_login():
    # the sample plants wordpress_logged_in_* on a GET; the login POST sets nothing
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Set-Cookie", "wordpress_logged_in_x=planted; Path=/")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass
    srv = _srv(H)
    try:
        s = WpSession(f"http://127.0.0.1:{srv.server_port}")
        s.get("/planted")
        s.login("admin", "wrong")
        assert s.logged_in is False
        assert s.actions[-1] == "LOGIN admin -> 200 FAILED"
    finally:
        srv.shutdown(); srv.server_close()


def test_login_success_via_unfollowed_302():
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            self.send_response(302)
            self.send_header("Set-Cookie", "wordpress_logged_in_x=real; Path=/")
            self.send_header("Location", "/wp-admin/")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass
    srv = _srv(H)
    try:
        s = WpSession(f"http://127.0.0.1:{srv.server_port}")
        s.login("admin", "sandbox")
        assert s.logged_in is True
        assert s.actions == ["LOGIN admin -> 302 ok"]
    finally:
        srv.shutdown(); srv.server_close()
