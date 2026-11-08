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
