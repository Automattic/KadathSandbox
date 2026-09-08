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
