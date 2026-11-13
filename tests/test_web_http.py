import http.client, http.server, json, os, threading
import pytest
from kadath import web


class _Job:
    state = "done"

    def __init__(self, report_dir):
        self.report_dir = report_dir


class _Manager:
    def __init__(self, job):
        self.job = job

    def get(self, job_id):
        return self.job if job_id == "J1" else None

    def busy(self):
        return False


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setattr(web, "REPO_ROOT", str(tmp_path))
    report = tmp_path / "reports" / "x-1"
    (report / "artifacts").mkdir(parents=True)
    (tmp_path / "live").mkdir()
    big = b"A" * 200000 + b"<html><script>alert(1)</script>"
    (tmp_path / "live" / "trace.1.xt").write_bytes(big)
    (tmp_path / "secret.txt").write_text("nope")
    (report / "summary.json").write_text(json.dumps({"artifacts": {
        "traces": [str(tmp_path / "live" / "trace.1.xt")], "sp_dumps": [], "pcaps": [],
        "bundle": ["artifacts/summary.json"]}}))
    (report / "artifacts" / "summary.json").write_text("BUNDLED")
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    httpd.manager = _Manager(_Job(str(report)))
    httpd.port = httpd.server_address[1]
    httpd.csrf = "tok"
    httpd.workdir = str(tmp_path)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd, big
    httpd.shutdown()
    httpd.server_close()


def _get(httpd, path):
    c = http.client.HTTPConnection("127.0.0.1", httpd.port, timeout=5)
    c.request("GET", path, headers={"Host": "127.0.0.1:%d" % httpd.port})
    return c.getresponse()


def test_csp_header_allows_own_fetch_and_denies_framing(server):
    httpd, _ = server
    csp = _get(httpd, "/").getheader("Content-Security-Policy")
    assert "connect-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp and "img-src" not in csp
    assert "connect-src 'self'" in web.CSP


def test_artifact_headers_and_streamed_body(server):
    httpd, big = server
    r = _get(httpd, "/artifact/J1/trace.1.xt")
    assert r.status == 200
    assert r.getheader("Content-Type") == "application/octet-stream"
    assert r.getheader("Content-Disposition") == 'attachment; filename="trace.1.xt"'
    assert r.getheader("X-Content-Type-Options") == "nosniff"
    assert r.getheader("Content-Length") == str(len(big))
    assert r.read() == big


def test_artifact_name_is_percent_decoded(server):
    httpd, big = server
    r = _get(httpd, "/artifact/J1/trace%2E1.xt")
    assert r.status == 200 and r.read() == big


def test_artifact_report_file_wins_over_bundle_same_basename(server):
    httpd, _ = server
    r = _get(httpd, "/artifact/J1/summary.json")
    assert r.status == 200
    assert b"BUNDLED" not in r.read()


def test_artifact_non_allowlisted_is_403(server):
    httpd, _ = server
    assert _get(httpd, "/artifact/J1/secret.txt").status == 403
    assert _get(httpd, "/artifact/J1/..%2Fsecret.txt").status == 403
    assert _get(httpd, "/artifact/J1/%2Fetc%2Fpasswd").status == 403


def test_artifact_unknown_job_is_404(server):
    httpd, _ = server
    assert _get(httpd, "/artifact/nope/trace.1.xt").status == 404
