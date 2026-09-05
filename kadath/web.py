"""KadathSandbox web front end. This module holds the background job model and
(Task 4) the HTTP server. Standard library only; the server shells out only to
the offer engine."""
import os
import secrets
import subprocess
import threading


class Busy(Exception):
    pass


class Job:
    def __init__(self, job_id):
        self.id = job_id
        self.state = "running"
        self.phase_lines = []
        self.report_dir = None
        self.summary_path = None
        self.error = None


class JobManager:
    def __init__(self, engine_cmd, workdir):
        self.engine_cmd = list(engine_cmd)
        self.workdir = workdir
        self.current = None
        self._jobs = {}
        self._lock = threading.Lock()

    def get(self, job_id):
        return self._jobs.get(job_id)

    def start(self, sample_path, recipe_path=None, reset=False):
        with self._lock:
            if self.current is not None and self.current.state == "running":
                raise Busy("another offering is in progress")
            job = Job(secrets.token_urlsafe(8))
            self.current = job
            self._jobs[job.id] = job
        argv = list(self.engine_cmd) + [sample_path, "--json"]
        if recipe_path:
            argv += ["--recipe", recipe_path]
        if reset:
            argv += ["--reset"]
        t = threading.Thread(target=self._run, args=(job, argv), daemon=True)
        t.start()
        return job

    def _run(self, job, argv):
        try:
            p = subprocess.Popen(argv, cwd=self.workdir, shell=False,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except OSError as e:
            job.error = f"failed to start engine: {e}"
            job.state = "error"
            return
        # The engine streams phase messages to stderr throughout and prints exactly
        # one line to stdout (the summary.json path) at the very end. So draining
        # stderr first, then reading stdout, cannot deadlock. If the engine ever
        # writes bulk stdout before exit, switch to a select/thread-per-pipe reader.
        for line in p.stderr:
            job.phase_lines.append(line.rstrip("\n"))
        out = p.stdout.read().strip()
        rc = p.wait()
        if rc == 0 and out:
            job.summary_path = out.splitlines()[-1].strip()
            job.report_dir = os.path.dirname(job.summary_path)
            job.state = "done"
        else:
            job.error = "\n".join(job.phase_lines[-10:]) or f"engine exited {rc}"
            job.state = "error"


import json
import http.server
import posixpath
from urllib.parse import urlparse

from kadath import web_util, web_verdict

_ASSETS = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(_ASSETS)
MAX_BODY = 25 * 1024 * 1024
CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self'; base-uri 'none'; form-action 'self'")


def _read_asset(name):
    with open(os.path.join(_ASSETS, name), "rb") as f:
        return f.read()


class Handler(http.server.BaseHTTPRequestHandler):
    # set by serve(): self.server.manager, self.server.port, self.server.csrf, self.server.workdir
    server_version = "kadath-web"

    def _headers(self, code, ctype, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self._headers(code, "application/json; charset=utf-8")
        self.wfile.write(body)

    def _guard_host(self):
        if not web_util.host_allowed(self.headers.get("Host", ""), self.server.port):
            self._headers(421, "text/plain; charset=utf-8")
            self.wfile.write(b"bad host")
            return False
        return True

    def do_GET(self):
        if not self._guard_host():
            return
        path = urlparse(self.path).path
        if path == "/":
            body = _read_asset("web_index.html").replace(b"__CSRF__", self.server.csrf.encode())
            self._headers(200, "text/html; charset=utf-8")
            self.wfile.write(body)
        elif path == "/app.js":
            self._headers(200, "application/javascript; charset=utf-8")
            self.wfile.write(_read_asset("web_app.js"))
        elif path == "/app.css":
            self._headers(200, "text/css; charset=utf-8")
            self.wfile.write(_read_asset("web_app.css"))
        elif path.startswith("/status/"):
            self._status(path.rsplit("/", 1)[-1])
        elif path.startswith("/report/"):
            self._report(path.rsplit("/", 1)[-1])
        elif path.startswith("/artifact/"):
            parts = path.split("/", 3)
            self._artifact(parts[2] if len(parts) > 2 else "", parts[3] if len(parts) > 3 else "")
        else:
            self._headers(404, "text/plain; charset=utf-8")
            self.wfile.write(b"not found")

    def do_POST(self):
        if not self._guard_host():
            return
        if urlparse(self.path).path != "/run":
            self._headers(404, "text/plain; charset=utf-8")
            self.wfile.write(b"not found")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            self._headers(400, "text/plain; charset=utf-8")
            self.wfile.write(b"bad content-length")
            return
        if length < 0:
            self._headers(400, "text/plain; charset=utf-8")
            self.wfile.write(b"bad content-length")
            return
        if length > MAX_BODY:
            self._headers(413, "text/plain; charset=utf-8")
            self.wfile.write(b"upload too large")
            return
        ctype = self.headers.get("Content-Type", "")
        body = self.rfile.read(length)
        fields, files = web_util.parse_multipart(ctype, body)
        if not secrets.compare_digest(fields.get("csrf") or "", self.server.csrf):
            self._headers(403, "text/plain; charset=utf-8")
            self.wfile.write(b"bad csrf token")
            return
        if "sample" not in files:
            self._json(400, {"error": "no sample uploaded"})
            return
        job_dir = os.path.join(self.server.workdir, ".kadath", "web", secrets.token_urlsafe(6))
        os.makedirs(job_dir, exist_ok=True)
        sample_name = web_util.sanitize_filename(files["sample"][0])
        sample_path = os.path.join(job_dir, sample_name)
        with open(sample_path, "wb") as f:
            f.write(files["sample"][1])
        recipe_path = None
        if "recipe" in files and files["recipe"][0]:
            recipe_path = os.path.join(job_dir, "recipe.kadath")
            with open(recipe_path, "wb") as f:
                f.write(files["recipe"][1])
        reset = fields.get("reset") in ("on", "true", "1")
        try:
            job = self.server.manager.start(sample_path, recipe_path, reset)
        except Busy as e:
            self._json(409, {"error": str(e)})
            return
        self._json(200, {"job_id": job.id})

    def _status(self, job_id):
        job = self.server.manager.get(job_id)
        if not job:
            self._json(404, {"error": "unknown job"})
            return
        self._json(200, {"state": job.state, "phase_lines": job.phase_lines,
                         "report_dir": job.report_dir, "error": job.error})

    def _report(self, job_id):
        job = self.server.manager.get(job_id)
        if not job or job.state != "done":
            self._json(404, {"error": "no report"})
            return
        try:
            with open(os.path.join(job.report_dir, "summary.json")) as f:
                summary = json.load(f)
        except (OSError, ValueError):
            self._json(500, {"error": "report unreadable"})
            return
        iocs = {}
        iocs_path = os.path.join(job.report_dir, "iocs.json")
        if os.path.exists(iocs_path):
            try:
                with open(iocs_path) as f:
                    iocs = json.load(f)
            except (OSError, ValueError):
                iocs = {}
        self._json(200, {"summary": summary, "iocs": iocs,
                         "verdict": web_verdict.compute(summary),
                         "report_dir": job.report_dir})

    def _artifact(self, job_id, name):
        job = self.server.manager.get(job_id)
        if not job or job.state != "done":
            self._headers(404, "text/plain; charset=utf-8")
            self.wfile.write(b"no report")
            return
        try:
            with open(os.path.join(job.report_dir, "summary.json")) as f:
                summary = json.load(f)
        except (OSError, ValueError):
            self._headers(500, "text/plain; charset=utf-8")
            self.wfile.write(b"report unreadable")
            return
        allow = web_util.artifact_allowlist(summary, job.report_dir)
        safe = web_util.safe_artifact_path(REPO_ROOT, allow, posixpath.basename(name))
        if not safe or not os.path.isfile(safe):
            self._headers(403, "text/plain; charset=utf-8")
            self.wfile.write(b"forbidden")
            return
        with open(safe, "rb") as f:
            data = f.read()
        dl_name = web_util.sanitize_filename(posixpath.basename(safe))
        self._headers(200, "text/plain; charset=utf-8",
                      {"Content-Disposition": f'attachment; filename="{dl_name}"'})
        self.wfile.write(data)

    def _method_not_allowed(self):
        self._headers(405, "text/plain; charset=utf-8", {"Allow": "GET, POST"})
        self.wfile.write(b"method not allowed")

    do_HEAD = do_PUT = do_DELETE = do_OPTIONS = do_PATCH = lambda self: self._method_not_allowed()

    def log_message(self, *a):
        pass  # quiet


def serve(port=8090, engine_cmd=None, workdir=None):
    workdir = workdir or REPO_ROOT
    if engine_cmd is None:
        engine_cmd = [os.path.join(REPO_ROOT, "bin", "kadath"), "offer"]
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    httpd.manager = JobManager(engine_cmd, workdir)
    httpd.port = port
    httpd.csrf = secrets.token_urlsafe(16)
    httpd.workdir = workdir
    print(f"kadath web on http://127.0.0.1:{port}  (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
