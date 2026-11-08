"""KadathSandbox web front end. This module holds the background job model and
(Task 4) the HTTP server. Standard library only; the server shells out only to
the offer engine."""
import os
import secrets
import selectors
import shutil
import signal
import subprocess
import threading
import time

WEB_JOB_TIMEOUT = 1800   # seconds before a running engine is killed


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


def _kill_group(p):
    # WHY: the engine spawns docker/compose children that would keep the pipes open.
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except OSError:
        try:
            p.kill()
        except OSError:
            pass


class JobManager:
    def __init__(self, engine_cmd, workdir, timeout=None):
        self.engine_cmd = list(engine_cmd)
        self.workdir = workdir
        self.timeout = timeout          # None -> WEB_JOB_TIMEOUT, read at run time
        self.current = None
        self._jobs = {}
        self._lock = threading.Lock()

    def get(self, job_id):
        return self._jobs.get(job_id)

    def busy(self):
        with self._lock:
            return self.current is not None and self.current.state == "running"

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
        # WHY: any failure must end in a terminal state, or the job stays
        # "running" forever and every later start() raises Busy.
        try:
            self._run_engine(job, argv)
        except Exception as e:
            job.error = f"engine failed: {e}"
            job.state = "error"

    def _run_engine(self, job, argv):
        timeout = self.timeout if self.timeout is not None else WEB_JOB_TIMEOUT
        try:
            p = subprocess.Popen(argv, cwd=self.workdir, shell=False, start_new_session=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            job.error = f"failed to start engine: {e}"
            job.state = "error"
            return
        deadline = time.monotonic() + timeout
        timed_out = False
        out, err = b"", b""
        sel = selectors.DefaultSelector()
        try:
            # Both pipes are drained here (select, not blocking reads) so a slow
            # or wedged engine can neither deadlock on a full pipe nor outlive
            # the deadline. Bytes are decoded with errors="replace".
            sel.register(p.stdout, selectors.EVENT_READ, "out")
            sel.register(p.stderr, selectors.EVENT_READ, "err")
            while sel.get_map():
                left = deadline - time.monotonic()
                if left <= 0:
                    timed_out = True
                    break
                for key, _ in sel.select(min(left, 1.0)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        sel.unregister(key.fileobj)
                    elif key.data == "out":
                        out += chunk
                    else:
                        err += chunk
                        *lines, err = err.split(b"\n")
                        job.phase_lines.extend(
                            ln.decode("utf-8", "replace").rstrip("\r") for ln in lines)
            if err:
                job.phase_lines.append(err.decode("utf-8", "replace").rstrip("\r"))
            rc = None
            if not timed_out:
                try:
                    rc = p.wait(timeout=max(deadline - time.monotonic(), 0.1))
                except subprocess.TimeoutExpired:
                    timed_out = True
            if timed_out:
                _kill_group(p)
                p.wait()
                job.error = f"engine timed out after {timeout} s"
                job.state = "error"
                return
        finally:
            sel.close()
            for f in (p.stdout, p.stderr):
                try:
                    f.close()
                except OSError:
                    pass
            if p.poll() is None:
                _kill_group(p)
                p.wait()
        text = out.decode("utf-8", "replace").strip()
        if rc == 0 and text:
            job.summary_path = text.splitlines()[-1].strip()
            job.report_dir = os.path.dirname(job.summary_path)
            job.state = "done"
        else:
            job.error = "\n".join(job.phase_lines[-10:]) or f"engine exited {rc}"
            job.state = "error"


import json
import http.server
import posixpath
from urllib.parse import unquote, urlparse

from kadath import web_util, web_verdict

_ASSETS = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(_ASSETS)
MAX_BODY = 25 * 1024 * 1024
# WHY: the UI has no inline styles or images, so neither 'unsafe-inline' nor
# img-src is granted; connect-src is needed for the UI's own fetch().
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
       "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


def _read_asset(name):
    with open(os.path.join(_ASSETS, name), "rb") as f:
        return f.read()


class Handler(http.server.BaseHTTPRequestHandler):
    # set by serve(): self.server.manager, self.server.port, self.server.csrf, self.server.workdir
    server_version = "kadath-web"
    timeout = 60   # socket timeout: a stalled client cannot pin a thread forever

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
            self._status(unquote(path.rsplit("/", 1)[-1]))
        elif path.startswith("/report/"):
            self._report(unquote(path.rsplit("/", 1)[-1]))
        elif path.startswith("/artifact/"):
            parts = path.split("/", 3)
            self._artifact(unquote(parts[2]) if len(parts) > 2 else "",
                           unquote(parts[3]) if len(parts) > 3 else "")
        else:
            self._headers(404, "text/plain; charset=utf-8")
            self.wfile.write(b"not found")

    def _text(self, code, msg):
        self._headers(code, "text/plain; charset=utf-8")
        self.wfile.write(msg)

    def _cross_origin(self):
        origin = self.headers.get("Origin")
        if origin is not None and not web_util.origin_allowed(origin, self.server.port):
            return True
        site = self.headers.get("Sec-Fetch-Site")
        return site is not None and site not in ("same-origin", "none")

    def do_POST(self):
        if not self._guard_host():
            return
        if urlparse(self.path).path != "/run":
            self._text(404, b"not found")
            return
        # WHY: refuse a cross-site POST before reading (or buffering) its body
        if self._cross_origin():
            self._text(403, b"cross-origin request refused")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            length = -1
        if length < 0:
            self._text(400, b"bad content-length")
            return
        if length > MAX_BODY:
            self._text(413, b"upload too large")
            return
        ctype = self.headers.get("Content-Type", "")
        try:
            body = self.rfile.read(length)
        except OSError:        # socket timeout / reset mid-upload
            self.close_connection = True
            return
        fields, files = web_util.parse_multipart(ctype, body)
        # WHY bytes: compare_digest raises TypeError on a non-ASCII str
        if not secrets.compare_digest((fields.get("csrf") or "").encode("utf-8"),
                                      self.server.csrf.encode("utf-8")):
            self._text(403, b"bad csrf token")
            return
        if "sample" not in files or not files["sample"][0] or not files["sample"][1]:
            self._json(400, {"error": "no sample uploaded"})
            return
        if self.server.manager.busy():
            self._json(409, {"error": "another offering is in progress"})
            return
        job_dir = os.path.join(self.server.workdir, ".kadath", "web", secrets.token_urlsafe(6))
        os.makedirs(job_dir, exist_ok=True)
        try:
            sample_path = os.path.join(job_dir, web_util.sanitize_filename(files["sample"][0]))
            with open(sample_path, "wb") as f:
                f.write(files["sample"][1])
            recipe_path = None
            if "recipe" in files and files["recipe"][0]:
                recipe_path = os.path.join(job_dir, "recipe.kadath")
                with open(recipe_path, "wb") as f:
                    f.write(files["recipe"][1])
            reset = fields.get("reset") in ("on", "true", "1")
            job = self.server.manager.start(sample_path, recipe_path, reset)
        except Busy as e:      # lost a race with another upload
            shutil.rmtree(job_dir, ignore_errors=True)
            self._json(409, {"error": str(e)})
            return
        except BaseException:
            shutil.rmtree(job_dir, ignore_errors=True)
            raise
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
        try:
            f = open(safe, "rb")
        except OSError:
            self._text(403, b"forbidden")
            return
        with f:
            size = os.fstat(f.fileno()).st_size
            # WHY ascii: header values are latin-1 encoded; the name is sample-derived
            dl_name = web_util.sanitize_filename(posixpath.basename(safe))
            dl_name = dl_name.encode("ascii", "replace").decode().replace("?", "_")
            # WHY octet-stream + attachment + nosniff: artifacts are hostile; never render them
            self._headers(200, "application/octet-stream",
                          {"Content-Disposition": f'attachment; filename="{dl_name}"',
                           "Content-Length": str(size)})
            left = size
            while left > 0:
                chunk = f.read(min(65536, left))
                if not chunk:
                    break
                self.wfile.write(chunk)
                left -= len(chunk)

    def _method_not_allowed(self):
        self._headers(405, "text/plain; charset=utf-8", {"Allow": "GET, POST"})
        self.wfile.write(b"method not allowed")

    do_HEAD = do_PUT = do_DELETE = do_OPTIONS = do_PATCH = lambda self: self._method_not_allowed()

    def log_message(self, *a):
        pass  # quiet


WEB_UPLOAD_MAX_AGE_DAYS = 7


def prune_uploads(workdir, max_age_days=WEB_UPLOAD_MAX_AGE_DAYS, now=None):
    """Remove upload dirs under <workdir>/.kadath/web older than max_age_days
    (they hold attacker-controlled PHP). Direct children only; symlinks and
    plain files are never followed or touched. Returns the removed paths."""
    base = os.path.join(workdir, ".kadath", "web")
    cutoff = (time.time() if now is None else now) - max_age_days * 86400
    removed = []
    try:
        names = os.listdir(base)
    except OSError:
        return removed
    for name in sorted(names):
        p = os.path.join(base, name)
        try:
            if os.path.islink(p) or not os.path.isdir(p):
                continue
            if os.lstat(p).st_mtime < cutoff:
                shutil.rmtree(p)
                removed.append(p)
        except OSError:
            continue
    return removed


def serve(port=8090, engine_cmd=None, workdir=None):
    workdir = workdir or REPO_ROOT
    if engine_cmd is None:
        engine_cmd = [os.path.join(REPO_ROOT, "bin", "kadath"), "offer"]
    pruned = prune_uploads(workdir)
    if pruned:
        print(f"kadath web: pruned {len(pruned)} stale upload dir(s) older than "
              f"{WEB_UPLOAD_MAX_AGE_DAYS} days")
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
