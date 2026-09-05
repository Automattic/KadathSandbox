"""KadathSandbox web front end. This module holds the background job model and
(Task 4) the HTTP server. Standard library only; the server shells out only to
the detonate engine."""
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
                raise Busy("another detonation is in progress")
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
