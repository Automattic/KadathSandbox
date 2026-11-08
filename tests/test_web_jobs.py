import os, stat, time
from kadath import web

def _stub_engine(tmp_path, rc=0, emit_summary=True):
    """A fake engine: prints two phase lines to stderr, optionally writes a report
    dir and prints the summary path to stdout, exits rc."""
    rep = tmp_path / "reports" / "stub-1"
    lines = ["#!/usr/bin/env bash",
             'echo "bringing the stack up..." >&2',
             'echo "triggering..." >&2']
    if emit_summary:
        lines += [f'mkdir -p "{rep}"',
                  f'printf "{{}}" > "{rep}/summary.json"',
                  f'echo "{rep}/summary.json"']
    lines.append(f"exit {rc}")
    script = tmp_path / "fake_engine.sh"
    script.write_text("\n".join(lines) + "\n")
    os.chmod(script, os.stat(script).st_mode | stat.S_IEXEC)
    return [str(script)], str(rep)

def _wait(job, state, timeout=5):
    end = time.time() + timeout
    while time.time() < end and job.state == "running":
        time.sleep(0.02)
    return job

def test_job_runs_to_done(tmp_path):
    cmd, rep = _stub_engine(tmp_path)
    jm = web.JobManager(cmd, str(tmp_path))
    job = jm.start(str(tmp_path / "sample.php"))
    _wait(job, "done")
    assert job.state == "done"
    assert "triggering..." in job.phase_lines
    assert job.report_dir == rep

def test_job_error_on_nonzero(tmp_path):
    cmd, _ = _stub_engine(tmp_path, rc=3, emit_summary=False)
    jm = web.JobManager(cmd, str(tmp_path))
    job = jm.start(str(tmp_path / "sample.php"))
    _wait(job, "error")
    assert job.state == "error"

def test_busy_rejects_second(tmp_path):
    cmd, _ = _stub_engine(tmp_path)
    jm = web.JobManager(cmd, str(tmp_path))
    # a slow stub so the first is still running
    slow = tmp_path / "slow.sh"; slow.write_text("#!/usr/bin/env bash\nsleep 1\n")
    os.chmod(slow, 0o755)
    jm2 = web.JobManager([str(slow)], str(tmp_path))
    jm2.start(str(tmp_path / "s.php"))
    import pytest
    with pytest.raises(web.Busy):
        jm2.start(str(tmp_path / "s.php"))


def _web_dir(tmp_path):
    d = tmp_path / ".kadath" / "web"
    d.mkdir(parents=True)
    return d

def test_prune_uploads_removes_old_keeps_fresh(tmp_path):
    d = _web_dir(tmp_path)
    old, fresh = d / "old", d / "fresh"
    for x in (old, fresh):
        x.mkdir()
        (x / "sample.php").write_text("<?php")
    t = time.time() - 8 * 86400
    os.utime(old, (t, t))
    removed = web.prune_uploads(str(tmp_path))
    assert removed == [str(old)]
    assert not old.exists() and fresh.exists()

def test_prune_uploads_does_not_follow_symlinks(tmp_path):
    d = _web_dir(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("k")
    link = d / "link"
    os.symlink(str(outside), str(link))
    t = time.time() - 30 * 86400
    os.utime(outside, (t, t))
    os.utime(str(link), (t, t), follow_symlinks=False)
    assert web.prune_uploads(str(tmp_path)) == []
    assert (outside / "keep.txt").exists() and os.path.islink(str(link))

def test_prune_uploads_ignores_plain_files(tmp_path):
    d = _web_dir(tmp_path)
    f = d / "stray.txt"
    f.write_text("x")
    t = time.time() - 30 * 86400
    os.utime(f, (t, t))
    assert web.prune_uploads(str(tmp_path)) == []
    assert f.exists()

def test_prune_uploads_missing_dir(tmp_path):
    assert web.prune_uploads(str(tmp_path)) == []


def test_start_exception_ends_in_error_and_unwedges(tmp_path, monkeypatch):
    cmd, _ = _stub_engine(tmp_path)
    jm = web.JobManager(cmd, str(tmp_path))
    def boom(*a, **k):
        raise ValueError("kaboom")
    monkeypatch.setattr(web.subprocess, "Popen", boom)
    job = jm.start(str(tmp_path / "s.php"))
    _wait(job, "error")
    assert job.state == "error" and "engine failed: kaboom" in job.error
    monkeypatch.undo()
    job2 = jm.start(str(tmp_path / "s.php"))      # manager is not wedged
    _wait(job2, "done")
    assert job2.state == "done"

def test_runtime_exception_in_reader_ends_in_error(tmp_path, monkeypatch):
    cmd, _ = _stub_engine(tmp_path)
    jm = web.JobManager(cmd, str(tmp_path))
    def boom(*a, **k):
        raise RuntimeError("select died")
    monkeypatch.setattr(web.os, "read", boom)
    job = jm.start(str(tmp_path / "s.php"))
    _wait(job, "error")
    assert job.state == "error" and "engine failed: select died" in job.error

def test_timeout_kills_engine_and_manager_accepts_next(tmp_path):
    slow = tmp_path / "hang.sh"
    # the grandchild sleep inherits the pipes: the kill must reach the process group
    slow.write_text("#!/usr/bin/env bash\necho started >&2\nsleep 30\n")
    os.chmod(slow, 0o755)
    jm = web.JobManager([str(slow)], str(tmp_path), timeout=0.5)
    t0 = time.time()
    job = jm.start(str(tmp_path / "s.php"))
    _wait(job, "error", timeout=10)
    assert job.state == "error"
    assert job.error == "engine timed out after 0.5 s"
    assert "started" in job.phase_lines
    assert time.time() - t0 < 10
    cmd, _ = _stub_engine(tmp_path)
    jm.engine_cmd = cmd
    job2 = jm.start(str(tmp_path / "s.php"))       # no Busy
    _wait(job2, "done")
    assert job2.state == "done"

def test_timeout_default_is_the_module_constant(tmp_path, monkeypatch):
    assert web.WEB_JOB_TIMEOUT == 1800
    monkeypatch.setattr(web, "WEB_JOB_TIMEOUT", 0.3)
    slow = tmp_path / "hang.sh"; slow.write_text("#!/usr/bin/env bash\nsleep 30\n"); os.chmod(slow, 0o755)
    jm = web.JobManager([str(slow)], str(tmp_path))
    job = jm.start(str(tmp_path / "s.php"))
    _wait(job, "error", timeout=10)
    assert job.state == "error" and "timed out" in job.error

def test_non_utf8_engine_output_is_replaced_not_fatal(tmp_path):
    s = tmp_path / "bad.sh"
    s.write_text("#!/usr/bin/env bash\nprintf 'bad \\377 line\\n' >&2\nexit 1\n")
    os.chmod(s, 0o755)
    jm = web.JobManager([str(s)], str(tmp_path))
    job = jm.start(str(tmp_path / "s.php"))
    _wait(job, "error")
    assert job.state == "error" and "bad \ufffd line" in job.phase_lines
