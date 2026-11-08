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
