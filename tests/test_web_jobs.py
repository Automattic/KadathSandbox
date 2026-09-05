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
