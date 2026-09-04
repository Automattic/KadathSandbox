import pytest
from kadath import shell

def test_run_captures_stdout():
    r = shell.run(["printf", "hello"])
    assert r.stdout == "hello"
    assert r.returncode == 0

def test_run_raises_on_failure():
    with pytest.raises(shell.ShellError) as e:
        shell.run(["sh", "-c", "echo boom >&2; exit 3"])
    assert e.value.returncode == 3
    assert "boom" in e.value.stderr

def test_run_no_check_returns_nonzero():
    r = shell.run(["sh", "-c", "exit 7"], check=False)
    assert r.returncode == 7
