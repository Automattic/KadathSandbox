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


def test_run_replaces_undecodable_bytes():
    r = shell.run(["printf", "a\\377b"])
    assert r.stdout == "a�b"


def test_run_times_out_as_shell_error():
    with pytest.raises(shell.ShellError) as e:
        shell.run(["sleep", "5"], timeout=0.3)
    assert e.value.returncode == 124 and "timed out" in e.value.stderr


def test_run_timeout_kills_grandchildren_holding_the_pipe():
    import time
    t = time.time()
    with pytest.raises(shell.ShellError):
        shell.run(["sh", "-c", "sleep 30 & wait"], timeout=0.3)
    assert time.time() - t < 5


def test_shell_error_message_truncates_long_argv():
    e = shell.ShellError(["bash", "-c", "x" * 5000], 1, "boom")
    assert len(str(e)) < 400 and "boom" in str(e)
