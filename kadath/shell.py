"""Thin subprocess wrapper. The engine shells out for all Docker/Make/wp work;
this is the one place that runs external commands, so failures are uniform."""
import os
import signal
import subprocess

_MAX_CMD = 200


class ShellError(RuntimeError):
    def __init__(self, cmd, returncode, stderr):
        shown = " ".join(str(c) for c in cmd)
        if len(shown) > _MAX_CMD:       # a `bash -c <script>` argv is not a message
            shown = shown[:_MAX_CMD] + "..."
        super().__init__(f"command failed ({returncode}): {shown}\n{stderr}")
        self.cmd = cmd
        self.returncode = returncode
        self.stderr = stderr


def _kill_group(p):
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except OSError:
        p.kill()


def run(args, *, cwd=None, check=True, timeout=600):
    """Run args (a list), capture text stdout/stderr (undecodable bytes are
    replaced, never raised). Raise ShellError on non-zero exit when check is
    True, and on timeout (returncode 124) whatever check says. timeout=None
    waits forever. The child gets its own process group so a timeout or ^C
    kills make/docker and whatever they spawned, not just the direct child."""
    p = subprocess.Popen(
        args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, errors="replace", start_new_session=True)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group(p)
        p.communicate()
        raise ShellError(args, 124, f"timed out after {timeout}s")
    except BaseException:
        _kill_group(p)
        p.communicate()
        raise
    r = subprocess.CompletedProcess(args, p.returncode, out, err)
    if check and r.returncode != 0:
        raise ShellError(args, r.returncode, err)
    return r
