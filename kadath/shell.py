"""Thin subprocess wrapper. The engine shells out for all Docker/Make/wp work;
this is the one place that runs external commands, so failures are uniform."""
import subprocess


class ShellError(RuntimeError):
    def __init__(self, cmd, returncode, stderr):
        super().__init__(f"command failed ({returncode}): {' '.join(cmd)}\n{stderr}")
        self.cmd = cmd
        self.returncode = returncode
        self.stderr = stderr


def run(args, *, cwd=None, check=True, timeout=None):
    """Run args (a list), capture text stdout/stderr. Raise ShellError on
    non-zero exit when check is True."""
    p = subprocess.run(
        args, cwd=cwd, timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if check and p.returncode != 0:
        raise ShellError(args, p.returncode, p.stderr)
    return p
