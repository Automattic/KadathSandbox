"""Parse a declarative .kadath trigger recipe. No host shell — only LOGIN/GET/POST."""
import os
import re
from dataclasses import dataclass


class RecipeError(ValueError):
    def __init__(self, msg, line_no):
        super().__init__(f"line {line_no}: {msg}")
        self.line_no = line_no


@dataclass
class Action:
    kind: str
    a: str = ""
    b: str = ""


def _check_path(path, i):
    # a path is appended to the base URL: "@evil.com/x" or "//evil.com/x" would
    # retarget the host, whitespace/control chars would smuggle request lines
    if not path.startswith("/") or path.startswith("//"):
        raise RecipeError(f"path must start with a single '/': {path!r}", i)
    if re.search(r"[\s\x00-\x1f\x7f]", path):
        raise RecipeError(f"path has whitespace or control characters: {path!r}", i)
    return path


def discover(sample):
    """The <sample>.kadath recipe next to a sample, or None. A symlink is never
    read: the sample's directory is attacker-influenced."""
    p = sample + ".kadath"
    if os.path.islink(p) or not os.path.isfile(p):
        return None
    return p


def parse(text):
    out = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        verb = parts[0].upper()
        rest = parts[1] if len(parts) > 1 else ""
        if verb == "LOGIN":
            up = rest.split()
            if len(up) != 2:
                raise RecipeError("LOGIN needs <user> <pass>", i)
            out.append(Action("login", up[0], up[1]))
        elif verb == "GET":
            out.append(Action("get", _check_path(rest.strip(), i)))
        elif verb == "POST":
            pp = rest.split(None, 1)
            if not pp:
                raise RecipeError("POST needs <path> [body]", i)
            out.append(Action("post", _check_path(pp[0], i), pp[1].strip() if len(pp) > 1 else ""))
        else:
            raise RecipeError(f"unknown directive {verb!r}", i)
    return out
