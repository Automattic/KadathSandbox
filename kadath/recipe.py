"""Parse a declarative .kadath trigger recipe. No host shell — only LOGIN/GET/POST."""
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
            out.append(Action("get", rest.strip()))
        elif verb == "POST":
            pp = rest.split(None, 1)
            out.append(Action("post", pp[0], pp[1].strip() if len(pp) > 1 else ""))
        else:
            raise RecipeError(f"unknown directive {verb!r}", i)
    return out
