"""Fatal-driven dependency stubs for an Offering. A sample lifted out of a kit
dies on its first require and reads as benign; PHP names exactly what is
missing, so we create empty stand-ins under samples/webroot (a read-only bind
mount inside the container, writable on the host) and trigger again. Missing
functions get no-op shims appended to the stub that should have defined them."""
import os
import re

_REQUIRED = re.compile(r"Failed opening (?:required )?'(/samples/[^']+)'")
_INCLUDE_STREAM = re.compile(r"(?:include|require)(?:_once)?\((/samples/[^)]+)\): Failed to open stream")
_UNDEFINED = re.compile(r"Call to undefined function ([A-Za-z_][A-Za-z0-9_]*)\(\) in /samples/")
# __DIR__ . '/x.php' / dirname(__FILE__) . '/x.php' (leading slash stripped), or a
# bare relative literal 'x.php'; an unprefixed absolute path is not ours to stub
_STATIC_INC = re.compile(
    r"\b(?:require|include)(?:_once)?\s*\(?\s*(?:"
    r"(?:__DIR__|dirname\(\s*__FILE__\s*\))\s*\.\s*['\"]/?([^'\"\s]+\.php)['\"]"
    r"|['\"]([^'\"\s/][^'\"\s]*\.php)['\"])")
_FUNC_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
STUB_HEADER = "<?php // kadath stub: missing dependency, created by the Offering\n"


def new_lines(path, offset):
    try:
        with open(path, "r", errors="replace") as f:
            f.seek(offset)
            return [l.rstrip("\n") for l in f if l.strip()]
    except OSError:
        return []


def missing_includes(lines):
    out = []
    for l in lines:
        m = _REQUIRED.search(l) or _INCLUDE_STREAM.search(l)
        if m and m.group(1) not in out and ".." not in m.group(1):
            out.append(m.group(1))
    return out


def undefined_functions(lines):
    out = []
    for l in lines:
        m = _UNDEFINED.search(l)
        if m and m.group(1) not in out:
            out.append(m.group(1))
    return out


def host_path(container_path, root):
    """Map /samples/<sub>/<rel> to <root>/samples/<sub>/<rel>; None if it would
    escape samples/ or names the mount root itself."""
    base = os.path.realpath(os.path.join(root, "samples"))
    if not container_path.startswith("/samples/"):
        return None
    rel = container_path[len("/samples/"):]
    target = os.path.realpath(os.path.join(base, rel))
    if not target.startswith(base + os.sep) or target.count(os.sep) <= base.count(os.sep) + 1:
        return None
    return target


def static_includes(source):
    """Relative include paths written as literals (optionally __DIR__ /
    dirname(__FILE__) prefixed). Dynamic paths and parent-directory escapes
    are left to the fatal-driven rounds."""
    out = []
    for m in _STATIC_INC.finditer(source):
        rel = m.group(1) or m.group(2)
        if ".." in rel or rel in out:
            continue
        out.append(rel)
    return out


def write_stub(path):
    if os.path.exists(path):
        return False
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(STUB_HEADER)
    except OSError:
        return False
    return True


def add_shims(path, names):
    with open(path, "r") as f:
        existing = f.read()
    with open(path, "a") as f:
        for n in names:
            if not _FUNC_NAME.match(n) or f"function {n}(" in existing:
                continue
            f.write(f"if (!function_exists('{n}')) {{ function {n}(...$a) {{ return null; }} }}\n")
            existing += f"function {n}("


def stub_rounds(root, err_log, err_off, retrigger, max_rounds=3, stub_files=None):
    """Read the fatals the last trigger produced, stub what is missing, and
    trigger again — up to max_rounds times. stub_files are host paths of stubs
    already written (the engine's static pre-scan), so a function the pre-scan's
    stub should have defined has somewhere to get its shim. Returns
    (stubs, fatal_remaining): stubs is a list of {"path", "kind":
    include|function, "round"}; fatal_remaining is True when the final round
    still ended in a PHP fatal."""
    made = []
    stub_files = list(stub_files or [])
    offset = err_off
    for rnd in range(1, max_rounds + 1):
        lines = new_lines(err_log, offset)
        try:
            offset = os.path.getsize(err_log)
        except OSError:
            offset = 0
        fatal = any("PHP Fatal error" in l for l in lines)
        if not fatal:
            return made, False
        acted = False
        for cpath in missing_includes(lines):
            hp = host_path(cpath, root)
            if hp and write_stub(hp):
                stub_files.append(hp)
                made.append({"path": cpath, "kind": "include", "round": rnd})
                acted = True
        names = undefined_functions(lines)
        if names and stub_files:
            add_shims(stub_files[0], names)
            for n in names:
                made.append({"path": n, "kind": "function", "round": rnd})
            acted = True
        if not acted:
            return made, True
        retrigger()
    lines = new_lines(err_log, offset)
    return made, any("PHP Fatal error" in l for l in lines)
