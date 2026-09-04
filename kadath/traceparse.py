"""Parse Xdebug computerized traces (format 4, tab-separated). Files are huge;
stream line by line, never load whole."""

DANGEROUS = ("eval", "assert", "system", "exec", "shell_exec", "passthru",
             "proc_open", "popen", "base64_decode", "gzinflate",
             "create_function", "call_user_func")
FILE_OPS = ("file_put_contents", "fwrite", "fputs", "move_uploaded_file",
            "rename", "copy", "unlink")


def _entries(paths):
    """Yield (cols) for entry records (col3 == '0') across all paths."""
    for p in paths:
        try:
            f = open(p, "r", errors="replace")
        except OSError:
            continue
        with f:
            for line in f:
                cols = line.rstrip("\n").split("\t")
                if len(cols) >= 6 and cols[2] == "0":
                    yield cols


def callchain(paths, sample_dirs=("/samples/",)):
    seen = set()
    out = []
    for c in _entries(paths):
        caller = c[8] if len(c) > 8 else ""
        if not any(d in caller for d in sample_dirs):
            continue
        line = int(c[9]) if len(c) > 9 and c[9].isdigit() else 0
        key = (c[5], caller, line)
        if key in seen:
            continue
        seen.add(key)
        out.append({"function": c[5], "file": caller, "line": line})
    return out


def files_written(paths, sample_dirs=("/samples/",)):
    out = []
    for c in _entries(paths):
        if c[5] not in FILE_OPS:
            continue
        caller = c[8] if len(c) > 8 else ""
        if not any(d in caller for d in sample_dirs):
            continue
        arg = c[11].strip("'") if len(c) > 11 else ""
        line = c[9] if len(c) > 9 else "0"
        out.append({"op": c[5], "path": arg, "caller": f"{caller}:{line}"})
    return out


def _first_arg(c):
    """eval/assert/include-class calls carry their payload in the include-file
    column (index 7) with argc 0; ordinary calls carry it as the first real
    argument (index 11). Pick whichever is populated."""
    argc = c[10] if len(c) > 10 else "0"
    if argc == "0" and len(c) > 7 and c[7]:
        return c[7]
    return c[11] if len(c) > 11 else ""


def dangerous_calls_from_trace(paths):
    agg = {}
    for c in _entries(paths):
        fn = c[5]
        if fn not in DANGEROUS:
            continue
        d = agg.setdefault(fn, {"function": fn, "count": 0, "first_arg": _first_arg(c)})
        d["count"] += 1
    return list(agg.values())
