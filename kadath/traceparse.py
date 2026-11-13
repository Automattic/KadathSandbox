"""Parse Xdebug computerized traces (format 4, tab-separated). Files are huge;
stream line by line, never load whole."""
import os
import stat

DANGEROUS = ("eval", "assert", "system", "exec", "shell_exec", "passthru",
             "proc_open", "popen", "base64_decode", "gzinflate",
             "create_function", "call_user_func")
FILE_OPS = ("file_put_contents", "fwrite", "fputs", "move_uploaded_file",
            "rename", "copy", "unlink")


FILES_WRITTEN_CAP = 2000
_SEEN_CAP = 100000      # bound the dedupe set; entries past it are only counted


def regular_file(path):
    """True for a regular file, not following a final symlink. The artifact
    dirs are writable by the sample: a planted link, FIFO or device must never
    be opened on the host."""
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except (OSError, ValueError):
        return False


def regular_size(path):
    """Size of a regular file, 0 for anything else (missing, link, FIFO)."""
    try:
        st = os.lstat(path)
    except (OSError, ValueError):
        return 0
    return st.st_size if stat.S_ISREG(st.st_mode) else 0


def open_regular(path, text=False):
    """Open an artifact file read-only without following a symlink and refuse
    anything that is not a regular file (O_NONBLOCK so a FIFO swapped in after
    the lstat cannot hang us). Raises OSError. text=True decodes with
    errors='replace'."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"not a regular file: {path}")
        return os.fdopen(fd, "r", errors="replace") if text else os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def _entries(paths):
    """Yield (cols) for entry records (col3 == '0') across all paths."""
    for p in paths:
        try:
            f = open_regular(p, text=True)
        except (OSError, ValueError):
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
    """File-op calls from sample code, one entry per (op, path), at most
    FILES_WRITTEN_CAP of them; the rest is summarised by a final
    {"op": "truncated", "path": "...and N more"} entry."""
    out, seen, more = [], set(), 0
    for c in _entries(paths):
        if c[5] not in FILE_OPS:
            continue
        caller = c[8] if len(c) > 8 else ""
        if not any(d in caller for d in sample_dirs):
            continue
        arg = c[11].strip("'") if len(c) > 11 else ""
        line = c[9] if len(c) > 9 else "0"
        key = (c[5], arg)
        if key in seen:
            continue
        if len(seen) < _SEEN_CAP:
            seen.add(key)
        if len(out) >= FILES_WRITTEN_CAP:
            more += 1
            continue
        out.append({"op": c[5], "path": arg, "caller": f"{caller}:{line}"})
    if more:
        out.append({"op": "truncated", "path": f"...and {more} more", "caller": ""})
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
