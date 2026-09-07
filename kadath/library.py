"""Walk the threat library's for-later-review tree and compute the cheap
static facts the Cavern prompt is built from. Filesystem and text only."""
import collections
import hashlib
import math
import os
import re
from kadath import traceparse

Case = collections.namedtuple("Case", "id dir php readme skip_reason")

DANGEROUS_FUNCS = tuple(traceparse.DANGEROUS) + tuple(traceparse.FILE_OPS) + (
    "str_rot13", "gzuncompress", "gzdecode", "preg_replace", "unserialize",
    "include", "include_once", "require", "require_once", "chmod", "mail")
_LOCAL_OR_REMOTE = ("file_get_contents", "fopen")
NETWORK_FUNCS = ("curl_init", "curl_exec", "fsockopen", "stream_socket_client",
                 "file_get_contents", "fopen", "wp_remote_get", "wp_remote_post",
                 "wp_remote_request", "socket_create")
_WP_API = re.compile(r"\b(wp_[a-z0-9_]+|add_action|add_filter|update_option|get_option|"
                     r"add_option|delete_option|update_user_meta|wp_schedule_event)\s*\(", re.IGNORECASE)
_BLOB = re.compile(r"[A-Za-z0-9+/=]{200,}|(?:\\x[0-9a-fA-F]{2}){20,}")
_LITERAL = re.compile(r"'([^'\\]|\\.)*'|\"([^\"\\]|\\.)*\"")


_WANTS_WP = re.compile(r"(?:\bABSPATH\b|\bWPINC\b|\$wpdb\b|\bWP_[A-Z][A-Za-z_]+|\bwp_[a-z0-9_]+\s*\(|"
                       r"\badd_(?:action|filter)\s*\(|\bget_option\s*\(|\bget_template_directory|wp-load\.php)")


def wants_wordpress(path):
    """True when a loose PHP file expects WordPress to be loaded beneath it —
    it should be offered adopted as a plugin rather than as a bare webshell."""
    try:
        with open(path, "rb") as f:
            text = f.read().decode("utf-8", errors="replace")
    except OSError:
        return False
    return bool(_WANTS_WP.search(text))


def walk(library_dir):
    out = []
    for name in sorted(os.listdir(library_dir)):
        d = os.path.join(library_dir, name)
        if not os.path.isdir(d) or name.startswith(".") or name.startswith("kadath-"):
            continue
        phps = []
        for r, ds, fs in os.walk(d):
            # Skip hidden directories in inner walk
            ds[:] = [x for x in ds if not x.startswith(".")]
            phps.extend(sorted(os.path.join(r, fn) for fn in fs if fn.lower().endswith(".php")))
        phps = sorted(phps)
        readme = os.path.join(d, "README.md")
        readme = readme if os.path.isfile(readme) else None
        if not phps:
            out.append(Case(name, d, None, readme, "no-php"))
        elif len(phps) > 1:
            out.append(Case(name, d, None, readme, "multi-file"))
        else:
            out.append(Case(name, d, phps[0], readme, None))
    return out


def provenance(readme_path):
    try:
        with open(readme_path, errors="replace") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    return s[:300]
    except (OSError, TypeError):
        pass
    return ""


def _entropy(data):
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def static_facts(path):
    with open(path, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8", errors="replace")
    dangerous = {}
    for fn in DANGEROUS_FUNCS:
        n = len(re.findall(r"\b" + re.escape(fn) + r"\s*\(", text, re.IGNORECASE))
        if n:
            dangerous[fn.lower()] = n
    # file_get_contents/fopen read local files far more often than URLs; they
    # count as network primitives only when the file names a URL scheme too
    has_url = bool(re.search(r"\b(?:https?|ftp)://", text, re.IGNORECASE))
    network = sorted({fn.lower() for fn in NETWORK_FUNCS
                      if re.search(r"\b" + re.escape(fn) + r"\s*\(", text, re.IGNORECASE)
                      and (has_url or fn not in _LOCAL_OR_REMOTE)})
    wp_api = sorted({m.group(1).lower() for m in _WP_API.finditer(text)})
    longest = max((m.end() - m.start() - 2 for m in _LITERAL.finditer(text)), default=0)
    return {
        "sha1": hashlib.sha1(raw).hexdigest(), "sha256": hashlib.sha256(raw).hexdigest(),
        "md5": hashlib.md5(raw).hexdigest(), "size": len(raw),
        "lines": text.count("\n") + (0 if text.endswith("\n") or not text else 1),
        "entropy": round(_entropy(raw), 3), "dangerous": dangerous, "wp_api": wp_api,
        "network": network, "longest_literal": longest, "has_blob": bool(_BLOB.search(text)),
    }


def _interesting(line):
    return bool(_BLOB.search(line)) or any(
        re.search(r"\b" + re.escape(fn) + r"\s*\(", line, re.IGNORECASE) for fn in DANGEROUS_FUNCS + NETWORK_FUNCS)


def source_view(path, limit=65536, head=24576, tail=8192):
    with open(path, "rb") as f:
        raw = f.read()
    lines = raw.decode("utf-8", errors="replace").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if len(raw) <= limit:
        return "\n".join(f"{i + 1}| {l}" for i, l in enumerate(lines)), False
    keep = set()
    acc = 0
    for i, l in enumerate(lines):
        acc += len(l) + 1
        if acc > head:
            break
        keep.add(i)
    acc = 0
    for i in range(len(lines) - 1, -1, -1):
        acc += len(lines[i]) + 1
        if acc > tail:
            break
        keep.add(i)
    for i, l in enumerate(lines):
        if i not in keep and _interesting(l):
            keep.add(i)
    out = []
    prev = -1
    for i in sorted(keep):
        if i != prev + 1:
            out.append(f"... [lines {prev + 2}-{i} omitted]")
        out.append(f"{i + 1}| {lines[i][:2000]}")
        prev = i
    if prev < len(lines) - 1:
        out.append(f"... [lines {prev + 2}-{len(lines)} omitted]")
    return "\n".join(out), True
