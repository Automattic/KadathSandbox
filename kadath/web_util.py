"""Pure helpers for the web server: multipart parsing, filename/host/path safety.
Standard library only."""
import email
import email.message
import email.utils
import os
import posixpath


def parse_multipart(content_type, body):
    """Parse a multipart/form-data body with the stdlib email parser.
    Returns (fields, files) where files maps name -> (filename, bytes)."""
    msg = email.message_from_bytes(
        b"Content-Type: " + content_type.encode() + b"\r\nMIME-Version: 1.0\r\n\r\n" + body)
    fields, files = {}, {}
    if not msg.is_multipart():
        return fields, files
    for part in msg.get_payload():
        disp = _disposition(part)
        name = _param_str(disp.get_param("name", header="content-disposition"))
        filename = _param_str(disp.get_param("filename", header="content-disposition"))
        payload = part.get_payload(decode=True) or b""
        if filename is not None:
            files[name] = (filename, payload)
        else:
            fields[name] = payload.decode("utf-8", "replace").strip()
    return fields, files


def _disposition(part):
    """A Message holding only this part's Content-Disposition, UTF-8 decoded.
    WHY: browsers send raw UTF-8 in filename=; the email parser keeps those bytes
    as surrogates and get_param on the part would turn them into U+FFFD."""
    raw = next((v for k, v in part.raw_items() if k.lower() == "content-disposition"), "")
    m = email.message.Message()
    m["Content-Disposition"] = raw.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    return m


def _param_str(v):
    """get_param returns a (charset, lang, value) tuple for RFC 2231 `name*=`."""
    if isinstance(v, tuple):
        try:
            v = email.utils.collapse_rfc2231_value(v)
        except Exception:
            v = v[-1]
    if isinstance(v, bytes):
        v = v.decode("utf-8", "replace")
    return v


MAX_FILENAME = 100


def sanitize_filename(name):
    base = posixpath.basename((_param_str(name) or "").replace("\\", "/"))
    # WHY isalnum per char: keep Unicode letters so the extension survives
    base = "".join(c if (c.isalnum() or c in "._-") else "_" for c in base)
    stem, ext = os.path.splitext(base)
    if len(ext) < 2:
        ext = ""
    ext = ext[:32]
    stem = stem.lstrip(".").strip("_") or "sample"
    return stem[:MAX_FILENAME - len(ext)] + ext


def host_allowed(host_header, port):
    return (host_header or "") in (f"127.0.0.1:{port}", f"localhost:{port}")


def origin_allowed(origin, port):
    """An Origin header is acceptable only if it is http://<an allowed host>."""
    origin = origin or ""
    return origin.startswith("http://") and host_allowed(origin[len("http://"):], port)


def artifact_allowlist(summary, report_dir):
    """Ordered, de-duplicated: report files, then the durable bundle, then the
    live paths. safe_artifact_path serves the first basename match, so the
    order is the precedence."""
    arts = summary.get("artifacts") or {}
    paths = [os.path.join(report_dir, n) for n in ("summary.json", "iocs.json", "run.env")]
    paths += [os.path.join(report_dir, p) for p in arts.get("bundle") or []]   # relative to the report dir
    for key in ("traces", "sp_dumps", "pcaps"):
        paths += list(arts.get(key) or [])
    allow = []
    for p in paths:
        rp = os.path.realpath(p)
        if rp not in allow:
            allow.append(rp)
    return allow


def safe_artifact_path(repo_root, allowlist, basename):
    root = os.path.realpath(repo_root)
    for p in allowlist:
        if os.path.basename(p) != basename:
            continue
        rp = os.path.realpath(p)
        if rp == root or rp.startswith(root + os.sep):
            return rp
        # basename matched but escapes repo_root: keep scanning for a valid one
    return None
