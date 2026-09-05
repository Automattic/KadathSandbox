"""Pure helpers for the web server: multipart parsing, filename/host/path safety.
Standard library only."""
import email
import os
import re


def parse_multipart(content_type, body):
    """Parse a multipart/form-data body with the stdlib email parser.
    Returns (fields, files) where files maps name -> (filename, bytes)."""
    msg = email.message_from_bytes(
        b"Content-Type: " + content_type.encode() + b"\r\nMIME-Version: 1.0\r\n\r\n" + body)
    fields, files = {}, {}
    if not msg.is_multipart():
        return fields, files
    for part in msg.get_payload():
        name = part.get_param("name", header="content-disposition")
        filename = part.get_param("filename", header="content-disposition")
        payload = part.get_payload(decode=True) or b""
        if filename is not None:
            files[name] = (filename, payload)
        else:
            fields[name] = payload.decode("utf-8", "replace").strip()
    return fields, files


def sanitize_filename(name):
    base = os.path.basename((name or "").replace("\\", "/"))
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base).strip("_.") or "sample"
    return base


def host_allowed(host_header, port):
    return (host_header or "") in (f"127.0.0.1:{port}", f"localhost:{port}")


def artifact_allowlist(summary, report_dir):
    allow = set()
    arts = summary.get("artifacts", {})
    for key in ("traces", "sp_dumps", "pcaps"):
        for p in arts.get(key, []):
            allow.add(os.path.realpath(p))
    for name in ("summary.json", "iocs.json", "run.env"):
        allow.add(os.path.realpath(os.path.join(report_dir, name)))
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
