"""Classify a sample path into a type, a slug, and the samples/ dest dir."""
import os
import re
from dataclasses import dataclass


class UnsupportedSample(ValueError):
    pass


@dataclass
class Detected:
    type: str
    slug: str
    dest: str


def _slug(name):
    base = re.sub(r"\.(php|zip)$", "", os.path.basename(name.rstrip("/")))
    s = re.sub(r"[^A-Za-z0-9]+", "-", base).strip("-").lower()
    return s or "sample"


def _has_marker(path, marker):
    try:
        with open(path, "r", errors="replace") as f:
            return marker in f.read(8192)
    except OSError:
        return False


def detect(path):
    if not os.path.exists(path):
        raise UnsupportedSample(f"no such sample: {path}")
    slug = _slug(path)
    if os.path.isdir(path):
        style = os.path.join(path, "style.css")
        if os.path.isfile(style) and _has_marker(style, "Theme Name:"):
            return Detected("theme", slug, f"samples/themes/{slug}")
        for root, _dirs, files in os.walk(path):
            for fn in files:
                if fn.endswith(".php") and _has_marker(os.path.join(root, fn), "Plugin Name:"):
                    return Detected("plugin", slug, f"samples/plugins/{slug}")
        raise UnsupportedSample(f"directory {path}: no 'Theme Name:' in style.css and no 'Plugin Name:' in any .php")
    if path.endswith(".zip"):
        return Detected("zip", slug, "")  # unpack+re-detect handled in stage.py
    if path.endswith(".php"):
        if _has_marker(path, "Plugin Name:"):
            return Detected("plugin", slug, f"samples/plugins/{slug}")
        return Detected("webshell", slug, f"samples/webroot/{os.path.basename(path)}")
    raise UnsupportedSample(f"unsupported sample {path}: not a .php, .zip, or plugin/theme directory")
