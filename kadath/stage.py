"""Isolate prior samples and stage the new one. Filesystem work only; the
container recreate is done by run.py via shell.run."""
import os
import shutil
import zipfile
from kadath import detect

_KEEP_PLUGINS = {"akismet", "hello"}
_SAMPLE_SUBS = ("plugins", "themes", "webroot")


def clear_samples(root):
    for sub in _SAMPLE_SUBS:
        d = os.path.join(root, "samples", sub)
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            if name == ".gitkeep":
                continue
            p = os.path.join(d, name)
            shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)


def isolate(root, wp_exec):
    actions = []
    listing = wp_exec(["plugin", "list", "--field=name", "--status=active"])
    for name in [n.strip() for n in listing.splitlines() if n.strip()]:
        if name in _KEEP_PLUGINS:
            continue
        wp_exec(["plugin", "deactivate", name])
        actions.append(f"deactivate {name}")
    wp_exec(["theme", "activate", "twentytwentyfour"])
    clear_samples(root)
    actions.append("cleared samples/")
    return actions


def place(root, sample_path, detected, unpack_dir=None):
    if detected.type == "zip":
        target = unpack_dir or os.path.join(root, ".kadath", "unpack", detected.slug)
        os.makedirs(target, exist_ok=True)
        with zipfile.ZipFile(sample_path) as z:
            z.extractall(target)
        inner = detect.detect(target)
        # inner.dest is derived from the unpack dir name; re-slug to the zip's slug
        inner = detect.Detected(inner.type, detected.slug,
                                 inner.dest.replace(f"/{os.path.basename(target)}", f"/{detected.slug}")
                                 if inner.type in ("plugin", "theme") else inner.dest)
        return place(root, target, inner)
    dest = os.path.join(root, detected.dest)
    if detected.type in ("plugin", "theme"):
        os.makedirs(dest, exist_ok=True)
        if os.path.isdir(sample_path):
            shutil.copytree(sample_path, dest, dirs_exist_ok=True)
        else:
            shutil.copy2(sample_path, dest)
    else:  # webshell -> single file into webroot
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(sample_path, dest)
    return dest
