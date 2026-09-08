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


# Artifact subdirs safe to clear between runs: php-fpm writes a fresh Xdebug
# trace file per request and closes it, and Snuffleupagus writes one dump per
# rule and closes it. The append logs (dns, dropped, php-error, flows, pcap) are
# held open by long-lived containers and must NOT be deleted here.
_CLEARABLE_ARTIFACTS = ("xdebug", "sp-dumps")


def clear_run_artifacts(root):
    """Delete the previous run's Xdebug traces and Snuffleupagus dumps so
    artifacts/ holds only the current run. The durable copy lives in the run's
    report bundle. Leaves .gitkeep and every container-held log untouched."""
    for sub in _CLEARABLE_ARTIFACTS:
        d = os.path.join(root, "artifacts", sub)
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            if name == ".gitkeep":
                continue
            p = os.path.join(d, name)
            try:
                shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
            except OSError:
                pass


ADOPT_WRAPPER = "kadath-wrapper.php"
ADOPT_SHIMS = "kadath-shims.php"
ADOPT_SAMPLE = "sample.php"


def adopt(root, sample_path, slug):
    """Wrap a loose PHP file that expects WordPress underneath it as a synthetic
    plugin: a Plugin Name header, an (initially empty) shims file the Offering
    can fill, then the sample. Returns the directory to stage as a plugin."""
    d = os.path.join(root, ".kadath", "adopt", slug)
    if os.path.isdir(d):
        shutil.rmtree(d)
    os.makedirs(d)
    # the sample is copied under a fixed name: its own filename is attacker
    # data and must never be interpolated into generated PHP
    shutil.copy2(sample_path, os.path.join(d, ADOPT_SAMPLE))
    with open(os.path.join(d, ADOPT_SHIMS), "w") as f:
        f.write("<?php // kadath shims: no-op stand-ins for functions and classes the adopted file expects\n")
    with open(os.path.join(d, ADOPT_WRAPPER), "w") as f:
        f.write("<?php\n/*\nPlugin Name: kadath-adopted " + slug + "\n"
                "Description: KadathSandbox wrapper - a loose PHP file adopted as a plugin so WordPress is loaded beneath it.\n*/\n"
                f"require_once __DIR__ . '/{ADOPT_SHIMS}';\n"
                "// deferred: pluggable functions (is_user_logged_in, wp_mail, ...) load after\n"
                "// the plugin files, so a fragment that calls them at load time would fatal\n"
                "add_action('plugins_loaded', function () {\n"
                f"    require_once __DIR__ . '/{ADOPT_SAMPLE}';\n"
                "}, 0);\n")
    return d


def isolate(root, wp_exec):
    actions = []
    listing = wp_exec(["plugin", "list", "--field=name", "--status=active"])
    for name in [n.strip() for n in listing.splitlines() if n.strip()]:
        if name in _KEEP_PLUGINS:
            continue
        wp_exec(["plugin", "deactivate", name])
        actions.append(f"deactivate {name}")
    wp_exec(["theme", "activate", "twentytwentyfour"])
    # remove users a prior sample created (keep the install admin, ID 1) so
    # this run's users_added diff reflects only the current sample
    ids = wp_exec(["user", "list", "--field=ID"])
    for uid in ids.split():
        uid = uid.strip()
        if uid and uid != "1":
            wp_exec(["user", "delete", uid, "--yes"])
            actions.append(f"delete user {uid}")
    clear_samples(root)
    actions.append("cleared samples/")
    clear_run_artifacts(root)
    actions.append("cleared prior traces/dumps")
    return actions


def _classify_dir(path):
    """Classify an unpacked sample directory. Returns (type, staged_source):
    - ("plugin", <dir containing the plugin main .php>)
    - ("theme",  <dir containing style.css with 'Theme Name:'>)
    - ("webshell", <the single .php file>)
    Raises detect.UnsupportedSample if none match."""
    # descend through a single wrapper directory (the WordPress packaging convention)
    entries = [e for e in os.listdir(path) if not e.startswith("__MACOSX")]
    if len(entries) == 1 and os.path.isdir(os.path.join(path, entries[0])):
        path = os.path.join(path, entries[0])
    # theme: style.css with a Theme Name header, anywhere from here down
    for root, _dirs, files in os.walk(path):
        if "style.css" in files:
            sc = os.path.join(root, "style.css")
            try:
                with open(sc, "r", errors="replace") as f:
                    if "Theme Name:" in f.read(8192):
                        return ("theme", root)
            except OSError:
                pass
    # plugin: a .php with a Plugin Name header
    for root, _dirs, files in os.walk(path):
        for fn in files:
            if fn.endswith(".php"):
                try:
                    with open(os.path.join(root, fn), "r", errors="replace") as f:
                        if "Plugin Name:" in f.read(8192):
                            return ("plugin", root)
                except OSError:
                    pass
    # webshell: exactly one .php in the tree
    phps = [os.path.join(r, fn) for r, _d, fs in os.walk(path) for fn in fs if fn.endswith(".php")]
    if len(phps) == 1:
        return ("webshell", phps[0])
    raise detect.UnsupportedSample(f"zip contents at {path}: no plugin header, theme style.css, or single .php found")


def place(root, sample_path, detected, unpack_dir=None):
    if detected.type == "zip":
        target = unpack_dir or os.path.join(root, ".kadath", "unpack", detected.slug)
        if os.path.isdir(target):
            shutil.rmtree(target)
        os.makedirs(target, exist_ok=True)
        with zipfile.ZipFile(sample_path) as z:
            z.extractall(target)
        kind, src = _classify_dir(target)
        if kind == "plugin":
            dest = os.path.join(root, "samples/plugins", detected.slug)
            os.makedirs(dest, exist_ok=True)
            shutil.copytree(src, dest, dirs_exist_ok=True)
            return dest
        if kind == "theme":
            dest = os.path.join(root, "samples/themes", detected.slug)
            os.makedirs(dest, exist_ok=True)
            shutil.copytree(src, dest, dirs_exist_ok=True)
            return dest
        # webshell
        dest = os.path.join(root, "samples/webroot", os.path.basename(src))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(src, dest)
        return dest
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
