"""Isolate prior samples and stage the new one. Filesystem work only; the
container recreate is done by run.py via shell.run."""
import json
import os
import re
import shutil
import sys
import zipfile
from datetime import datetime, timezone
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


# ---------------------------------------------------------------------------
# Database residue. The sample runs inside WordPress and its writes land in the
# shared DB: options it added, cron hooks it scheduled, posts it created (and
# their postmeta), stale `active_plugins` entries for a plugin whose files are
# gone. Only `--reset` (`make reset`, minutes) wiped that before; a second run
# of a sample that re-set the same option therefore produced an empty diff.
# A baseline of what the install legitimately holds is recorded once (after
# `--reset`, or on the first offering if none exists) and every later isolate
# deletes what is not in it. Names only: a sample that *changes* a stock
# option's value (users_can_register, admin_email) is not undone here.

DB_BASELINE = os.path.join(".kadath", "db-baseline.json")
# never deleted: WordPress rewrites these itself and they carry no evidence
VOLATILE_OPTION = re.compile(r"^(_transient_|_site_transient_|cron$|recently_activated$)")


def _json_list(out):
    try:
        v = json.loads(out) if out and out.strip() else []
    except ValueError:
        return []
    return v if isinstance(v, list) else []


def _ids(out):
    return [t for t in (out or "").split() if t.isdigit()]


def _option_names(wp_exec):
    return [o.get("option_name") for o in
            _json_list(wp_exec(["option", "list", "--format=json", "--fields=option_name"]))
            if isinstance(o, dict) and o.get("option_name")]


def _cron_hooks(wp_exec):
    return sorted({c.get("hook") for c in _json_list(wp_exec(["cron", "event", "list", "--format=json"]))
                   if isinstance(c, dict) and c.get("hook")})


def _post_ids(wp_exec):
    """Every post ID. `--post_status=any` drops trash and auto-draft (WP_Query
    excludes the exclude_from_search statuses), so those are asked for too."""
    ids = _ids(wp_exec(["post", "list", "--post_type=any", "--post_status=any", "--format=ids"]))
    ids += _ids(wp_exec(["post", "list", "--post_type=any", "--post_status=trash,auto-draft",
                         "--format=ids"]))
    return sorted(set(ids), key=int)


def _install_id(wp_exec):
    """Fingerprint of this WordPress install: the admin's registration time,
    set once by the installer. A manual `make reset` gives a new DB and a new
    value, which makes a baseline recorded against the old DB stale."""
    return (wp_exec(["user", "get", "1", "--field=user_registered"]) or "").strip()


def db_snapshot(wp_exec):
    return {"options": _option_names(wp_exec), "cron": _cron_hooks(wp_exec),
            "posts": _post_ids(wp_exec)}


def record_db_baseline(root, wp_exec):
    """Snapshot the install's legitimate DB contents to .kadath/db-baseline.json."""
    snap = db_snapshot(wp_exec)
    snap["install"] = _install_id(wp_exec)
    snap["recorded"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    path = os.path.join(root, DB_BASELINE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(snap, f, indent=1, sort_keys=True)
    return path


def load_db_baseline(root, wp_exec):
    """The recorded baseline, or None when there is none or it belongs to a
    different install (the DB was recreated under it)."""
    try:
        with open(os.path.join(root, DB_BASELINE)) as f:
            b = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(b, dict) or not all(isinstance(b.get(k), list) for k in ("options", "cron", "posts")):
        return None
    if b.get("install") and b["install"] != _install_id(wp_exec):
        return None
    return b


def reset_db(wp_exec, baseline):
    """Delete options, cron hooks and posts that are not in the baseline.
    Returns the actions taken."""
    actions = []
    keep = set(baseline["options"])
    for name in _option_names(wp_exec):
        if name in keep or VOLATILE_OPTION.search(name):
            continue
        wp_exec(["option", "delete", name])
        actions.append(f"delete option {name}")
    keep = set(baseline["cron"])
    for hook in _cron_hooks(wp_exec):
        if hook in keep:
            continue
        wp_exec(["cron", "event", "delete", hook])
        actions.append(f"delete cron {hook}")
    keep = set(baseline["posts"])
    stale = [pid for pid in _post_ids(wp_exec) if pid not in keep]
    if stale:
        # --force: a plain delete only moves the post to the trash, which is residue
        wp_exec(["post", "delete"] + stale + ["--force"])
        actions.extend(f"delete post {pid}" for pid in stale)
    return actions


def prune_active_plugins(wp_exec):
    """Rewrite active_plugins to the entries whose plugin file still exists.
    A previous sample's plugin is gone from samples/ by now, but the option
    still names it. Returns the entries removed."""
    cur = json.loads(wp_exec(["option", "get", "active_plugins", "--format=json"]) or "[]")
    if isinstance(cur, dict):
        cur = list(cur.values())
    if not isinstance(cur, list):
        cur = []
    present = {f.strip() for f in (wp_exec(["plugin", "list", "--field=file"]) or "").splitlines()
               if f.strip()}
    kept = [f for f in cur if f in present]
    removed = [f for f in cur if f not in present]
    if removed:
        wp_exec(["option", "update", "active_plugins", json.dumps(kept), "--format=json"])
    return removed


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
    # after clear_samples: the previous sample's files are gone from the bind
    # mount, so its active_plugins entry is now one without a file
    for f in prune_active_plugins(wp_exec):
        actions.append(f"remove stale active_plugins entry {f}")
    baseline = load_db_baseline(root, wp_exec)
    if baseline is None:
        path = record_db_baseline(root, wp_exec)
        print(f"note: no DB baseline for this install; recorded one from the live database at "
              f"{path} and skipped the DB reset this run (`--reset` records a pristine one)",
              file=sys.stderr)
        actions.append("recorded db baseline (first run; db reset skipped)")
    else:
        actions.extend(reset_db(wp_exec, baseline))
    clear_run_artifacts(root)
    actions.append("cleared prior traces/dumps")
    return actions


# The sample runs as uid 33 and can write anywhere under /var/www/html (the
# wp_html volume): an uploads shell, an mu-plugin, a .user.ini, a patched core
# file. That persists into the NEXT offering and pollutes its evidence, so the
# docroot is put back to the image's pristine tree (/usr/src/wordpress) first.
# wp-config.php goes too: appending to it is textbook WordPress persistence, and
# the entrypoint regenerates it (fresh salts) on the recreate that follows; every
# `wp` call of this offering happens after that. Symlinks go unconditionally (the pristine tree
# ships none, and a sample could swap a core dir for a link that would redirect
# the cp below); the entrypoint recreates the /samples links on recreate. DB
# residue is isolate()'s job (reset_db above). The cp also reverts the mitmproxy CA the
# entrypoint appended to WordPress's own TLS bundle, so that is re-applied last.
RESTORE_DOCROOT_SH = r"""set -e
cd /var/www/html
find . -type l -delete
find . \( -type f -o -type l \) -print | while IFS= read -r f; do [ -e "/usr/src/wordpress/$f" ] || rm -f "$f"; done
find . -mindepth 1 -type d -empty -delete
cp -a /usr/src/wordpress/. /var/www/html/
# the pristine bundle does not trust the proxy; re-apply what the entrypoint did
bundle=/var/www/html/wp-includes/certificates/ca-bundle.crt
if [ -f "$bundle" ] && [ -r /gateway-ca/mitmproxy-ca-cert.pem ] && ! grep -qF "KadathSandbox mitmproxy CA" "$bundle"; then
  { echo; echo "# KadathSandbox mitmproxy CA"; cat /gateway-ca/mitmproxy-ca-cert.pem; } >> "$bundle"
fi
"""


def restore_docroot(sh_exec):
    sh_exec(RESTORE_DOCROOT_SH)
    return "restored docroot from pristine core"


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


# Zip bombs: a few KB of zip can expand to terabytes under .kadath/unpack. The
# declared sizes are enforced by zipfile when extracting, so summing them is a
# sound pre-check.
MAX_ZIP_BYTES = 256 * 1024 * 1024
MAX_ZIP_ENTRIES = 20000


def _check_zip_limits(z):
    infos = z.infolist()
    if len(infos) > MAX_ZIP_ENTRIES:
        raise detect.UnsupportedSample(
            f"zip has {len(infos)} entries (limit {MAX_ZIP_ENTRIES}); refusing to unpack")
    total = sum(i.file_size for i in infos)
    if total > MAX_ZIP_BYTES:
        raise detect.UnsupportedSample(
            f"zip expands to {total} bytes (limit {MAX_ZIP_BYTES}); refusing to unpack")


def place(root, sample_path, detected, unpack_dir=None):
    if detected.type == "zip":
        target = unpack_dir or os.path.join(root, ".kadath", "unpack", detected.slug)
        if os.path.isdir(target):
            shutil.rmtree(target)
        with zipfile.ZipFile(sample_path) as z:
            _check_zip_limits(z)
            os.makedirs(target, exist_ok=True)
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
