"""Orchestrate one offering: preflight, lock, isolate, stage, mark, trigger,
collect, emit. Shells out for all Docker/Make/wp work; touches no containment
config."""
import argparse
import fcntl
import fnmatch
import glob
import gzip
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import sys
import tempfile
import time
from datetime import datetime, timezone
from kadath import stubs, pcapslice

# Artifact file types worth compressing in a run bundle. Xdebug traces are the
# bulk (a page view is ~200 MB of tab-separated text, ~16x smaller gzipped); the
# text logs and the mitmproxy flow file compress well too.
_GZIP_EXT = (".xt", ".log", ".mitm")

from kadath import detect, stage, trigger, recipe, dbdiff, traceparse, network, summary
from kadath.shell import run as sh, ShellError
from kadath.wpsession import WpSession

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
URL = "http://127.0.0.1:8088"
SERVICES = ["db", "gateway", "wpnet", "netcap", "wordpress"]


def _type_from_staged(staged, root):
    """Resolve the actual sample type from where stage.place put it."""
    rel = os.path.relpath(staged, root)
    if rel.startswith("samples/plugins/"):
        return "plugin"
    if rel.startswith("samples/themes/"):
        return "theme"
    return "webshell"


def _wp(args):
    """Run wp inside the wordpress container (wrapper adds --skip-plugins)."""
    return sh(["docker", "compose", "exec", "-T", "wordpress", "wp"] + args,
              cwd=ROOT).stdout


def _wp_sh(script):
    """Run a bash script in the wordpress container (no PHP, no wp); stdout."""
    return sh(["docker", "compose", "exec", "-T", "wordpress", "bash", "-c", script],
              cwd=ROOT).stdout


def _tail(e, n=300):
    """The last n characters of a ShellError's stderr (or its exit code)."""
    err = (getattr(e, "stderr", "") or "").strip()
    return err[-n:] if err else f"exit {getattr(e, 'returncode', '?')}"


def _warn(warnings, msg):
    if msg not in warnings:
        warnings.append(msg)


def _regular_file(path):
    """True for a regular file, not following a final symlink."""
    return traceparse.regular_file(path)


def _open_artifact(path):
    """Open a sample-writable artifact for reading: no symlink, regular files only."""
    return traceparse.open_regular(path)


def _activate_direct(plugin_file, wp=None):
    """Activate a plugin by editing active_plugins, bypassing WordPress's
    activation sandbox. The sandbox executes the plugin inside WP-CLI — an
    adopted fragment that fatals or echoes there would abort the offering
    before the trigger, where the stub rounds could have handled it."""
    wp = wp or _wp
    cur = json.loads(wp(["--skip-plugins", "option", "get", "active_plugins", "--format=json"]) or "[]")
    if not isinstance(cur, list):
        cur = list(cur.values()) if isinstance(cur, dict) else []
    if plugin_file not in cur:
        cur.append(plugin_file)
        wp(["--skip-plugins", "option", "update", "active_plugins", json.dumps(cur), "--format=json"])
    return cur


def _healthy():
    try:
        out = sh(["docker", "compose", "ps", "--format", "{{.Service}} {{.Health}}"],
                 cwd=ROOT).stdout
    except ShellError:
        return False
    have = {line.split()[0]: (line.split()[1] if len(line.split()) > 1 else "")
            for line in out.splitlines() if line.strip()}
    return all(have.get(s) == "healthy" for s in SERVICES if s != "wpnet") and "wpnet" in have


def _build_id():
    out = sh(["docker", "compose", "images", "-q", "wordpress", "gateway"], cwd=ROOT).stdout
    return hashlib.sha256(out.encode()).hexdigest()[:16]


def _selftest_ok():
    marker = os.path.join(ROOT, ".kadath", "selftest-pass")
    if not os.path.exists(marker):
        return False
    return open(marker).read().strip() == _build_id()


def _record_selftest():
    os.makedirs(os.path.join(ROOT, ".kadath"), exist_ok=True)
    open(os.path.join(ROOT, ".kadath", "selftest-pass"), "w").write(_build_id())


def _admin_credentials():
    """The WordPress admin the sandbox was installed with: the process
    environment first, then ROOT/.env, then the stock sandbox login. Per key."""
    env = {}
    try:
        with open(os.path.join(ROOT, ".env")) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                if k.startswith("export "):
                    k = k[len("export "):].strip()
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                    v = v[1:-1]
                env[k] = v
    except OSError:
        pass
    user = os.environ.get("WP_ADMIN_USER") or env.get("WP_ADMIN_USER") or "admin"
    pw = os.environ.get("WP_ADMIN_PASSWORD") or env.get("WP_ADMIN_PASSWORD") or "sandbox"
    return user, pw


def _dbstate():
    users = _wp(["--skip-plugins", "user", "list",
                 "--fields=ID,user_login,user_email,roles", "--format=json"]) or "[]"
    options = _wp(["--skip-plugins", "option", "list", "--format=json"]) or "[]"
    cron = _wp(["--skip-plugins", "cron", "event", "list", "--format=json"]) or "[]"
    return dbdiff.state_from_json(users, options, cron)


def _dbstate_or_warn(before, warnings):
    """The post-trigger DB state. A sample running as uid 33 shares it with
    supervisord and can kill the container (kill 1); that is a result, not a
    crash: report it and fall back to the before state (an empty diff)."""
    try:
        return _dbstate()
    except ShellError:
        warnings.append("wordpress container unreachable after the trigger (the sample may have "
                        "killed php-fpm or supervisord); DB diff unavailable")
        return before


def _wp_started_at():
    """The wordpress container's State.StartedAt, or "" when unknown. A restart
    during a run changes it; a fast restart can make the after-state readable."""
    try:
        cid = sh(["docker", "compose", "ps", "-q", "wordpress"], cwd=ROOT).stdout.strip()
        if not cid:
            return ""
        return sh(["docker", "inspect", "-f", "{{.State.StartedAt}}", cid],
                  cwd=ROOT).stdout.strip()
    except ShellError:
        return ""


# Append-only logs and the flow file are held open by long-lived containers and
# never truncated, so a bundle copies only the bytes appended since the run began.
_PCAP_GLOB = "pcap/*.pcap*"
_FLOWS = "mitm/flows.mitm"
_TNETSTRING_START = re.compile(rb"\d+:")


def _flows_tail_ok(fp, offset):
    """A mitmproxy flow file is concatenated tnetstrings; a tail is only valid
    if it begins on a record boundary: ASCII digits then ':'."""
    with _open_artifact(fp) as f:
        f.seek(offset)
        return _TNETSTRING_START.match(f.read(32)) is not None


def _artifact_rel(path):
    base = os.path.join(ROOT, "artifacts")
    rel = os.path.relpath(path, base)
    return path if rel.startswith("..") else rel


def _bundle_file(fp, rel, dest, epoch, offsets, written, warnings):
    out = os.path.join(dest, rel)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    if fnmatch.fnmatch(rel, _PCAP_GLOB):
        w = pcapslice.slice_pcap(fp, out, epoch)
        if w:
            warnings.append(w)
        written.append(rel)
        return
    with _open_artifact(fp) as fi:
        start = 0
        if rel in offsets:
            start = offsets[rel] or 0
            size = os.fstat(fi.fileno()).st_size
            if start > size:
                warnings.append(f"{rel}: shrank below its recorded offset; copied the whole file")
                start = 0
            elif start == size:
                return      # nothing appended during this run
            elif rel == _FLOWS and start and not _flows_tail_ok(fp, start):
                warnings.append(f"{rel}: offset {start} is not a flow record boundary; "
                                "copied the whole file")
                start = 0
        fi.seek(start)
        if rel.endswith(_GZIP_EXT):
            with gzip.open(out + ".gz", "wb") as fo:
                shutil.copyfileobj(fi, fo)
            written.append(rel + ".gz")
        else:
            with open(out, "wb") as fo:
                shutil.copyfileobj(fi, fo)
            shutil.copystat(fp, out)
            written.append(rel)


def _bundle_artifacts(src, dest, epoch, offsets=None):
    """Copy every artifact file with mtime >= epoch (this run's) from src into
    dest, gzipping traces/logs and copying the rest verbatim. offsets maps a
    path relative to src to the byte offset recorded before the trigger: such a
    file contributes only its tail; the live pcap slice is cut to this run's
    packets. The sample can write to some of these dirs, so only regular files
    are read (no symlink followed, no FIFO opened): anything else is skipped
    with a warning, and one file failing does not stop the rest. Pure
    filesystem; no Docker, so it is unit-testable. Returns (relative dest
    paths, warnings)."""
    offsets = offsets or {}
    written, warnings = [], []
    for r, dirs, files in os.walk(src):
        for fn in list(files) + [d for d in dirs if os.path.islink(os.path.join(r, d))]:
            fp = os.path.join(r, fn)
            rel = os.path.relpath(fp, src)
            try:
                st = os.lstat(fp)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                _warn(warnings, f"skipped non-regular artifact {rel}")
                continue
            if fn == ".gitkeep" or st.st_mtime < epoch:
                continue
            try:
                _bundle_file(fp, rel, dest, epoch, offsets, written, warnings)
            except (OSError, ValueError) as e:
                warnings.append(f"bundle: {rel}: {e}")
    return written, warnings


def _bundle_run(run_dir, epoch, offsets=None):
    """Write this run's durable evidence into the report dir: its artifacts
    (compressed) plus the container logs. Best-effort — a bundle failure must
    not fail the run. Returns (written, warnings): written are paths relative
    to <run_dir>/artifacts/ ([] if the artifact copy failed)."""
    written, warnings = [], []
    try:
        written, warnings = _bundle_artifacts(os.path.join(ROOT, "artifacts"),
                                        os.path.join(run_dir, "artifacts"), epoch, offsets)
    except OSError:
        pass
    try:
        out = sh(["docker", "compose", "logs", "--no-color", "wordpress", "gateway"],
                 cwd=ROOT).stdout
        with open(os.path.join(run_dir, "compose-logs.txt"), "w", errors="replace") as f:
            f.write(out)
    except (ShellError, OSError, UnicodeDecodeError):
        pass
    return written, warnings


def _new_files(pattern, epoch, warnings=None):
    """Regular files matching pattern whose mtime is this run's. Never follows
    a link and never raises on a missing or dangling entry; anything else is
    skipped, with one warning per path when warnings is given."""
    out = []
    for p in sorted(glob.glob(pattern)):
        try:
            st = os.lstat(p)
        except (OSError, ValueError):
            continue
        if not stat.S_ISREG(st.st_mode):
            if warnings is not None:
                _warn(warnings, f"skipped non-regular artifact {_artifact_rel(p)}")
            continue
        if st.st_mtime >= epoch:
            out.append(p)
    return out


def _flows(epoch, mitm_off=0, dns_map=None):
    """Run the flowdump addon inside the gateway, scoped to the run epoch, over
    just the bytes appended since mitm_off when that is a record boundary (the
    whole file otherwise). Returns (flows, warnings): flows have wp_core
    verified against dns_map (network.verify_wp_core); a failure is a warning,
    not silence."""
    fp = os.path.join(ROOT, "artifacts", _FLOWS)
    tmp = None
    try:
        target = "/artifacts/mitm/flows.mitm"
        sh(["docker", "compose", "cp", "kadath/flowdump.py", "gateway:/tmp/flowdump.py"],
           cwd=ROOT, timeout=60)
        if mitm_off and _flows_tail_ok(fp, mitm_off):
            os.makedirs(os.path.join(ROOT, ".kadath"), exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix="flows-run-", dir=os.path.join(ROOT, ".kadath"))
            # mkstemp gives 0600 owned by the analyst; compose cp keeps that, and the
            # gateway's root has no CAP_DAC_OVERRIDE any more, so it could not read it
            os.fchmod(fd, 0o644)
            with os.fdopen(fd, "wb") as fo, _open_artifact(fp) as fi:
                fi.seek(mitm_off)
                shutil.copyfileobj(fi, fo)
            target = "/tmp/flows-run.mitm"
            sh(["docker", "compose", "cp", tmp, "gateway:" + target], cwd=ROOT, timeout=120)
        out = sh(["docker", "compose", "exec", "-T", "-e", f"RUN_EPOCH={epoch}", "gateway",
                  "mitmdump", "-nq", "-r", target, "-s", "/tmp/flowdump.py"],
                 cwd=ROOT, timeout=300).stdout
    except ShellError as e:
        reason = "timeout" if e.returncode == 124 else f"exit {e.returncode}: {_tail(e, 120)}"
        return [], [f"flow extraction failed ({reason}); network summary incomplete"]
    except (OSError, ValueError) as e:
        return [], [f"flow extraction failed ({e}); network summary incomplete"]
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    flows, bad = network.parse_flowdump_checked(out)
    warns = []
    if bad:
        warns.append(f"flow extraction failed ({bad} unparseable line(s)); network summary incomplete")
    return network.verify_wp_core(flows, dns_map or {}), warns


def _credentials_from_trace(traces):
    """Pull login+password pairs from wp_insert_user calls in the trace."""
    creds = []
    for t in traces:
        try:
            f = traceparse.open_regular(t, text=True)
        except (OSError, ValueError):
            continue
        with f:
            for line in f:
                c = line.split("\t")
                if len(c) > 11 and c[5] == "wp_insert_user":
                    blob = "\t".join(c[11:])
                    login = _between(blob, "'user_login' => '", "'")
                    pw = _between(blob, "'user_pass' => '", "'")
                    if login and pw:
                        creds.append({"login": login, "password": pw})
    return creds


def _hash_file(fileobj):
    sha, md = hashlib.sha256(), hashlib.md5()
    for chunk in iter(lambda: fileobj.read(1 << 20), b""):
        sha.update(chunk)
        md.update(chunk)
    return sha.hexdigest(), md.hexdigest()


def _hash_sample(path):
    """Return (sha256, md5) for a file, or for a directory a deterministic
    hash over a sorted manifest of per-entry hashes. Inside a directory only
    regular files are read; a symlink contributes its target string, anything
    else (FIFO, device, socket) just its name, so hashing never follows a link
    to a host file and never blocks."""
    if os.path.isfile(path):
        with open(path, "rb") as f:
            return _hash_file(f)
    entries = []
    for r, dirs, files in os.walk(path):
        for fn in sorted(files) + sorted(d for d in dirs if os.path.islink(os.path.join(r, d))):
            fp = os.path.join(r, fn)
            rel = os.path.relpath(fp, path)
            try:
                mode = os.lstat(fp).st_mode
                if stat.S_ISLNK(mode):
                    h = "link:" + os.readlink(fp)
                elif stat.S_ISREG(mode):
                    with open(fp, "rb") as f:
                        h = _hash_file(f)[0]
                else:
                    h = "special"
            except OSError:
                h = ""
            entries.append(f"{rel}\x00{h}")
    manifest = "\n".join(sorted(entries)).encode("utf-8", "surrogateescape")
    return hashlib.sha256(manifest).hexdigest(), hashlib.md5(manifest).hexdigest()


def _between(s, a, b):
    i = s.find(a)
    if i < 0:
        return None
    i += len(a)
    j = s.find(b, i)
    return s[i:j] if j > i else None


def _apply_slug(det, slug):
    """Return det with slug overridden and the plugin/theme dest segment updated."""
    new_dest = det.dest
    if det.type in ("plugin", "theme"):
        new_dest = re.sub(r"/[^/]+$", "/" + slug, det.dest)
    return detect.Detected(det.type, slug, new_dest)


_BUILD_TIMEOUT = 1800       # make up/reset/selftest build images; shell.run's default is 600
_WP_CONFIG_SHA = os.path.join(".kadath", "wp-config.sha256")


def _read_wp_config_sha():
    try:
        with open(os.path.join(ROOT, _WP_CONFIG_SHA)) as f:
            v = f.read().strip()
    except OSError:
        return ""
    return v if re.fullmatch(r"[0-9a-f]{64}", v) else ""


def _forget_wp_config_sha():
    try:
        os.unlink(os.path.join(ROOT, _WP_CONFIG_SHA))
    except OSError:
        pass


def _record_wp_config_sha(warnings):
    """Record the freshly generated wp-config.php's sha256 (the entrypoint just
    wrote it) for the after-run taint check and the next run's pre-check.
    Returns it, "" when it could not be read (and drops any stale record)."""
    try:
        sha = stage.wp_config_sha(_wp_sh)
        if sha:
            os.makedirs(os.path.join(ROOT, ".kadath"), exist_ok=True)
            with open(os.path.join(ROOT, _WP_CONFIG_SHA), "w") as f:
                f.write(sha + "\n")
            return sha
    except (ShellError, OSError) as e:
        warnings.append(f"could not record wp-config.php hash ({e.__class__.__name__}); "
                        "wp-config tampering cannot be checked this run")
        _forget_wp_config_sha()
        return ""
    _forget_wp_config_sha()
    warnings.append("could not read wp-config.php hash; wp-config tampering cannot be checked this run")
    return ""


def _recreate_wordpress():
    sh(["docker", "compose", "up", "-d", "--force-recreate", "--wait", "wordpress"],
       cwd=ROOT, timeout=_BUILD_TIMEOUT)


def _restore_or_fail():
    """restore_docroot; a failed restore is fatal (the docroot would still hold
    the previous sample's files). Returns 0 or an exit code."""
    try:
        stage.restore_docroot(_wp_sh)
    except ShellError as e:
        print(f"error: docroot restore failed: {_tail(e)}", file=sys.stderr)
        return 3
    return 0


def _clean_slate(wp, warnings):
    """Undo the previous sample: isolate() (plugins, users, DB residue, samples/)
    and restore the docroot. isolate runs wp, and wp loads wp-config.php and the
    mu-plugins/drop-ins, so when the previous run left any of those behind the
    docroot is restored and the container recreated FIRST; otherwise their
    persisted code would run during the cleanup. Returns 0 or an exit code."""
    try:
        tainted = stage.docroot_tainted(_wp_sh, _read_wp_config_sha())
    except ShellError as e:
        tainted = [f"taint check failed: {_tail(e, 120)}"]
    if tainted:
        warnings.append("the previous run left persisted code in the docroot "
                        f"({', '.join(tainted)}); restored and recreated before cleanup")
        rc = _restore_or_fail()
        if rc:
            return rc
        try:
            _recreate_wordpress()
        except ShellError as e:
            print(f"error: recreating wordpress failed: {_tail(e)}", file=sys.stderr)
            return 3
    # isolate() also deletes the DB residue (options, cron, posts, stale
    # active_plugins) a previous sample left, against the recorded baseline
    stage.isolate(ROOT, wp, warnings)
    # persistence across offerings: the previous sample may have dropped files
    # into the docroot volume or patched core
    return 0 if tainted else _restore_or_fail()


def _taint_after(sha, warnings):
    """The taint indicators present after the trigger, warning when there are
    any: the DB state read through wp is then untrusted."""
    try:
        tainted = stage.docroot_tainted(_wp_sh, sha)
    except ShellError as e:
        warnings.append(f"docroot taint check failed ({_tail(e, 120)}); "
                        "DB state read through wp is unverified")
        return []
    if tainted:
        warnings.append(f"docroot tainted during the run ({', '.join(tainted)}); "
                        "DB state read through wp is untrusted")
    return tainted


_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _env_value(v):
    """A run.env value: control characters removed, then shell-quoted. The
    scry skill does `set -a; . run.env`, and the sample's path is attacker data."""
    return shlex.quote(_CTRL.sub("", str(v)))


def _write_run_env(path, pairs):
    # surrogateescape: a non-UTF-8 filename must not raise after the run is done
    with open(path, "w", encoding="utf-8", errors="surrogateescape") as f:
        for k, v in pairs:
            f.write(f"{k}={_env_value(v)}\n")


def offer(argv):
    ap = argparse.ArgumentParser(prog="kadath offer")
    ap.add_argument("sample")
    ap.add_argument("--recipe")
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--slug")
    ap.add_argument("--skip-selftest", action="store_true")
    ap.add_argument("--keep-active", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--stub-missing", action="store_true",
                    help="stub missing includes/functions PHP reports and trigger again (up to 3 rounds)")
    ap.add_argument("--adopt-wp", action="store_true",
                    help="offer a loose .php that expects WordPress as a synthetic plugin instead of a bare webshell")
    a = ap.parse_args(argv)

    # detect
    try:
        det = detect.detect(a.sample)
    except detect.UnsupportedSample as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if a.slug:
        det = _apply_slug(det, a.slug)

    # a loose file the entrypoint will not link would leave the engine GETting
    # WordPress's own file of that name: refuse before touching the stack
    if det.type == "webshell" and not a.adopt_wp:
        try:
            stage.check_webroot_name(a.sample)
        except detect.UnsupportedSample as e:
            print(f"error: {e}", file=sys.stderr)
            return 2

    # lock: before the preflight, so a second offering cannot run make up /
    # selftest against a stack the first is already using
    os.makedirs(os.path.join(ROOT, ".kadath"), exist_ok=True)
    lock = open(os.path.join(ROOT, ".kadath", "offer.lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("error: another offering is in progress", file=sys.stderr)
        lock.close()
        return 2

    warnings = []
    try:
        # preflight: stack
        if not _healthy():
            print("bringing the stack up...", file=sys.stderr)
            try:
                sh(["make", "up"], cwd=ROOT, timeout=_BUILD_TIMEOUT)
            except ShellError as e:
                print(f"error: bringing the stack up failed\n{e.stderr}", file=sys.stderr)
                return 1

        # preflight: self-test gate
        if not _selftest_ok():
            if a.skip_selftest:
                print("warning: self-test not verified for this build; proceeding", file=sys.stderr)
            else:
                print("running self-test (gate)...", file=sys.stderr)
                try:
                    sh(["make", "selftest"], cwd=ROOT, timeout=_BUILD_TIMEOUT)
                except ShellError as e:
                    print(f"error: self-test failed; results would be untrustworthy\n{e.stderr}",
                          file=sys.stderr)
                    return 1
                _record_selftest()

        wp = lambda args: _wp(["--skip-plugins"] + args)
        if a.reset:
            try:
                sh(["make", "reset"], cwd=ROOT, timeout=_BUILD_TIMEOUT)
                sh(["make", "up"], cwd=ROOT, timeout=_BUILD_TIMEOUT)
            except ShellError as e:
                print(f"error: bringing the stack up failed\n{e.stderr}", file=sys.stderr)
                return 1
            _forget_wp_config_sha()
            # a fresh install: what the DB holds now is what every later
            # isolate() puts it back to
            stage.record_db_baseline(ROOT, wp)
        elif not a.keep_active:
            rc = _clean_slate(wp, warnings)
            if rc:
                return rc

        # a file lifted out of a plugin/theme dies on add_action() in a bare
        # webroot; adopt it as a plugin so WordPress is loaded beneath it
        adopted = False
        stage_src = a.sample
        if a.adopt_wp and det.type == "webshell":
            stage_src = stage.adopt(ROOT, a.sample, det.slug)
            det = detect.Detected("plugin", det.slug, f"samples/plugins/{det.slug}")
            adopted = True
        try:
            staged = stage.place(ROOT, stage_src, det)
        except detect.UnsupportedSample as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        if det.type == "zip":
            det = detect.Detected(_type_from_staged(staged, ROOT), det.slug,
                                  os.path.relpath(staged, ROOT))
        # a single file lifted out of a kit dies on its first require; stub the
        # literal includes up front, then let PHP name the rest after the trigger
        made_stubs, stub_files = [], []
        if a.stub_missing and os.path.isfile(staged):
            made_stubs, stub_files = stubs.prescan(staged, os.path.dirname(staged), ROOT)
        elif a.stub_missing and adopted:
            # the shims file loads before the sample, so it stays stub_files[0]
            shims = os.path.join(staged, stage.ADOPT_SHIMS)
            made_stubs, files = stubs.prescan(os.path.join(staged, stage.ADOPT_SAMPLE), staged, ROOT)
            stub_files = [shims] + files
        _recreate_wordpress()
        # the entrypoint just generated wp-config.php: remember it so a sample's
        # append (or a drop-in/mu-plugin) is caught before the DB state is read
        wp_sha = _record_wp_config_sha(warnings)

        # activation for plugin/theme (state change; wrapper keeps it untraced);
        # the sample may die under WP_CLI, which is not a reason to skip the trigger
        try:
            if adopted:
                _activate_direct(f"{det.slug}/{stage.ADOPT_WRAPPER}")
            elif det.type in ("plugin", "directory-plugin"):
                _wp(["--skip-plugins", "plugin", "activate", det.slug])
            elif det.type in ("theme", "directory-theme"):
                _wp(["--skip-plugins", "theme", "activate", det.slug])
        except ShellError as e:
            warnings.append(f"activation failed: {_tail(e)}")

        # mark + before-state
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        run_dir = os.path.join(ROOT, "reports", f"{det.slug}-{ts}")
        os.makedirs(run_dir, exist_ok=True)
        epoch = int(time.time())
        sha256, md5 = _hash_sample(a.sample)
        dns_log = os.path.join(ROOT, "artifacts/dns/dns.log")
        dns_off = traceparse.regular_size(dns_log)
        drop_off = traceparse.regular_size(os.path.join(ROOT, "artifacts/dropped.log"))
        err_log = os.path.join(ROOT, "artifacts/php/php-error.log")
        err_off = traceparse.regular_size(err_log)
        mitm_off = traceparse.regular_size(os.path.join(ROOT, "artifacts/mitm/flows.mitm"))
        access_off = traceparse.regular_size(os.path.join(ROOT, "artifacts/php/nginx-access.log"))
        before = _dbstate()
        started_before = _wp_started_at()

        # trigger
        session = WpSession(URL)
        rpath = a.recipe or recipe.discover(a.sample)
        if rpath:
            try:
                actions = recipe.parse(open(rpath).read())
            except (recipe.RecipeError, OSError) as e:
                print(f"error: {e}", file=sys.stderr)
                return 2
            if det.type in ("plugin", "theme", "directory-plugin", "directory-theme") and \
               not any(x.kind == "login" for x in actions):
                actions = [recipe.Action("login", *_admin_credentials())] + actions
        else:
            actions = trigger.default_actions(det, recipe.Action("login", *_admin_credentials()))
        trigger.execute(session, actions)
        time.sleep(3)
        if a.stub_missing:
            def _retrigger():
                session.actions.append("-- retrigger after stubbing --")
                trigger.execute(session, actions)
                time.sleep(3)
            made, fatal = stubs.stub_rounds(ROOT, err_log, err_off, _retrigger, stub_files=stub_files)
            made_stubs.extend(made)
        else:
            fatal = any(stubs.is_fatal(l) for l in stubs.new_lines(err_log, err_off))
        fatals = stubs.fatal_lines(stubs.new_lines(err_log, err_off))

        # collect
        # wp loads wp-config.php, mu-plugins and the drop-ins: if the sample
        # planted any, the DB state wp reports may be filtered by it
        docroot_tainted = _taint_after(wp_sha, warnings)
        after = _dbstate_or_warn(before, warnings)
        started_after = _wp_started_at()
        wp_restarted = bool(started_before and started_after and started_before != started_after)
        if wp_restarted:
            warnings.append("wordpress container restarted during the run (the sample likely "
                            "killed php-fpm or supervisord; the restart policy brought it back)")
        traces = _new_files(os.path.join(ROOT, "artifacts/xdebug/*.xt"), epoch, warnings)
        sp_dumps = _new_files(os.path.join(ROOT, "artifacts/sp-dumps/*"), epoch, warnings)
        pcaps = _new_files(os.path.join(ROOT, "artifacts/pcap/*"), epoch, warnings)
        offsets = {"dns/dns.log": dns_off, "dropped.log": drop_off,
                   "php/php-error.log": err_off, "php/nginx-access.log": access_off,
                   "mitm/flows.mitm": mitm_off}
        bundled, bundle_warnings = _bundle_run(run_dir, epoch, offsets)
        for w in bundle_warnings:
            _warn(warnings, w)
        bundle = sorted(os.path.join("artifacts", rel) for rel in bundled)

        # assemble
        if not traces:
            warnings.append("no new trace produced; sample may need a recipe")
        if session.logged_in is False:
            warnings.append("admin login failed; the sample ran unauthenticated "
                            "(check WP_ADMIN_USER/WP_ADMIN_PASSWORD in .env)")
        db_diff = dbdiff.diff(before, after)
        have_dns = os.path.exists(dns_log)
        flows, flow_warnings = _flows(epoch, mitm_off, network.dns_map_from_log(dns_log, dns_off)
                                      if have_dns else {})
        warnings.extend(flow_warnings)
        net = {
            "dns": network.dns_from_log(dns_log, dns_off) if have_dns else [],
            "flows": flows,
            "dropped": network.dropped_from_log(os.path.join(ROOT, "artifacts/dropped.log"), drop_off)
                       if os.path.exists(os.path.join(ROOT, "artifacts/dropped.log")) else [],
        }
        sample_meta = {"filename": os.path.basename(a.sample), "path": os.path.abspath(a.sample),
                       "sha256": sha256, "md5": md5,
                       "size_bytes": os.path.getsize(a.sample) if os.path.isfile(a.sample) else 0,
                       "type": det.type}
        run_meta = {"epoch": epoch, "utc": iso, "slug": det.slug,
                    "trigger_actions": session.actions, "reset": a.reset,
                    "stubs": made_stubs, "fatal": fatal, "fatals": fatals, "adopted": adopted,
                    "login_ok": session.logged_in, "wp_restarted": wp_restarted,
                    "docroot_tainted": docroot_tainted}
        creds = _credentials_from_trace(traces)
        files_written = traceparse.files_written(traces)
        s = summary.build_summary(
            sample_meta, run_meta, db_diff, traceparse.callchain(traces),
            traceparse.dangerous_calls_from_trace(traces), files_written,
            net, {"traces": traces, "sp_dumps": sp_dumps, "pcaps": pcaps, "bundle": bundle},
            warnings)
        iocs = summary.build_iocs(
            {k: sample_meta[k] for k in ("filename", "path", "sha256", "md5", "size_bytes")},
            iso, f"wp-sample/{det.type}", db_diff, files_written, net, creds)
        summary.validate_iocs(iocs)

        # run.env: sourced by the scry skill, so every value is quoted; the
        # trigger actions are in summary.json (run.trigger_actions), not here
        _write_run_env(os.path.join(run_dir, "run.env"), [
            ("RUN_EPOCH", epoch), ("RUN_UTC", iso), ("SLUG", det.slug),
            ("SAMPLE_SRC", os.path.abspath(a.sample)),
            ("SAMPLE_SHA256", sha256), ("SAMPLE_MD5", md5), ("SAMPLE_TYPE", det.type)])
        with open(os.path.join(run_dir, "summary.json"), "w") as f:
            json.dump(s, f, indent=2)
        with open(os.path.join(run_dir, "iocs.json"), "w") as f:
            json.dump(iocs, f, indent=2)

        if a.json:
            print(os.path.join(run_dir, "summary.json"))
        else:
            print(run_dir)
            for w in warnings:
                print("warning:", w, file=sys.stderr)
        return 0
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()
