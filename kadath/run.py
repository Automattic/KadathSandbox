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
import shutil
import subprocess
import sys
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
    with open(fp, "rb") as f:
        f.seek(offset)
        return _TNETSTRING_START.match(f.read(32)) is not None


def _bundle_artifacts(src, dest, epoch, offsets=None):
    """Copy every artifact file with mtime >= epoch (this run's) from src into
    dest, gzipping traces/logs and copying the rest verbatim. offsets maps a
    path relative to src to the byte offset recorded before the trigger: such a
    file contributes only its tail; the live pcap slice is cut to this run's
    packets. Pure filesystem; no Docker, so it is unit-testable. Returns
    (relative dest paths, warnings)."""
    offsets = offsets or {}
    written, warnings = [], []
    for r, _dirs, files in os.walk(src):
        for fn in files:
            if fn == ".gitkeep":
                continue
            fp = os.path.join(r, fn)
            try:
                if os.path.getmtime(fp) < epoch:
                    continue
            except OSError:
                continue
            rel = os.path.relpath(fp, src)
            os.makedirs(os.path.join(dest, os.path.dirname(rel)), exist_ok=True)
            if fnmatch.fnmatch(rel, _PCAP_GLOB):
                w = pcapslice.slice_pcap(fp, os.path.join(dest, rel), epoch)
                if w:
                    warnings.append(w)
                written.append(rel)
                continue
            start = 0
            if rel in offsets:
                start = offsets[rel] or 0
                try:
                    size = os.path.getsize(fp)
                except OSError:
                    continue
                if start > size:
                    warnings.append(f"{rel}: shrank below its recorded offset; copied the whole file")
                    start = 0
                elif start == size:
                    continue    # nothing appended during this run
                elif rel == _FLOWS and start and not _flows_tail_ok(fp, start):
                    warnings.append(f"{rel}: offset {start} is not a flow record boundary; "
                                    "copied the whole file")
                    start = 0
            if fn.endswith(_GZIP_EXT):
                out = os.path.join(dest, rel) + ".gz"
                with open(fp, "rb") as fi, gzip.open(out, "wb") as fo:
                    fi.seek(start)
                    shutil.copyfileobj(fi, fo)
                written.append(rel + ".gz")
            elif start:
                with open(fp, "rb") as fi, open(os.path.join(dest, rel), "wb") as fo:
                    fi.seek(start)
                    shutil.copyfileobj(fi, fo)
                written.append(rel)
            else:
                shutil.copy2(fp, os.path.join(dest, rel))
                written.append(rel)
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
        with open(os.path.join(run_dir, "compose-logs.txt"), "w") as f:
            f.write(out)
    except (ShellError, OSError):
        pass
    return written, warnings


def _new_files(pattern, epoch):
    return sorted(p for p in glob.glob(pattern) if os.path.getmtime(p) >= epoch)


def _flows(epoch):
    """Run the flowdump addon inside the gateway, scoped to the run epoch."""
    try:
        sh(["docker", "compose", "cp", "kadath/flowdump.py",
            "gateway:/tmp/flowdump.py"], cwd=ROOT)
        out = subprocess.run(
            ["docker", "compose", "exec", "-T", "-e", f"RUN_EPOCH={epoch}", "gateway",
             "mitmdump", "-nq", "-r", "/artifacts/mitm/flows.mitm", "-s", "/tmp/flowdump.py"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=120)
        return network.parse_flowdump(out.stdout)
    except Exception:
        print("warning: flow extraction failed", file=sys.stderr)
        return []


def _credentials_from_trace(traces):
    """Pull login+password pairs from wp_insert_user calls in the trace."""
    creds = []
    for t in traces:
        try:
            f = open(t, "r", errors="replace")
        except OSError:
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


def _hash_sample(path):
    """Return (sha256, md5) for a file, or for a directory a deterministic
    hash over a sorted manifest of per-file hashes."""
    if os.path.isfile(path):
        data = open(path, "rb").read()
        return hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest()
    entries = []
    for r, _d, files in os.walk(path):
        for fn in sorted(files):
            fp = os.path.join(r, fn)
            rel = os.path.relpath(fp, path)
            try:
                h = hashlib.sha256(open(fp, "rb").read()).hexdigest()
            except OSError:
                h = ""
            entries.append(f"{rel}\x00{h}")
    manifest = "\n".join(sorted(entries)).encode()
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

    # preflight: stack
    if not _healthy():
        print("bringing the stack up...", file=sys.stderr)
        try:
            sh(["make", "up"], cwd=ROOT)
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
                sh(["make", "selftest"], cwd=ROOT)
            except ShellError as e:
                print(f"error: self-test failed; results would be untrustworthy\n{e.stderr}",
                      file=sys.stderr)
                return 1
            _record_selftest()

    # lock
    os.makedirs(os.path.join(ROOT, ".kadath"), exist_ok=True)
    lock = open(os.path.join(ROOT, ".kadath", "offer.lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("error: another offering is in progress", file=sys.stderr)
        return 2

    warnings = []
    try:
        wp = lambda args: _wp(["--skip-plugins"] + args)
        if a.reset:
            try:
                sh(["make", "reset"], cwd=ROOT)
                sh(["make", "up"], cwd=ROOT)
            except ShellError as e:
                print(f"error: bringing the stack up failed\n{e.stderr}", file=sys.stderr)
                return 1
            # a fresh install: what the DB holds now is what every later
            # isolate() puts it back to
            stage.record_db_baseline(ROOT, wp)
        elif not a.keep_active:
            # isolate() also deletes the DB residue (options, cron, posts, stale
            # active_plugins) a previous sample left, against the recorded baseline
            stage.isolate(ROOT, wp)
            # persistence across offerings: the previous sample may have dropped
            # files into the docroot volume or patched core.
            try:
                stage.restore_docroot(lambda script: sh(
                    ["docker", "compose", "exec", "-T", "wordpress", "sh", "-c", script], cwd=ROOT))
            except ShellError as e:
                warnings.append("docroot restore failed; files a previous sample left in the "
                                f"docroot may taint this run: {str(e).splitlines()[0]}")

        # a file lifted out of a plugin/theme dies on add_action() in a bare
        # webroot; adopt it as a plugin so WordPress is loaded beneath it
        adopted = False
        stage_src = a.sample
        if a.adopt_wp and det.type == "webshell":
            stage_src = stage.adopt(ROOT, a.sample, det.slug)
            det = detect.Detected("plugin", det.slug, f"samples/plugins/{det.slug}")
            adopted = True
        staged = stage.place(ROOT, stage_src, det)
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
        sh(["docker", "compose", "up", "-d", "--force-recreate", "--wait", "wordpress"], cwd=ROOT)

        # activation for plugin/theme (state change; wrapper keeps it untraced)
        if adopted:
            _activate_direct(f"{det.slug}/{stage.ADOPT_WRAPPER}")
        elif det.type in ("plugin", "directory-plugin"):
            _wp(["--skip-plugins", "plugin", "activate", det.slug])
        elif det.type in ("theme", "directory-theme"):
            _wp(["--skip-plugins", "theme", "activate", det.slug])

        # mark + before-state
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        run_dir = os.path.join(ROOT, "reports", f"{det.slug}-{ts}")
        os.makedirs(run_dir, exist_ok=True)
        epoch = int(time.time())
        sha256, md5 = _hash_sample(a.sample)
        dns_off = os.path.getsize(os.path.join(ROOT, "artifacts/dns/dns.log")) if os.path.exists(os.path.join(ROOT, "artifacts/dns/dns.log")) else 0
        drop_off = os.path.getsize(os.path.join(ROOT, "artifacts/dropped.log")) if os.path.exists(os.path.join(ROOT, "artifacts/dropped.log")) else 0
        err_log = os.path.join(ROOT, "artifacts/php/php-error.log")
        err_off = os.path.getsize(err_log) if os.path.exists(err_log) else 0
        mitm_log = os.path.join(ROOT, "artifacts/mitm/flows.mitm")
        mitm_off = os.path.getsize(mitm_log) if os.path.exists(mitm_log) else 0
        access_log = os.path.join(ROOT, "artifacts/php/nginx-access.log")
        access_off = os.path.getsize(access_log) if os.path.exists(access_log) else 0
        before = _dbstate()
        started_before = _wp_started_at()

        # trigger
        session = WpSession(URL)
        if a.recipe or os.path.exists(a.sample + ".kadath"):
            rpath = a.recipe or (a.sample + ".kadath")
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
        after = _dbstate_or_warn(before, warnings)
        started_after = _wp_started_at()
        wp_restarted = bool(started_before and started_after and started_before != started_after)
        if wp_restarted:
            warnings.append("wordpress container restarted during the run (the sample likely "
                            "killed php-fpm or supervisord; the restart policy brought it back)")
        traces = _new_files(os.path.join(ROOT, "artifacts/xdebug/*.xt"), epoch)
        sp_dumps = _new_files(os.path.join(ROOT, "artifacts/sp-dumps/*"), epoch)
        pcaps = _new_files(os.path.join(ROOT, "artifacts/pcap/*"), epoch)
        offsets = {"dns/dns.log": dns_off, "dropped.log": drop_off,
                   "php/php-error.log": err_off, "php/nginx-access.log": access_off,
                   "mitm/flows.mitm": mitm_off}
        bundled, bundle_warnings = _bundle_run(run_dir, epoch, offsets)
        warnings.extend(bundle_warnings)
        bundle = sorted(os.path.join("artifacts", rel) for rel in bundled)

        # assemble
        if not traces:
            warnings.append("no new trace produced; sample may need a recipe")
        if session.logged_in is False:
            warnings.append("admin login failed; the sample ran unauthenticated "
                            "(check WP_ADMIN_USER/WP_ADMIN_PASSWORD in .env)")
        db_diff = dbdiff.diff(before, after)
        net = {
            "dns": network.dns_from_log(os.path.join(ROOT, "artifacts/dns/dns.log"), dns_off)
                   if os.path.exists(os.path.join(ROOT, "artifacts/dns/dns.log")) else [],
            "flows": _flows(epoch),
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
                    "login_ok": session.logged_in, "wp_restarted": wp_restarted}
        creds = _credentials_from_trace(traces)
        s = summary.build_summary(
            sample_meta, run_meta, db_diff, traceparse.callchain(traces),
            traceparse.dangerous_calls_from_trace(traces), traceparse.files_written(traces),
            net, {"traces": traces, "sp_dumps": sp_dumps, "pcaps": pcaps, "bundle": bundle},
            warnings)
        iocs = summary.build_iocs(
            {k: sample_meta[k] for k in ("filename", "path", "sha256", "md5", "size_bytes")},
            iso, f"wp-sample/{det.type}", db_diff, traceparse.files_written(traces), net, creds)
        summary.validate_iocs(iocs)

        # run.env
        with open(os.path.join(run_dir, "run.env"), "w") as f:
            f.write(f"RUN_EPOCH={epoch}\nRUN_UTC={iso}\nSLUG={det.slug}\n")
            f.write(f"SAMPLE_SRC={os.path.abspath(a.sample)}\n")
            f.write(f"SAMPLE_SHA256={sha256}\nSAMPLE_MD5={md5}\nSAMPLE_TYPE={det.type}\n")
            f.write("TRIGGER_ACTIONS=" + " | ".join(session.actions) + "\n")
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
