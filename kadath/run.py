"""Orchestrate one offering: preflight, lock, isolate, stage, mark, trigger,
collect, emit. Shells out for all Docker/Make/wp work; touches no containment
config."""
import argparse
import fcntl
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


def _dbstate():
    users = _wp(["--skip-plugins", "user", "list",
                 "--fields=ID,user_login,user_email,roles", "--format=json"]) or "[]"
    options = _wp(["--skip-plugins", "option", "list", "--format=json"]) or "[]"
    cron = _wp(["--skip-plugins", "cron", "event", "list", "--format=json"]) or "[]"
    return dbdiff.state_from_json(users, options, cron)


def _bundle_artifacts(src, dest, epoch):
    """Copy every artifact file with mtime >= epoch (this run's) from src into
    dest, gzipping traces/logs and copying the rest verbatim. Pure filesystem;
    no Docker, so it is unit-testable. Returns the list of relative dest paths."""
    written = []
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
            if fn.endswith(_GZIP_EXT):
                out = os.path.join(dest, rel) + ".gz"
                with open(fp, "rb") as fi, gzip.open(out, "wb") as fo:
                    shutil.copyfileobj(fi, fo)
                written.append(rel + ".gz")
            else:
                shutil.copy2(fp, os.path.join(dest, rel))
                written.append(rel)
    return written


def _bundle_run(run_dir, epoch):
    """Write this run's durable evidence into the report dir: its artifacts
    (compressed) plus the container logs. Best-effort — a bundle failure must
    not fail the run."""
    try:
        _bundle_artifacts(os.path.join(ROOT, "artifacts"),
                          os.path.join(run_dir, "artifacts"), epoch)
    except OSError:
        pass
    try:
        out = sh(["docker", "compose", "logs", "--no-color", "wordpress", "gateway"],
                 cwd=ROOT).stdout
        with open(os.path.join(run_dir, "compose-logs.txt"), "w") as f:
            f.write(out)
    except (ShellError, OSError):
        pass


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

    try:
        if a.reset:
            try:
                sh(["make", "reset"], cwd=ROOT)
                sh(["make", "up"], cwd=ROOT)
            except ShellError as e:
                print(f"error: bringing the stack up failed\n{e.stderr}", file=sys.stderr)
                return 1
        elif not a.keep_active:
            stage.isolate(ROOT, lambda args: _wp(["--skip-plugins"] + args))

        staged = stage.place(ROOT, a.sample, det)
        if det.type == "zip":
            det = detect.Detected(_type_from_staged(staged, ROOT), det.slug,
                                  os.path.relpath(staged, ROOT))
        sh(["docker", "compose", "up", "-d", "--force-recreate", "--wait", "wordpress"], cwd=ROOT)

        # activation for plugin/theme (state change; wrapper keeps it untraced)
        if det.type in ("plugin", "directory-plugin"):
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
        before = _dbstate()

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
                actions = [recipe.Action("login", "admin", "sandbox")] + actions
        else:
            actions = trigger.default_actions(det)
        trigger.execute(session, actions)
        time.sleep(3)

        # collect
        after = _dbstate()
        traces = _new_files(os.path.join(ROOT, "artifacts/xdebug/*.xt"), epoch)
        sp_dumps = _new_files(os.path.join(ROOT, "artifacts/sp-dumps/*"), epoch)
        pcaps = _new_files(os.path.join(ROOT, "artifacts/pcap/*"), epoch)
        _bundle_run(run_dir, epoch)

        # assemble
        warnings = [] if traces else ["no new trace produced; sample may need a recipe"]
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
                    "trigger_actions": session.actions, "reset": a.reset}
        creds = _credentials_from_trace(traces)
        s = summary.build_summary(
            sample_meta, run_meta, db_diff, traceparse.callchain(traces),
            traceparse.dangerous_calls_from_trace(traces), traceparse.files_written(traces),
            net, {"traces": traces, "sp_dumps": sp_dumps, "pcaps": pcaps}, warnings)
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
