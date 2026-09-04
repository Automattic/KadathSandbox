# Detonate CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A single host-side command, `bin/kadath detonate <sample>`, that stages an untrusted WordPress sample, brings the sandbox up, triggers it by type (or by a recipe file), attributes the run's artifacts, and emits `summary.json` + `iocs.json` of deterministic facts.

**Architecture:** A pure-standard-library Python 3 package `kadath/` with small single-responsibility modules (detect, traceparse, dbdiff, network, recipe, stage, trigger, summary, run) plus a thin `bin/kadath` dispatcher and a `make detonate` wrapper. The parsing modules are pure functions tested against real-format fixtures; the orchestration module shells out to `make`, `docker compose`, and `wp`. Nothing imports a Docker SDK or touches containment config.

**Tech Stack:** Python 3.9+ (host `python3`, standard library only — no pip installs), pytest for unit tests, bash for the end-to-end acceptance test, existing `make`/`docker compose`/`wp` tooling.

**Spec:** `docs/superpowers/specs/2026-09-04-detonate-cli-design.md`

## Global Constraints

- Python 3, **standard library only**. No third-party imports in `kadath/` or `bin/kadath`. pytest is a dev/test tool, invoked as `python3 -m pytest`.
- The engine only ever calls: `make up/reset/snapshot/selftest`, `docker compose up/exec/logs/images`, `mitmdump` inside the gateway, and HTTP to `http://127.0.0.1:8088`. It never edits `docker-compose.yml`, `netguard/`, `gateway/`, or any container security setting; never adds a capability; never publishes a port.
- The sample and every artifact are DATA: parsed, hashed, quoted — never executed on the host. The recipe format is declarative and cannot run host commands.
- Every `wp` call that reads ground-truth state uses `--skip-plugins` so the sample's own hooks cannot filter it.
- Host URL is `http://127.0.0.1:8088`. Never touch host port 8080.
- `iocs.json` conforms to `.claude/skills/kadath-analyze/references/iocs-schema.json`.
- One detonation at a time (flock on `.kadath/detonate.lock`). `.kadath/` and `reports/` are gitignored.
- Xdebug trace format: tab-separated, `xdebug.trace_format=1`. Entry record columns: 1 depth, 2 func#, 3 type (`0`=entry,`1`=exit,`R`=return,`A`=assign), 4 time, 5 mem, 6 function name, 7 user-defined flag, 8 include-file, 9 caller file, 10 caller line, 11 argc, 12+ rendered args. Return value is the last field of the matching `R` record.
- Commit messages end with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.

---

## File map

| Path | Responsibility |
|---|---|
| `bin/kadath` | executable dispatcher: parse argv, call `kadath.run.detonate` |
| `kadath/__init__.py` | package marker, version |
| `kadath/detect.py` | classify a sample path into a type + target subdir + slug |
| `kadath/traceparse.py` | callchain, files_written, dangerous_calls from `.xt` files |
| `kadath/dbdiff.py` | diff before/after `wp ... --format=json` dumps |
| `kadath/network.py` | dns/dropped (byte-offset) + flows (mitmdump addon json) summary |
| `kadath/recipe.py` | parse a `.kadath` recipe into request objects |
| `kadath/wpsession.py` | tiny stdlib HTTP client with cookie jar for LOGIN/GET/POST |
| `kadath/stage.py` | isolate prior samples, copy the sample in, recreate wordpress |
| `kadath/trigger.py` | default per-type triggers + recipe execution, returns actions |
| `kadath/summary.py` | assemble summary.json + iocs.json dicts from component outputs |
| `kadath/shell.py` | run a subprocess, capture stdout/stderr, raise on failure |
| `kadath/run.py` | the orchestration flow: preflight, lock, stage, mark, trigger, collect, emit |
| `kadath/flowdump.py` | mitmproxy addon: emit one JSON line per flow in the run window |
| `Makefile` | `+ detonate` target |
| `tests/fixtures/` | real-format `.xt`, before/after wp json, dns/dropped lines, a `.kadath` |
| `tests/test_*.py` | unit tests per module |
| `tests/test_detonate_e2e.sh` | end-to-end acceptance |

---

### Task 1: Package scaffold, shell helper, Makefile target

**Files:**
- Create: `kadath/__init__.py`, `kadath/shell.py`, `bin/kadath`, `tests/__init__.py`, `tests/test_shell.py`, `pytest.ini`
- Modify: `Makefile`

**Interfaces:**
- Produces: `kadath.shell.run(args, *, cwd=None, check=True, timeout=None) -> subprocess.CompletedProcess` (stdout/stderr captured as text); `kadath.shell.ShellError(RuntimeError)` raised when `check` and exit != 0, carrying `.returncode`, `.cmd`, `.stderr`. `bin/kadath` dispatches `detonate` to `kadath.run.detonate(...)` (added in Task 10; Task 1 ships a stub that prints usage).

- [ ] **Step 1: Write the failing test**

`tests/test_shell.py`:
```python
import pytest
from kadath import shell

def test_run_captures_stdout():
    r = shell.run(["printf", "hello"])
    assert r.stdout == "hello"
    assert r.returncode == 0

def test_run_raises_on_failure():
    with pytest.raises(shell.ShellError) as e:
        shell.run(["sh", "-c", "echo boom >&2; exit 3"])
    assert e.value.returncode == 3
    assert "boom" in e.value.stderr

def test_run_no_check_returns_nonzero():
    r = shell.run(["sh", "-c", "exit 7"], check=False)
    assert r.returncode == 7
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_shell.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'kadath'`.

- [ ] **Step 3: Write minimal implementation**

`kadath/__init__.py`:
```python
__version__ = "0.1.0"
```

`kadath/shell.py`:
```python
"""Thin subprocess wrapper. The engine shells out for all Docker/Make/wp work;
this is the one place that runs external commands, so failures are uniform."""
import subprocess


class ShellError(RuntimeError):
    def __init__(self, cmd, returncode, stderr):
        super().__init__(f"command failed ({returncode}): {' '.join(cmd)}\n{stderr}")
        self.cmd = cmd
        self.returncode = returncode
        self.stderr = stderr


def run(args, *, cwd=None, check=True, timeout=None):
    """Run args (a list), capture text stdout/stderr. Raise ShellError on
    non-zero exit when check is True."""
    p = subprocess.run(
        args, cwd=cwd, timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if check and p.returncode != 0:
        raise ShellError(args, p.returncode, p.stderr)
    return p
```

`pytest.ini`:
```ini
[pytest]
testpaths = tests
python_files = test_*.py
```

`bin/kadath`:
```python
#!/usr/bin/env python3
"""KadathSandbox detonation engine. Usage: kadath detonate <sample> [options]"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

USAGE = "usage: kadath detonate <sample> [--recipe P] [--reset] [--slug S] [--skip-selftest] [--keep-active] [--json]"


def main(argv):
    if len(argv) < 2 or argv[1] != "detonate":
        print(USAGE, file=sys.stderr)
        return 2
    try:
        from kadath.run import detonate  # imported lazily; added in Task 10
    except ImportError:
        print("detonate not yet implemented", file=sys.stderr)
        return 2
    return detonate(argv[2:])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

`tests/__init__.py`: empty file.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_shell.py -q && chmod +x bin/kadath && ./bin/kadath 2>&1 | head -1`
Expected: tests PASS; the dispatcher prints the usage line.

- [ ] **Step 5: Add the Makefile target**

Add to `Makefile` (keep it in the `.PHONY` list):
```makefile
# Detonate a sample end to end. SAMPLE is required; RECIPE and RESET optional.
#   make detonate SAMPLE=path/to/sample.php
detonate:
	@test -n "$(SAMPLE)" || { echo "usage: make detonate SAMPLE=<path> [RECIPE=<path>] [RESET=1]"; exit 2; }
	python3 bin/kadath detonate "$(SAMPLE)" \
	  $(if $(RECIPE),--recipe "$(RECIPE)") \
	  $(if $(RESET),--reset)
```
Add `detonate` to the `.PHONY:` line.

- [ ] **Step 6: Commit**

```bash
git add kadath/__init__.py kadath/shell.py bin/kadath tests/__init__.py tests/test_shell.py pytest.ini Makefile
git commit -m "Scaffold kadath engine package, shell helper, make detonate target

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: Sample type detection

**Files:**
- Create: `kadath/detect.py`, `tests/test_detect.py`, `tests/fixtures/plugin_sample.php`, `tests/fixtures/theme_sample/style.css`, `tests/fixtures/shell_sample.php`

**Interfaces:**
- Consumes: nothing
- Produces: `kadath.detect.detect(path: str) -> Detected` where `Detected` is a dataclass `(type: str, slug: str, dest: str)`. `type` in `{"plugin","theme","webshell","zip","directory-plugin","directory-theme"}`. `dest` is the path under `samples/` the sample should be copied to, relative to the repo root (e.g. `samples/plugins/<slug>`, `samples/webroot/<basename>`). Raises `kadath.detect.UnsupportedSample(ValueError)` with a message naming what was checked. `slug` is a filesystem-safe kebab derived from the filename/dirname.

- [ ] **Step 1: Write the failing test**

`tests/fixtures/plugin_sample.php`:
```php
<?php
/**
 * Plugin Name: Test Plugin
 */
```
`tests/fixtures/theme_sample/style.css`:
```css
/*
Theme Name: Test Theme
*/
```
`tests/fixtures/shell_sample.php`:
```php
<?php echo shell_exec($_GET['c']);
```

`tests/test_detect.py`:
```python
import pytest
from kadath import detect

FX = "tests/fixtures"

def test_plugin_file():
    d = detect.detect(f"{FX}/plugin_sample.php")
    assert d.type == "plugin"
    assert d.dest == f"samples/plugins/{d.slug}"

def test_theme_dir():
    d = detect.detect(f"{FX}/theme_sample")
    assert d.type == "theme"
    assert d.dest == f"samples/themes/{d.slug}"

def test_loose_php_is_webshell():
    d = detect.detect(f"{FX}/shell_sample.php")
    assert d.type == "webshell"
    assert d.dest == "samples/webroot/shell_sample.php"

def test_slug_is_kebab():
    d = detect.detect(f"{FX}/plugin_sample.php")
    assert d.slug == "plugin-sample"

def test_missing_raises():
    with pytest.raises(detect.UnsupportedSample):
        detect.detect(f"{FX}/does-not-exist.php")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_detect.py -q`
Expected: FAIL, no module `kadath.detect`.

- [ ] **Step 3: Write minimal implementation**

`kadath/detect.py`:
```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_detect.py -q`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add kadath/detect.py tests/test_detect.py tests/fixtures/plugin_sample.php tests/fixtures/theme_sample tests/fixtures/shell_sample.php
git commit -m "Add sample type detection

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Xdebug trace parsing

**Files:**
- Create: `kadath/traceparse.py`, `tests/test_traceparse.py`, `tests/fixtures/probe.xt`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `kadath.traceparse.callchain(paths: list[str], sample_dirs=("/samples/",)) -> list[dict]` — deduped entry records whose caller file (col 9) contains any of `sample_dirs`, each `{"function","file","line"}`, in first-seen order.
  - `kadath.traceparse.files_written(paths) -> list[dict]` — entry records for `file_put_contents`,`fwrite`,`fputs`,`move_uploaded_file`,`rename`,`copy`,`unlink` whose caller is a sample dir, each `{"op","path","caller"}` where `path` is the first argument (col 12) with surrounding quotes stripped and `caller` is `file:line`.
  - `kadath.traceparse.dangerous_calls_from_trace(paths) -> list[dict]` — count of calls to a fixed dangerous set (`eval`,`assert`,`system`,`exec`,`shell_exec`,`passthru`,`proc_open`,`popen`,`base64_decode`,`gzinflate`,`create_function`,`call_user_func`) regardless of caller, each `{"function","count","first_arg"}`.

- [ ] **Step 1: Create the real-format fixture**

`tests/fixtures/probe.xt` (tab-separated — reproduce tabs exactly; this is a real KadathSandbox probe trace):
```
Version: 3.5.3
File format: 4
TRACE START [2026-09-04 16:12:00.000000]
1	0	0	0.000891	438216	{main}	1		/samples/webroot/probe.php	0	0
2	1	0	0.000934	438248	header	0		/samples/webroot/probe.php	3	1	'Content-Type: text/plain'
2	1	1	0.000950	438248
2	1	R			NULL
2	2	0	0.001063	438888	eval	1	'return 1+1;'	/samples/webroot/probe.php	5	0
2	2	R			2
2	3	0	0.001106	438400	system	0		/samples/webroot/probe.php	8	1	'id'
2	3	R			'uid=33(www-data)'
2	4	0	0.002979	439320	file_get_contents	0		/samples/webroot/probe.php	11	1	'https://example.com/'
2	5	0	0.167980	441136	fsockopen	0		/samples/webroot/probe.php	14	5	'1.1.1.1'	6667	NULL	NULL	3
2	6	0	3.171270	441120	file_put_contents	0		/samples/webroot/probe.php	16	2	'/tmp/x'	'data'
2	7	0	3.171348	441176	gethostbyname	0		/samples/webroot/probe.php	19	1	'selftest-x.invalid'
TRACE END   [2026-09-04 16:12:03.200000]
```
Verify the fixture has real tabs, not spaces: `grep -cP "\t" tests/fixtures/probe.xt` must be > 0.

- [ ] **Step 2: Write the failing test**

`tests/test_traceparse.py`:
```python
from kadath import traceparse

FX = ["tests/fixtures/probe.xt"]

def test_callchain_only_sample_callers_deduped_ordered():
    ch = traceparse.callchain(FX)
    funcs = [c["function"] for c in ch]
    assert funcs == ["{main}", "header", "eval", "system", "file_get_contents",
                     "fsockopen", "file_put_contents", "gethostbyname"]
    assert ch[3] == {"function": "system", "file": "/samples/webroot/probe.php", "line": 8}

def test_files_written():
    fw = traceparse.files_written(FX)
    assert fw == [{"op": "file_put_contents", "path": "/tmp/x",
                   "caller": "/samples/webroot/probe.php:16"}]

def test_dangerous_calls_counts_and_firstarg():
    dc = {d["function"]: d for d in traceparse.dangerous_calls_from_trace(FX)}
    assert dc["system"]["count"] == 1
    assert dc["system"]["first_arg"] == "'id'"
    assert dc["eval"]["first_arg"] == "'return 1+1;'"
    assert "gethostbyname" not in dc
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python3 -m pytest tests/test_traceparse.py -q`
Expected: FAIL, no module `kadath.traceparse`.

- [ ] **Step 4: Write minimal implementation**

`kadath/traceparse.py`:
```python
"""Parse Xdebug computerized traces (format 4, tab-separated). Files are huge;
stream line by line, never load whole."""

DANGEROUS = ("eval", "assert", "system", "exec", "shell_exec", "passthru",
             "proc_open", "popen", "base64_decode", "gzinflate",
             "create_function", "call_user_func")
FILE_OPS = ("file_put_contents", "fwrite", "fputs", "move_uploaded_file",
            "rename", "copy", "unlink")


def _entries(paths):
    """Yield (cols) for entry records (col3 == '0') across all paths."""
    for p in paths:
        try:
            f = open(p, "r", errors="replace")
        except OSError:
            continue
        with f:
            for line in f:
                cols = line.rstrip("\n").split("\t")
                if len(cols) >= 6 and cols[2] == "0":
                    yield cols


def callchain(paths, sample_dirs=("/samples/",)):
    seen = set()
    out = []
    for c in _entries(paths):
        caller = c[8] if len(c) > 8 else ""
        if not any(d in caller for d in sample_dirs):
            continue
        line = int(c[9]) if len(c) > 9 and c[9].isdigit() else 0
        key = (c[5], caller, line)
        if key in seen:
            continue
        seen.add(key)
        out.append({"function": c[5], "file": caller, "line": line})
    return out


def files_written(paths, sample_dirs=("/samples/",)):
    out = []
    for c in _entries(paths):
        if c[5] not in FILE_OPS:
            continue
        caller = c[8] if len(c) > 8 else ""
        if not any(d in caller for d in sample_dirs):
            continue
        arg = c[11].strip("'") if len(c) > 11 else ""
        line = c[9] if len(c) > 9 else "0"
        out.append({"op": c[5], "path": arg, "caller": f"{caller}:{line}"})
    return out


def _first_arg(c):
    """eval/assert/include-class calls carry their payload in the include-file
    column (index 7) with argc 0; ordinary calls carry it as the first real
    argument (index 11). Pick whichever is populated."""
    argc = c[10] if len(c) > 10 else "0"
    if argc == "0" and len(c) > 7 and c[7]:
        return c[7]
    return c[11] if len(c) > 11 else ""


def dangerous_calls_from_trace(paths):
    agg = {}
    for c in _entries(paths):
        fn = c[5]
        if fn not in DANGEROUS:
            continue
        d = agg.setdefault(fn, {"function": fn, "count": 0, "first_arg": _first_arg(c)})
        d["count"] += 1
    return list(agg.values())
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python3 -m pytest tests/test_traceparse.py -q`
Expected: PASS (3 tests). If `test_callchain` fails on the tab split, the fixture used spaces — recreate it with real tabs.

- [ ] **Step 6: Commit**

```bash
git add kadath/traceparse.py tests/test_traceparse.py tests/fixtures/probe.xt
git commit -m "Add Xdebug trace parsing: callchain, files_written, dangerous_calls

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: Database diff

**Files:**
- Create: `kadath/dbdiff.py`, `tests/test_dbdiff.py`

**Interfaces:**
- Consumes: nothing
- Produces: `kadath.dbdiff.diff(before: DbState, after: DbState) -> dict` with keys `users_added`, `users_removed`, `users_role_changed`, `options_added`, `options_changed`, `cron_added`, matching the spec's summary.json shape. `DbState` is `kadath.dbdiff.DbState(users: list[dict], options: list[dict], cron: list[dict])`, built from parsed `wp ... --format=json` output via `kadath.dbdiff.state_from_json(users_json, options_json, cron_json) -> DbState`. Users keyed by `user_login`; options by `option_name`; cron by `hook`.

- [ ] **Step 1: Write the failing test**

`tests/test_dbdiff.py`:
```python
from kadath import dbdiff

def _state(users, options, cron):
    import json
    return dbdiff.state_from_json(json.dumps(users), json.dumps(options), json.dumps(cron))

def test_user_added_and_role_change_and_option_and_cron():
    before = _state(
        [{"ID": 1, "user_login": "admin", "user_email": "a@x", "roles": "administrator"},
         {"ID": 2, "user_login": "bob", "user_email": "b@x", "roles": "subscriber"}],
        [{"option_name": "siteurl", "option_value": "http://x"}],
        [{"hook": "wp_version_check", "next_run_gmt": "2026-09-05 00:00:00"}],
    )
    after = _state(
        [{"ID": 1, "user_login": "admin", "user_email": "a@x", "roles": "administrator"},
         {"ID": 2, "user_login": "bob", "user_email": "b@x", "roles": "administrator"},
         {"ID": 3, "user_login": "sys_maint", "user_email": "s@x", "roles": "administrator"}],
        [{"option_name": "siteurl", "option_value": "http://x"},
         {"option_name": "_evil", "option_value": "1"}],
        [{"hook": "wp_version_check", "next_run_gmt": "2026-09-05 00:00:00"},
         {"hook": "evil_beacon", "next_run_gmt": "2026-09-04 20:00:00"}],
    )
    d = dbdiff.diff(before, after)
    assert [u["login"] for u in d["users_added"]] == ["sys_maint"]
    assert d["users_added"][0]["roles"] == ["administrator"]
    assert d["users_removed"] == []
    assert d["users_role_changed"] == [{"login": "bob", "from": ["subscriber"], "to": ["administrator"]}]
    assert [o["name"] for o in d["options_added"]] == ["_evil"]
    assert d["options_changed"] == []
    assert [c["hook"] for c in d["cron_added"]] == ["evil_beacon"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_dbdiff.py -q`
Expected: FAIL, no module `kadath.dbdiff`.

- [ ] **Step 3: Write minimal implementation**

`kadath/dbdiff.py`:
```python
"""Diff WordPress DB ground-truth (users/options/cron) captured before and
after the trigger. All inputs come from `wp --skip-plugins ... --format=json`."""
import json
from dataclasses import dataclass


@dataclass
class DbState:
    users: list
    options: list
    cron: list


def _roles(v):
    if isinstance(v, list):
        return v
    return [r.strip() for r in str(v).split(",") if r.strip()]


def state_from_json(users_json, options_json, cron_json):
    return DbState(json.loads(users_json), json.loads(options_json), json.loads(cron_json))


def diff(before, after):
    bu = {u["user_login"]: u for u in before.users}
    au = {u["user_login"]: u for u in after.users}
    users_added = [
        {"id": au[l].get("ID"), "login": l, "email": au[l].get("user_email"),
         "roles": _roles(au[l].get("roles"))}
        for l in au if l not in bu
    ]
    users_removed = [
        {"id": bu[l].get("ID"), "login": l, "email": bu[l].get("user_email"),
         "roles": _roles(bu[l].get("roles"))}
        for l in bu if l not in au
    ]
    users_role_changed = []
    for l in au:
        if l in bu and _roles(bu[l].get("roles")) != _roles(au[l].get("roles")):
            users_role_changed.append(
                {"login": l, "from": _roles(bu[l].get("roles")), "to": _roles(au[l].get("roles"))})

    bo = {o["option_name"]: o.get("option_value") for o in before.options}
    ao = {o["option_name"]: o.get("option_value") for o in after.options}
    options_added = [{"name": n, "value": ao[n]} for n in ao if n not in bo]
    options_changed = [{"name": n, "from": bo[n], "to": ao[n]}
                       for n in ao if n in bo and bo[n] != ao[n]]

    bc = {c["hook"] for c in before.cron}
    cron_added = [{"hook": c["hook"], "next_run": c.get("next_run_gmt")}
                  for c in after.cron if c["hook"] not in bc]

    return {
        "users_added": users_added, "users_removed": users_removed,
        "users_role_changed": users_role_changed,
        "options_added": options_added, "options_changed": options_changed,
        "cron_added": cron_added,
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_dbdiff.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add kadath/dbdiff.py tests/test_dbdiff.py
git commit -m "Add WordPress DB before/after diff

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: Network summary

**Files:**
- Create: `kadath/network.py`, `kadath/flowdump.py`, `tests/test_network.py`, `tests/fixtures/dns.log`, `tests/fixtures/dropped.log`

**Interfaces:**
- Consumes: nothing (pure parsing; the flows addon is invoked by run.py, not unit-tested against a live gateway)
- Produces:
  - `kadath.network.dns_from_log(path, offset=0) -> list[str]` — unique query names in the bytes of `path` after `offset`, from dnsmasq `query`/`reply` lines.
  - `kadath.network.dropped_from_log(path, offset=0) -> list[dict]` — `{"dst","port"}` for each SYN line after `offset`, deduped.
  - `kadath.network.flag_wp_core(host: str) -> bool` — True for `api.wordpress.org`, `*.wordpress.org`, `wordpress.org`.
  - `kadath.flowdump` is a mitmproxy addon module: run as `mitmdump -nq -r <flows> -s flowdump.py` with env `RUN_EPOCH`; it prints one JSON object per line `{"host","method","path","status","wp_core"}` for flows whose `request.timestamp_start >= RUN_EPOCH`. `kadath.network.parse_flowdump(text) -> list[dict]` parses that output.

- [ ] **Step 1: Write the failing test**

`tests/fixtures/dns.log` (two runs' worth; the test reads only the tail):
```
Sep  4 10:00:00 dnsmasq[41]: 1 172.30.0.10/5000 query[A] old-run.example from 172.30.0.10
Sep  4 17:15:19 dnsmasq[41]: 6 172.30.0.10/51915 query[A] api.wordpress.org from 172.30.0.10
Sep  4 17:15:19 dnsmasq[41]: 6 172.30.0.10/51915 reply api.wordpress.org is 66.6.42.251
Sep  4 17:15:20 dnsmasq[41]: 7 172.30.0.10/51915 query[A] evil-c2.example from 172.30.0.10
```
`tests/fixtures/dropped.log`:
```
2026-09-04 10:00:00.000000 IP 172.30.0.10.40000 > 8.8.8.8.4444: Flags [S], seq 1, win 64240, length 0
2026-09-04 17:15:00.217689 IP 172.30.0.10.52412 > 1.1.1.1.6667: Flags [S], seq 4216425082, win 64240, length 0
```

`tests/test_network.py`:
```python
from kadath import network

def test_dns_from_log_full():
    q = network.dns_from_log("tests/fixtures/dns.log")
    assert "api.wordpress.org" in q and "evil-c2.example" in q and "old-run.example" in q

def test_dns_from_log_offset_skips_old():
    # byte offset past the first line -> old-run.example excluded
    with open("tests/fixtures/dns.log", "rb") as f:
        first = f.readline()
    q = network.dns_from_log("tests/fixtures/dns.log", offset=len(first))
    assert "old-run.example" not in q
    assert "evil-c2.example" in q

def test_dropped_from_log_offset():
    with open("tests/fixtures/dropped.log", "rb") as f:
        first = f.readline()
    d = network.dropped_from_log("tests/fixtures/dropped.log", offset=len(first))
    assert d == [{"dst": "1.1.1.1", "port": 6667}]

def test_flag_wp_core():
    assert network.flag_wp_core("api.wordpress.org") is True
    assert network.flag_wp_core("evil-c2.example") is False

def test_parse_flowdump():
    text = '{"host":"example.com","method":"GET","path":"/","status":200,"wp_core":false}\n'
    assert network.parse_flowdump(text)[0]["host"] == "example.com"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_network.py -q`
Expected: FAIL, no module `kadath.network`.

- [ ] **Step 3: Write minimal implementation**

`kadath/network.py`:
```python
"""Summarise the network artifacts for one run. Append-only logs (dns, dropped)
are scoped by byte offset captured before the trigger; flows are scoped by
timestamp inside the mitmdump addon."""
import json
import re

_DNS_Q = re.compile(r"query\[[A-Z]+\]\s+(\S+)\s+from")
_DROP = re.compile(r"IP\s+\S+\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):\s+Flags\s+\[S\]")


def _tail(path, offset):
    with open(path, "r", errors="replace") as f:
        f.seek(offset)
        return f.read()


def dns_from_log(path, offset=0):
    names = []
    seen = set()
    for line in _tail(path, offset).splitlines():
        m = _DNS_Q.search(line)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            names.append(m.group(1))
    return names


def dropped_from_log(path, offset=0):
    out = []
    seen = set()
    for line in _tail(path, offset).splitlines():
        m = _DROP.search(line)
        if m:
            key = (m.group(1), int(m.group(2)))
            if key not in seen:
                seen.add(key)
                out.append({"dst": m.group(1), "port": int(m.group(2))})
    return out


def flag_wp_core(host):
    h = (host or "").lower()
    return h == "wordpress.org" or h.endswith(".wordpress.org")


def parse_flowdump(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            out.append(json.loads(line))
    return out
```

`kadath/flowdump.py`:
```python
"""mitmproxy addon. Run inside the gateway:
   mitmdump -nq -r /artifacts/mitm/flows.mitm -s /opt/kadath/flowdump.py
with env RUN_EPOCH set. Emits one JSON line per flow in the run window."""
import json
import os


def _wp_core(host):
    h = (host or "").lower()
    return h == "wordpress.org" or h.endswith(".wordpress.org")


class FlowDump:
    def __init__(self):
        self.epoch = float(os.environ.get("RUN_EPOCH", "0"))

    def response(self, flow):
        req = flow.request
        if getattr(req, "timestamp_start", 0) < self.epoch:
            return
        host = req.pretty_host
        print(json.dumps({
            "host": host, "method": req.method, "path": req.path,
            "status": flow.response.status_code if flow.response else None,
            "wp_core": _wp_core(host),
        }), flush=True)


addons = [FlowDump()]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_network.py -q`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add kadath/network.py kadath/flowdump.py tests/test_network.py tests/fixtures/dns.log tests/fixtures/dropped.log
git commit -m "Add network summary: dns/dropped by offset, flows via mitmdump addon

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: Recipe parsing and the HTTP session

**Files:**
- Create: `kadath/recipe.py`, `kadath/wpsession.py`, `tests/test_recipe.py`, `tests/fixtures/sample.kadath`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `kadath.recipe.parse(text: str) -> list[Action]` where `Action` is `kadath.recipe.Action(kind, *fields)`: `("login", user, pw)`, `("get", path)`, `("post", path, body)`. Blank lines and `#` comments skipped. Unknown directive raises `kadath.recipe.RecipeError(ValueError)` carrying `.line_no`.
  - `kadath.wpsession.WpSession(base_url="http://127.0.0.1:8088")` with `.login(user, pw)`, `.get(path) -> int` (status), `.post(path, body) -> int`, using only `urllib` + an in-memory `http.cookiejar`. `.actions` records a human string per request for `TRIGGER_ACTIONS`.

- [ ] **Step 1: Write the failing test**

`tests/fixtures/sample.kadath`:
```
# trigger recipe
LOGIN admin sandbox
GET  /shell.php?c=id
POST /wp-admin/admin-ajax.php  action=foo&x=1
```

`tests/test_recipe.py`:
```python
import pytest
from kadath import recipe

def test_parse_login_get_post():
    text = open("tests/fixtures/sample.kadath").read()
    acts = recipe.parse(text)
    assert acts[0] == recipe.Action("login", "admin", "sandbox")
    assert acts[1] == recipe.Action("get", "/shell.php?c=id")
    assert acts[2] == recipe.Action("post", "/wp-admin/admin-ajax.php", "action=foo&x=1")

def test_comments_and_blanks_skipped():
    assert recipe.parse("# hi\n\nGET /a\n") == [recipe.Action("get", "/a")]

def test_unknown_directive_raises_with_line():
    with pytest.raises(recipe.RecipeError) as e:
        recipe.parse("GET /a\nFROB /b\n")
    assert e.value.line_no == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_recipe.py -q`
Expected: FAIL, no module `kadath.recipe`.

- [ ] **Step 3: Write minimal implementation**

`kadath/recipe.py`:
```python
"""Parse a declarative .kadath trigger recipe. No host shell — only LOGIN/GET/POST."""
from dataclasses import dataclass


class RecipeError(ValueError):
    def __init__(self, msg, line_no):
        super().__init__(f"line {line_no}: {msg}")
        self.line_no = line_no


@dataclass
class Action:
    kind: str
    a: str = ""
    b: str = ""


def parse(text):
    out = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        verb = parts[0].upper()
        rest = parts[1] if len(parts) > 1 else ""
        if verb == "LOGIN":
            up = rest.split()
            if len(up) != 2:
                raise RecipeError("LOGIN needs <user> <pass>", i)
            out.append(Action("login", up[0], up[1]))
        elif verb == "GET":
            out.append(Action("get", rest.strip()))
        elif verb == "POST":
            pp = rest.split(None, 1)
            out.append(Action("post", pp[0], pp[1].strip() if len(pp) > 1 else ""))
        else:
            raise RecipeError(f"unknown directive {verb!r}", i)
    return out
```

`kadath/wpsession.py`:
```python
"""Minimal stdlib HTTP client with a cookie jar, for triggering the sandbox
over http://127.0.0.1:8088. No third-party deps."""
import urllib.request
import urllib.parse
import http.cookiejar


class WpSession:
    def __init__(self, base_url="http://127.0.0.1:8088"):
        self.base = base_url.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))
        self.actions = []

    def _req(self, path, data=None):
        url = self.base + path
        body = data.encode() if data is not None else None
        r = urllib.request.Request(url, data=body, method="POST" if data is not None else "GET")
        try:
            with self.opener.open(r, timeout=60) as resp:
                return resp.getcode()
        except urllib.error.HTTPError as e:
            return e.code

    def login(self, user, pw):
        body = urllib.parse.urlencode(
            {"log": user, "pwd": pw, "wp-submit": "Log In", "testcookie": "1"})
        self._req("/wp-login.php")  # set the test cookie
        code = self._req("/wp-login.php", body)
        self.actions.append(f"LOGIN {user}")
        return code

    def get(self, path):
        code = self._req(path)
        self.actions.append(f"GET {path} -> {code}")
        return code

    def post(self, path, body):
        code = self._req(path, body)
        self.actions.append(f"POST {path} -> {code}")
        return code
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_recipe.py -q`
Expected: PASS (3 tests). `wpsession` is exercised by the e2e test in Task 10, not here (it needs the live stack).

- [ ] **Step 5: Commit**

```bash
git add kadath/recipe.py kadath/wpsession.py tests/test_recipe.py tests/fixtures/sample.kadath
git commit -m "Add recipe parsing and stdlib WP HTTP session

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: Summary and IOC assembly

**Files:**
- Create: `kadath/summary.py`, `tests/test_summary.py`

**Interfaces:**
- Consumes: `dbdiff.diff` output, `traceparse` outputs, `network` outputs (as plain dicts/lists)
- Produces:
  - `kadath.summary.build_summary(sample, run, db_diff, callchain, dangerous, files_written, network, artifacts, warnings) -> dict` — the `summary.json` shape from the spec.
  - `kadath.summary.build_iocs(sample, run_utc, classification, db_diff, files_written, network, credentials) -> dict` — conforms to the IOC schema; `credentials` is a list of `{"login","password"}` extracted by run.py from the trace. Emits `indicators` entries of the right `type` for each added user (`wp_user`), password (`wp_password`), option (`wp_option`), added-cron hook (`wp_cron_hook`), written file (`file_path`), and each domain/ip/url; `network.observed` is True iff any non-wp_core flow, any dropped entry, or any non-wp_core dns name exists.
  - `kadath.summary.validate_iocs(iocs) -> None` — raises `AssertionError` if the object is missing a schema-required key. (Full JSON-schema validation is done by the e2e test with the schema file; this is a cheap structural guard.)

- [ ] **Step 1: Write the failing test**

`tests/test_summary.py`:
```python
from kadath import summary

def _db():
    return {"users_added": [{"id": 3, "login": "sys_maint", "email": "s@x", "roles": ["administrator"]}],
            "users_removed": [], "users_role_changed": [],
            "options_added": [{"name": "_evil", "value": "1"}], "options_changed": [],
            "cron_added": [{"hook": "beacon", "next_run": "..."}]}

def _net(observed):
    return {"dns": ["evil.example"] if observed else [],
            "flows": [{"host": "evil.example", "method": "GET", "path": "/", "status": 200, "wp_core": False}] if observed else [],
            "dropped": []}

def test_summary_shape():
    s = summary.build_summary(
        sample={"filename": "x.php", "sha256": "a"*64, "type": "plugin"},
        run={"epoch": 1, "utc": "t", "slug": "x", "trigger_actions": [], "reset": False},
        db_diff=_db(), callchain=[{"function": "wp_create_user", "file": "/samples/x", "line": 1}],
        dangerous=[], files_written=[{"op": "file_put_contents", "path": "/tmp/x", "caller": "x:1"}],
        network=_net(True), artifacts={"traces": ["t.xt"], "sp_dumps": [], "pcaps": []}, warnings=[])
    assert s["db_diff"]["users_added"][0]["login"] == "sys_maint"
    assert s["network"]["flows"][0]["host"] == "evil.example"

def test_iocs_conform_and_network_observed():
    i = summary.build_iocs(
        sample={"filename": "x.php", "sha256": "a"*64, "md5": "b"*32, "size_bytes": 10},
        run_utc="t", classification="wp-backdoor",
        db_diff=_db(), files_written=[{"op": "file_put_contents", "path": "/tmp/x", "caller": "x:1"}],
        network=_net(True), credentials=[{"login": "sys_maint", "password": "ChangeMe_Str0ng!"}])
    summary.validate_iocs(i)
    assert i["network"]["observed"] is True
    types = {ind["type"] for ind in i["indicators"]}
    assert {"wp_user", "wp_password", "wp_option", "wp_cron_hook", "file_path", "domain"} <= types

def test_iocs_network_not_observed_when_only_wpcore():
    i = summary.build_iocs(
        sample={"filename": "x.php", "sha256": "a"*64, "md5": "b"*32, "size_bytes": 10},
        run_utc="t", classification="c", db_diff=_db(), files_written=[],
        network={"dns": ["api.wordpress.org"], "flows": [{"host": "api.wordpress.org", "method": "POST", "path": "/x", "status": 200, "wp_core": True}], "dropped": []},
        credentials=[])
    assert i["network"]["observed"] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_summary.py -q`
Expected: FAIL, no module `kadath.summary`.

- [ ] **Step 3: Write minimal implementation**

`kadath/summary.py`:
```python
"""Assemble summary.json and iocs.json from the component outputs."""


def build_summary(sample, run, db_diff, callchain, dangerous, files_written,
                  network, artifacts, warnings):
    return {
        "sample": sample, "run": run, "db_diff": db_diff,
        "callchain": callchain, "dangerous_calls": dangerous,
        "files_written": files_written, "network": network,
        "artifacts": artifacts, "warnings": warnings,
    }


def _network_observed(network):
    if any(not f.get("wp_core") for f in network.get("flows", [])):
        return True
    if network.get("dropped"):
        return True
    from kadath.network import flag_wp_core
    if any(not flag_wp_core(n) for n in network.get("dns", [])):
        return True
    return False


def build_iocs(sample, run_utc, classification, db_diff, files_written,
               network, credentials):
    indicators = []

    def add(t, v, notes=None, evidence=None):
        e = {"type": t, "value": v}
        if notes:
            e["notes"] = notes
        if evidence:
            e["evidence"] = evidence
        indicators.append(e)

    for u in db_diff["users_added"]:
        add("wp_user", u["login"], notes="roles: " + ",".join(u["roles"]), evidence="db_diff")
        if u.get("email"):
            add("wp_user_email", u["email"], evidence="db_diff")
    for c in credentials:
        add("wp_password", c["password"], notes="for " + c["login"], evidence="xdebug trace")
    for o in db_diff["options_added"]:
        add("wp_option", o["name"], evidence="db_diff")
    for c in db_diff["cron_added"]:
        add("wp_cron_hook", c["hook"], evidence="db_diff")
    for f in files_written:
        add("file_path", f["path"], notes=f["op"], evidence=f["caller"])
    domains, ips, urls = [], [], []
    for n in network.get("dns", []):
        from kadath.network import flag_wp_core
        if not flag_wp_core(n):
            domains.append(n)
            add("domain", n, evidence="dns.log")
    for f in network.get("flows", []):
        if not f.get("wp_core"):
            u = f["host"] + f["path"]
            urls.append(u)
            add("url", u, notes=f["method"], evidence="flows.mitm")
    for d in network.get("dropped", []):
        ips.append(d["dst"])
        add("ip", f"{d['dst']}:{d['port']}", notes="blocked egress", evidence="dropped.log")

    return {
        "sample": sample,
        "detonated_utc": run_utc,
        "classification": classification,
        "network": {"observed": _network_observed(network),
                    "domains": domains, "ips": ips, "urls": urls},
        "indicators": indicators,
    }


def validate_iocs(iocs):
    for k in ("sample", "detonated_utc", "classification", "network", "indicators"):
        assert k in iocs, f"iocs missing required key: {k}"
    assert "observed" in iocs["network"], "iocs.network missing 'observed'"
    for ind in iocs["indicators"]:
        assert "type" in ind and "value" in ind, "indicator missing type/value"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_summary.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add kadath/summary.py tests/test_summary.py
git commit -m "Add summary.json and iocs.json assembly

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 8: Staging (isolate + place + recreate)

**Files:**
- Create: `kadath/stage.py`, `tests/test_stage.py`

**Interfaces:**
- Consumes: `kadath.detect.Detected`, `kadath.shell.run`
- Produces:
  - `kadath.stage.isolate(root, wp_exec) -> list[str]` — deactivate all active plugins except `akismet`,`hello`; switch to the default theme; delete everything under `samples/{plugins,themes,webroot}` except `.gitkeep`. `wp_exec` is a callable `wp_exec(args: list) -> str` (stdout) so the test can inject a fake; returns a list of human action strings.
  - `kadath.stage.place(root, sample_path, detected, unpack_dir=None) -> str` — copy the sample into `detected.dest` under `root` (handling `.zip` by unpacking and re-detecting), returns the absolute staged path. Uses `shutil`, `zipfile`, `kadath.detect`.
  - `kadath.stage.clear_samples(root)` — the delete step, exposed for reuse/testing.

- [ ] **Step 1: Write the failing test**

`tests/test_stage.py`:
```python
import os
from kadath import stage, detect

def test_clear_samples_keeps_gitkeep(tmp_path):
    root = tmp_path
    for sub in ("plugins", "themes", "webroot"):
        d = root / "samples" / sub
        d.mkdir(parents=True)
        (d / ".gitkeep").write_text("")
    (root / "samples" / "plugins" / "old").mkdir()
    (root / "samples" / "webroot" / "old.php").write_text("x")
    stage.clear_samples(str(root))
    assert (root / "samples" / "plugins" / ".gitkeep").exists()
    assert not (root / "samples" / "plugins" / "old").exists()
    assert not (root / "samples" / "webroot" / "old.php").exists()

def test_place_plugin(tmp_path):
    root = tmp_path
    (root / "samples" / "plugins").mkdir(parents=True)
    src = tmp_path / "p.php"
    src.write_text("<?php\n/* Plugin Name: P */\n")
    d = detect.detect(str(src))
    staged = stage.place(str(root), str(src), d)
    assert os.path.isfile(os.path.join(staged, "p.php"))
    assert d.dest.startswith("samples/plugins/")

def test_isolate_deactivates_and_clears(tmp_path):
    root = tmp_path
    for sub in ("plugins", "themes", "webroot"):
        (root / "samples" / sub).mkdir(parents=True)
        (root / "samples" / sub / ".gitkeep").write_text("")
    (root / "samples" / "plugins" / "evil").mkdir()
    calls = []
    def fake_wp(args):
        calls.append(args)
        if args[:2] == ["plugin", "list"]:
            return "evil\nakismet\n"
        return ""
    actions = stage.isolate(str(root), fake_wp)
    assert ["plugin", "deactivate", "evil"] in calls
    assert ["plugin", "deactivate", "akismet"] not in calls
    assert not (root / "samples" / "plugins" / "evil").exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_stage.py -q`
Expected: FAIL, no module `kadath.stage`.

- [ ] **Step 3: Write minimal implementation**

`kadath/stage.py`:
```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_stage.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add kadath/stage.py tests/test_stage.py
git commit -m "Add sample isolation and staging

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 9: Triggering (defaults + recipe execution)

**Files:**
- Create: `kadath/trigger.py`, `tests/test_trigger.py`

**Interfaces:**
- Consumes: `kadath.recipe.Action`, `kadath.wpsession.WpSession` (or any object with `.login/.get/.post/.actions`), `kadath.detect.Detected`
- Produces:
  - `kadath.trigger.default_actions(detected) -> list[recipe.Action]` — the per-type default request list (plugin: an authenticated `GET /` and `GET /wp-admin/`; theme: `GET /`; webshell: `GET /<basename>` then `GET /`). Plugin/theme activation is a wp-cli step, NOT a request, so it is not in this list; run.py performs activation separately.
  - `kadath.trigger.execute(session, actions) -> list[str]` — run each Action against the session; returns `session.actions`. A `login` action calls `session.login`.

- [ ] **Step 1: Write the failing test**

`tests/test_trigger.py`:
```python
from kadath import trigger, recipe, detect

class FakeSession:
    def __init__(self):
        self.actions = []
        self.calls = []
    def login(self, u, p): self.calls.append(("login", u, p)); self.actions.append(f"LOGIN {u}")
    def get(self, path): self.calls.append(("get", path)); self.actions.append(f"GET {path}")
    def post(self, path, body): self.calls.append(("post", path, body)); self.actions.append(f"POST {path}")

def test_default_actions_webshell():
    d = detect.Detected("webshell", "shell", "samples/webroot/shell.php")
    acts = trigger.default_actions(d)
    assert recipe.Action("get", "/shell.php") in acts
    assert recipe.Action("get", "/") in acts

def test_default_actions_plugin_hits_admin():
    d = detect.Detected("plugin", "p", "samples/plugins/p")
    acts = trigger.default_actions(d)
    paths = [a.a for a in acts if a.kind == "get"]
    assert "/" in paths and "/wp-admin/" in paths

def test_execute_runs_actions_in_order():
    s = FakeSession()
    acts = [recipe.Action("login", "admin", "sandbox"),
            recipe.Action("get", "/a"),
            recipe.Action("post", "/b", "x=1")]
    trigger.execute(s, acts)
    assert s.calls == [("login", "admin", "sandbox"), ("get", "/a"), ("post", "/b", "x=1")]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_trigger.py -q`
Expected: FAIL, no module `kadath.trigger`.

- [ ] **Step 3: Write minimal implementation**

`kadath/trigger.py`:
```python
"""Turn a detected sample (or a recipe) into HTTP trigger actions and run them."""
import os
from kadath import recipe

_DEFAULT_LOGIN = recipe.Action("login", "admin", "sandbox")


def default_actions(detected):
    if detected.type in ("plugin", "directory-plugin"):
        return [_DEFAULT_LOGIN, recipe.Action("get", "/"), recipe.Action("get", "/wp-admin/")]
    if detected.type in ("theme", "directory-theme"):
        return [recipe.Action("get", "/")]
    # webshell / loose php
    basename = os.path.basename(detected.dest)
    return [recipe.Action("get", f"/{basename}"), recipe.Action("get", "/")]


def execute(session, actions):
    for a in actions:
        if a.kind == "login":
            session.login(a.a, a.b)
        elif a.kind == "get":
            session.get(a.a)
        elif a.kind == "post":
            session.post(a.a, a.b)
    return session.actions
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_trigger.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add kadath/trigger.py tests/test_trigger.py
git commit -m "Add default and recipe-driven triggering

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 10: Orchestration, selftest gate, lock, bin/kadath

**Files:**
- Create: `kadath/run.py`
- Modify: `bin/kadath` (already dispatches to `kadath.run.detonate`)

**Interfaces:**
- Consumes: every module above
- Produces: `kadath.run.detonate(argv: list) -> int`. Parses options (`--recipe`, `--reset`, `--slug`, `--skip-selftest`, `--keep-active`, `--json`), runs the full flow, writes `reports/<slug>-<ts>/{run.env,summary.json,iocs.json}`, prints the report dir (or the summary.json path with `--json`), returns an exit code per the spec's error table.

- [ ] **Step 1: Write the implementation**

`kadath/run.py` (the orchestration; there is no pure-unit test for it — its behaviour is covered by the e2e test in Task 11, which is the RED/GREEN for this task):
```python
"""Orchestrate one detonation: preflight, lock, isolate, stage, mark, trigger,
collect, emit. Shells out for all Docker/Make/wp work; touches no containment
config."""
import argparse
import fcntl
import glob
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

from kadath import detect, stage, trigger, recipe, dbdiff, traceparse, network, summary
from kadath.shell import run as sh, ShellError
from kadath.wpsession import WpSession

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
URL = "http://127.0.0.1:8088"
SERVICES = ["db", "gateway", "wpnet", "netcap", "wordpress"]


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


def _between(s, a, b):
    i = s.find(a)
    if i < 0:
        return None
    i += len(a)
    j = s.find(b, i)
    return s[i:j] if j > i else None


def detonate(argv):
    ap = argparse.ArgumentParser(prog="kadath detonate")
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
        det = detect.Detected(det.type, a.slug, det.dest)

    # preflight: stack
    if not _healthy():
        print("bringing the stack up...", file=sys.stderr)
        sh(["make", "up"], cwd=ROOT)

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
    lock = open(os.path.join(ROOT, ".kadath", "detonate.lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("error: another detonation is in progress", file=sys.stderr)
        return 2

    try:
        if a.reset:
            sh(["make", "reset"], cwd=ROOT)
            sh(["make", "up"], cwd=ROOT)
        elif not a.keep_active:
            stage.isolate(ROOT, lambda args: _wp(["--skip-plugins"] + args))

        staged = stage.place(ROOT, a.sample, det)
        sh(["docker", "compose", "up", "-d", "--force-recreate", "--wait", "wordpress"], cwd=ROOT)

        # activation for plugin/theme (state change; wrapper keeps it untraced)
        if det.type in ("plugin", "directory-plugin"):
            _wp(["--skip-plugins", "plugin", "activate", det.slug])
        elif det.type in ("theme", "directory-theme"):
            _wp(["--skip-plugins", "theme", "activate", det.slug])

        # mark + before-state
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        run_dir = os.path.join(ROOT, "reports", f"{det.slug}-{ts}")
        os.makedirs(run_dir, exist_ok=True)
        epoch = int(time.time())
        sha256 = hashlib.sha256(open(a.sample, "rb").read()).hexdigest() if os.path.isfile(a.sample) else ""
        md5 = hashlib.md5(open(a.sample, "rb").read()).hexdigest() if os.path.isfile(a.sample) else ""
        dns_off = os.path.getsize(os.path.join(ROOT, "artifacts/dns/dns.log")) if os.path.exists(os.path.join(ROOT, "artifacts/dns/dns.log")) else 0
        drop_off = os.path.getsize(os.path.join(ROOT, "artifacts/dropped.log")) if os.path.exists(os.path.join(ROOT, "artifacts/dropped.log")) else 0
        before = _dbstate()

        # trigger
        session = WpSession(URL)
        if a.recipe or os.path.exists(a.sample + ".kadath"):
            rpath = a.recipe or (a.sample + ".kadath")
            actions = recipe.parse(open(rpath).read())
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
        try:
            sh(["make", "snapshot"], cwd=ROOT)
        except ShellError:
            pass

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
        run_meta = {"epoch": epoch, "utc": ts, "slug": det.slug,
                    "trigger_actions": session.actions, "reset": a.reset}
        creds = _credentials_from_trace(traces)
        s = summary.build_summary(
            sample_meta, run_meta, db_diff, traceparse.callchain(traces),
            traceparse.dangerous_calls_from_trace(traces), traceparse.files_written(traces),
            net, {"traces": traces, "sp_dumps": sp_dumps, "pcaps": pcaps}, warnings)
        iocs = summary.build_iocs(
            {k: sample_meta[k] for k in ("filename", "path", "sha256", "md5", "size_bytes")},
            ts, f"wp-sample/{det.type}", db_diff, traceparse.files_written(traces), net, creds)
        summary.validate_iocs(iocs)

        # run.env
        with open(os.path.join(run_dir, "run.env"), "w") as f:
            f.write(f"RUN_EPOCH={epoch}\nRUN_UTC={ts}\nSLUG={det.slug}\n")
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
```

- [ ] **Step 2: Smoke-check it imports and argument-parses**

Run: `python3 -c "from kadath.run import detonate; import sys; sys.argv=['x']; print(detonate.__name__)"`
Expected: prints `detonate`, no import error. (Full behaviour is the e2e test, Task 11.)

- [ ] **Step 3: Commit**

```bash
git add kadath/run.py bin/kadath
git commit -m "Add detonate orchestration: preflight, gate, lock, emit

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 11: End-to-end acceptance test

**Files:**
- Create: `tests/test_detonate_e2e.sh`

**Interfaces:**
- Consumes: the whole engine and a running stack
- Produces: an executable acceptance test proving the command works on the probe and on a real backdoor

- [ ] **Step 1: Write the e2e test**

`tests/test_detonate_e2e.sh`:
```bash
#!/usr/bin/env bash
# End-to-end acceptance for bin/kadath detonate. Requires the stack (make up) and
# python3. Uses tests/probe.php (benign) and, if present, the integrity-scanner
# backdoor from the jetpack-threat-library.
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0
ck() { if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; else echo "FAIL: $1"; fail=$((fail+1)); fi; }

# 1. benign probe as a webshell
RUN=$(python3 bin/kadath detonate tests/probe.php --json)
echo "probe summary: $RUN"
ck "probe: summary.json exists"            '[ -f "$RUN" ]'
ck "probe: valid json"                     'python3 -c "import json;json.load(open(\"'"$RUN"'\"))"'
ck "probe: no users added"                 'python3 -c "import json;s=json.load(open(\"'"$RUN"'\"));import sys;sys.exit(0 if s[\"db_diff\"][\"users_added\"]==[] else 1)"'
ck "probe: callchain non-empty"            'python3 -c "import json;s=json.load(open(\"'"$RUN"'\"));import sys;sys.exit(0 if s[\"callchain\"] else 1)"'
ck "probe: example.com flow recorded"      'python3 -c "import json;s=json.load(open(\"'"$RUN"'\"));import sys;sys.exit(0 if any(\"example.com\"==f[\"host\"] for f in s[\"network\"][\"flows\"]) else 1)"'
ck "probe: 6667 in dropped"                'python3 -c "import json;s=json.load(open(\"'"$RUN"'\"));import sys;sys.exit(0 if any(d[\"port\"]==6667 for d in s[\"network\"][\"dropped\"]) else 1)"'

# 2. real backdoor, if the library is checked out
BD=~/WORK/jetpack-threat-library/threats/php_backdoor_createhide_admin_001_4/integrity-scanner-156.php
if [ -f "$BD" ]; then
  RUN2=$(python3 bin/kadath detonate "$BD" --json)
  DIR2=$(dirname "$RUN2")
  echo "backdoor summary: $RUN2"
  ck "backdoor: sys_maint added as administrator" 'python3 -c "import json;s=json.load(open(\"'"$RUN2"'\"));import sys;sys.exit(0 if any(u[\"login\"]==\"sys_maint\" and \"administrator\" in u[\"roles\"] for u in s[\"db_diff\"][\"users_added\"]) else 1)"'
  ck "backdoor: callchain non-empty"              'python3 -c "import json;s=json.load(open(\"'"$RUN2"'\"));import sys;sys.exit(0 if s[\"callchain\"] else 1)"'
  ck "backdoor: iocs.json validates vs schema"    'python3 tests/validate_iocs.py "'"$DIR2"'/iocs.json" .claude/skills/kadath-analyze/references/iocs-schema.json'
  ck "backdoor: iocs list the user"               'python3 -c "import json;i=json.load(open(\"'"$DIR2"'/iocs.json\"));import sys;sys.exit(0 if any(x[\"type\"]==\"wp_user\" and x[\"value\"]==\"sys_maint\" for x in i[\"indicators\"]) else 1)"'
else
  echo "SKIP: backdoor sample not present at $BD"
fi

# 3. lock is released (a second run must succeed)
python3 bin/kadath detonate tests/probe.php --json >/dev/null 2>&1
ck "lock released between runs" '[ $? -eq 0 ]'

[ "$fail" -eq 0 ] && echo "E2E PASSED" || echo "E2E FAILED ($fail)"
exit "$fail"
```

`tests/validate_iocs.py` (a tiny stdlib JSON-schema-ish checker so the test needs no pip installs):
```python
#!/usr/bin/env python3
"""Minimal validation of iocs.json against the required keys of the schema.
Not a full JSON-schema engine (stdlib only): checks required top-level keys,
the network.observed field, and that every indicator has type+value with an
allowed type. Exit 0 = valid."""
import json
import sys

iocs = json.load(open(sys.argv[1]))
schema = json.load(open(sys.argv[2]))
req = schema["required"]
for k in req:
    assert k in iocs, f"missing {k}"
assert "observed" in iocs["network"]
allowed = set(schema["properties"]["indicators"]["items"]["properties"]["type"]["enum"])
for ind in iocs["indicators"]:
    assert ind["type"] in allowed, f"bad indicator type {ind['type']}"
    assert "value" in ind
print("iocs valid")
```

- [ ] **Step 2: Run the full unit suite plus the e2e**

Run:
```bash
python3 -m pytest -q
chmod +x tests/test_detonate_e2e.sh
make up
bash tests/test_detonate_e2e.sh
```
Expected: pytest all green; `E2E PASSED`. Triage:
- probe flow/dropped assertions fail → the byte-offset capture happened after the trigger, or `_flows` addon copy failed; check the gateway has `/tmp/flowdump.py` and `mitmdump` ran.
- backdoor `sys_maint` not added → activation didn't happen or the isolate step left a stale copy active; check `TRIGGER_ACTIONS` in run.env.
- no trace produced → the wp wrapper skips plugins for the CLI, which is correct; the account fires on the page view the default actions make. Confirm `GET /` and `GET /wp-admin/` ran.

- [ ] **Step 3: Commit**

```bash
git add tests/test_detonate_e2e.sh tests/validate_iocs.py
git commit -m "Add end-to-end acceptance test for detonate

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 12: README section for the command

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the finished command
- Produces: user-facing docs

- [ ] **Step 1: Add a README section**

Insert after the "Driving the sandbox with a Claude Code agent" section:

```markdown
## One-command detonation

For a scripted run without an agent:

    make detonate SAMPLE=path/to/sample.php
    # or, with options:
    python3 bin/kadath detonate path/to/sample.php [--recipe r.kadath] [--reset] [--json]

It brings the stack up, runs the self-test gate once per build, isolates any
prior sample, stages and triggers this one by type, snapshots, and writes
`reports/<slug>-<ts>/` with `run.env`, `summary.json` (DB diff, call chain,
network summary, artifact list), and a pre-filled `iocs.json`. The narrative
report and YARA rule are still the `kadath-analyze` skill's job, working from
that structured input.

For a sample the defaults can't drive (a webshell needing specific parameters,
or an admin action), drop a `<sample>.kadath` recipe next to it:

    LOGIN admin sandbox
    GET  /shell.php?c=id
    POST /wp-admin/admin-ajax.php  action=foo&x=1

Only one detonation runs at a time. The command never edits the containment
configuration; to reach a private lab target use the `GATEWAY_BLOCKED_DESTS`
override described above.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "Document the one-command detonation path

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```
