# kadath detonate CLI: one-command detonation engine

Date: 2026-09-04
Status: approved design, pending implementation plan

## Purpose

Collapse the multi-step detonation workflow — stage, bring the stack up,
trigger by sample type, snapshot, attribute artifacts to the run — into a
single host-side command. The command is the deterministic engine; a thin
web front end (a separate sub-project) will later shell out to it. It does
the mechanical work and emits machine-readable facts; narrative analysis and
YARA generation stay with the `kadath-analyze` skill.

This is sub-project 1 of 2. Sub-project 2 (a localhost web front end over
this engine) gets its own spec later.

## Decisions taken during brainstorming

| Question | Decision |
|---|---|
| Interface | CLI engine first (`bin/kadath`), thin web layer over it later |
| Triggering | Auto-detect type and auto-trigger; optional per-sample recipe file for custom cases |
| Output | Execute and emit a machine-readable run summary; no narrative, no YARA (those stay with kadath-analyze) |
| Implementation | Python 3 (already on the host); shells out to `docker compose`, `make`, and `wp` |
| Analyze integration | `kadath-analyze` will be updated later to consume `summary.json`/`iocs.json` — out of scope here |

## Architecture

### Entry points

- `bin/kadath detonate <sample> [options]` — the engine.
- `make detonate SAMPLE=<path> [RECIPE=<path>] [RESET=1]` — a convenience
  wrapper that calls `bin/kadath detonate`.

`bin/kadath` is a single Python 3 program (no third-party dependencies;
standard library only, so it runs on the host with the `python3` that is
already present). It shells out for all Docker, Make, and WordPress work;
it never imports Docker SDKs or talks to the daemon directly.

### Options

```
bin/kadath detonate <sample>
  --recipe <path>     trigger recipe file (default: <sample>.kadath if present)
  --reset             full `make reset` (down -v) before staging, for a clean slate
  --slug <name>       override the derived slug
  --skip-selftest     proceed even if no self-test pass is recorded (prints a warning)
  --keep-active       do not deactivate previously staged samples (default is to isolate)
  --json              print the path to summary.json only (for the web layer / scripting)
```

`<sample>` is a file (`.php`, `.zip`) or a directory (an unpacked plugin or
theme).

### Run flow

1. **Preflight.**
   - Resolve and hash the sample; fail fast if missing or an unsupported type.
   - Ensure the stack is healthy: run `make up` if any of `db`, `gateway`,
     `wpnet`, `netcap`, `wordpress` is not healthy.
   - Self-test gate: read `.kadath/selftest-pass` (a marker file, see below).
     If it does not match the current image build, run `make selftest`; on
     failure, abort (a result on an unverified stack is worthless). `--skip-selftest`
     downgrades this to a warning.
   - Acquire an exclusive lock at `.kadath/detonate.lock` (flock). If held,
     abort with "another detonation is in progress". The sandbox is
     single-tenant; concurrent runs would corrupt shared artifacts and DB.
2. **Isolate** (unless `--keep-active`).
   - `--reset`: `make reset`, then continue.
   - Otherwise: deactivate every active plugin except the WordPress defaults
     (`akismet`, `hello`) via `wp --skip-plugins plugin deactivate`, switch to
     a default theme, and delete every directory/file under `samples/plugins`,
     `samples/themes`, `samples/webroot` except `.gitkeep`. This stops a
     backdoor staged in a previous run from firing into this run's trace.
3. **Stage.**
   - Detect type (see Type detection). Copy the sample into the matching
     `samples/` subdirectory. For a `.zip`, unpack to a temp dir, re-detect
     from the contents, and stage the unpacked tree.
   - `docker compose up -d --force-recreate --wait wordpress`; confirm the
     symlink was made from the container log.
4. **Mark and snapshot "before".**
   - Create `reports/<slug>-<ts>/`, write `run.env` (see Outputs).
   - Capture the before-state DB dump (see DB diff).
5. **Trigger.**
   - If a recipe applies, execute it (see Recipe). Otherwise auto-trigger by
     type (see Triggering). Record every action taken into `run.env`
     (`TRIGGER_ACTIONS`).
6. **Collect.**
   - Capture the after-state DB dump.
   - Enumerate this run's new artifacts (mtime ≥ `RUN_EPOCH`).
   - `make snapshot`.
7. **Emit.**
   - Assemble and write `summary.json` and `iocs.json`.
   - Warn if no new Xdebug trace appeared (sample likely needs a recipe).
   - Print the report directory path (or, with `--json`, the `summary.json` path).

### Type detection

| Detected type | Signal | Staged to |
|---|---|---|
| plugin | a PHP file whose header contains `Plugin Name:` | `samples/plugins/<slug>/` |
| theme | a `style.css` with `Theme Name:`, or a dir containing one | `samples/themes/<slug>/` |
| webshell / loose PHP | a `.php` file with no plugin header | `samples/webroot/<basename>` |
| zip | `.zip` magic; unpack and re-detect | per contents |
| directory | scan for a plugin header or `style.css` | plugin or theme |

Ambiguous or undetectable input aborts with a message naming what was checked;
`--type` is intentionally not offered in this version (YAGNI) — an analyst with
an unusual sample uses a recipe.

### Triggering

Default per type (all requests are plain HTTP to `http://127.0.0.1:8088`):

- **plugin**: `wp --skip-plugins plugin activate <slug>` (state change; the
  wrapper keeps it out of the traced process), then `GET /` and an
  authenticated `GET /wp-admin/` so `init` and `admin_init` payloads fire.
- **theme**: `wp --skip-plugins theme activate <slug>`, then `GET /`.
- **webshell / loose PHP**: `GET /<basename>` with no parameters, then `GET /`.
  A shell's real inputs cannot be guessed; this confirms the file executes and
  the analyst adds a recipe for parameters.

Every default request reuses one admin session (established once with the
`.env` credentials) so admin-only payloads are reachable.

### Recipe file

Optional. Default path `<sample>.kadath` next to the sample; `--recipe`
overrides. Declarative, line-based, no host shell:

```
# lines are comments, LOGIN, GET, or POST
LOGIN admin sandbox
GET  /shell.php?cmd=id
POST /wp-admin/admin-ajax.php  action=foo&x=1
```

- `LOGIN <user> <pass>` establishes an admin session reused by later requests.
  With no `LOGIN`, requests are unauthenticated.
- `GET <path>` and `POST <path> <urlencoded-body>` issue one request each to
  `127.0.0.1:8088`, recorded in `run.env`.
- A recipe replaces the type default for webshells; for plugins/themes the
  activation still happens, then the recipe requests run (so a recipe adds
  admin actions on top of activation). Unknown directives abort with the line
  number.

The recipe can only cause HTTP requests into the already-contained sandbox,
so an attacker-supplied recipe cannot escalate.

### DB diff

Before triggering and after, capture:

- `wp --skip-plugins user list --fields=ID,user_login,user_email,roles --format=json`
- `wp --skip-plugins option list --format=json` (filtered to a stable subset:
  everything, then diffed — transient/cache options are noted but not
  suppressed, to avoid hiding a malicious option)
- `wp --skip-plugins cron event list --format=json`

`--skip-plugins` is mandatory so the sample's own hiding hooks do not filter
the ground truth. The diff yields: users added / removed / role-changed,
options added / changed, cron events added. This is what catches a
create-hidden-admin backdoor regardless of tracing.

### Outputs (all under `reports/<slug>-<ts>/`)

**`run.env`** — the contract kadath-detonate/kadath-analyze already use:
`RUN_EPOCH`, `RUN_UTC`, `SLUG`, `SAMPLE_SRC`, `SAMPLE_SHA256`, `SAMPLE_MD5`,
`SAMPLE_TYPE`, `TRIGGER_ACTIONS` (newline-separated).

**`summary.json`** — deterministic facts, everything filtered to the run window:

```json
{
  "sample": { "filename": "...", "path": "...", "sha256": "...", "md5": "...", "size_bytes": 0, "type": "plugin" },
  "run": { "epoch": 0, "utc": "...", "slug": "...", "trigger_actions": ["..."], "reset": false },
  "db_diff": {
    "users_added": [ { "id": 0, "login": "...", "email": "...", "roles": ["..."] } ],
    "users_removed": [ ... ],
    "users_role_changed": [ { "login": "...", "from": ["..."], "to": ["..."] } ],
    "options_added": [ { "name": "...", "value": "..." } ],
    "options_changed": [ { "name": "...", "from": "...", "to": "..." } ],
    "cron_added": [ { "hook": "...", "next_run": "..." } ]
  },
  "callchain": [ { "function": "...", "file": "...", "line": 0 } ],
  "dangerous_calls": [ { "function": "...", "count": 0, "first_arg": "..." } ],
  "files_written": [ { "op": "file_put_contents", "path": "...", "caller": "file:line" } ],
  "network": {
    "dns": [ "example.com" ],
    "flows": [ { "host": "...", "method": "GET", "path": "/", "status": 200, "wp_core": false } ],
    "dropped": [ { "dst": "1.1.1.1", "port": 6667 } ]
  },
  "artifacts": { "traces": ["..."], "sp_dumps": ["..."], "pcaps": ["..."] },
  "warnings": [ "no new trace produced; sample may need a recipe" ]
}
```

`wp_core` flags api.wordpress.org and the base image's own health traffic so
the analyst separates sample behaviour from WordPress noise.

**`iocs.json`** — conforms to
`.claude/skills/kadath-analyze/references/iocs-schema.json`, pre-filled from
the deterministic sources above (added users, credentials visible in the
trace, options, usermeta keys, slug, file hashes, and network indicators).
Behavioural and string IOCs are left empty for the analyst.

### Marker for the self-test gate

`make selftest` (or `bin/kadath`) writes `.kadath/selftest-pass` containing the
image build id it verified (a hash of the relevant Dockerfiles, or the
`wordpress`/`gateway` image ids from `docker compose images -q`). The engine
compares against the current build to decide whether the gate is satisfied.
`.kadath/` is gitignored.

## Repository layout additions

```
KadathSandbox/
  bin/kadath                     the engine (Python 3, executable)
  kadath/                        engine package (importable, unit-tested)
    __init__.py
    detect.py                    type detection
    stage.py                     isolate + stage
    trigger.py                   default triggers + recipe execution
    dbdiff.py                    before/after WP DB diff
    traceparse.py                Xdebug callchain, files_written, dangerous_calls
    network.py                   dns/flows/dropped summary from artifacts
    summary.py                   assemble summary.json + iocs.json
    run.py                       orchestration (the flow above)
  tests/
    fixtures/                    small saved traces, before/after wp json, sample .kadath
    test_detect.py test_traceparse.py test_dbdiff.py test_network.py test_recipe.py
    test_detonate_e2e.sh         end-to-end acceptance (probe + integrity-scanner)
  Makefile                       + detonate target
```

`.kadath/` (lock, selftest marker) and `reports/` are gitignored.

## Testing

**Unit (pure functions, fixtures, no Docker):**
- `detect.py`: each type from a representative header/file.
- `traceparse.py`: against a saved small `.xt` fixture — callchain extraction,
  files_written, dangerous_calls, argument rendering, the tab-column layout.
- `dbdiff.py`: before/after `wp ... --format=json` fixtures — added user,
  role change, added option, added cron.
- `network.py`: saved `dns.log` / `dropped.log` lines and a small flows dump —
  window filtering and wp_core flagging.
- `recipe.py`: parsing (LOGIN/GET/POST, comments, unknown directive error).

**End-to-end acceptance (`test_detonate_e2e.sh`, requires the stack):**
- `bin/kadath detonate tests/probe.php`: `summary.json` well-formed, empty
  `db_diff.users_added`, non-empty `callchain`, a decrypted example.com flow,
  the raw-TCP 6667 attempt in `dropped`.
- `bin/kadath detonate <integrity-scanner-156 sample>`: `db_diff.users_added`
  contains `sys_maint` with role administrator; `callchain` non-empty;
  `iocs.json` validates against the schema and lists the user and its
  credentials.
- Both leave a lock-free state and a snapshot.

`make selftest` remains the sandbox-level gate and is unchanged.

## Error handling

| Condition | Behaviour |
|---|---|
| Sample missing or unsupported type | abort, nonzero, name what was checked |
| Stack will not become healthy | surface the `make up` error, nonzero |
| Self-test fails (and not `--skip-selftest`) | abort, nonzero: results untrustworthy |
| Lock held | abort, nonzero: "another detonation is in progress" |
| Unknown recipe directive | abort, nonzero, with the line number |
| Trigger produced no new trace | warning in `summary.json`, still emit, exit 0 |

## Containment invariants (must hold)

- The engine only ever calls: `make up/reset/snapshot/selftest`,
  `docker compose up/exec/logs/images/ps/cp` (ps and cp are read-only / copy trusted
  engine code into the gateway), `mitmdump` inside the gateway, and HTTP to `127.0.0.1:8088`.
- It never edits `docker-compose.yml`, `netguard`, `gateway`, or any container
  security setting; never adds a capability; never publishes a port.
- The sample and every artifact are treated as data: parsed, hashed, quoted —
  never executed on the host.
- The recipe format is declarative; it cannot run host commands.
- One detonation at a time (lock).

## Out of scope

- The web front end (sub-project 2).
- Updating `kadath-analyze` to consume `summary.json` (follow-up).
- Narrative report or YARA generation (stays with the skill).
- Multi-sample or parallel detonation.
- `--type` override and non-HTTP trigger directives (add only if a real
  sample needs them).
