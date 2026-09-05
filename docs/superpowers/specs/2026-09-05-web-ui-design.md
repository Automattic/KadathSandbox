# KadathSandbox web UI: a localhost front end over the detonate engine

Date: 2026-09-05
Status: approved design, pending implementation plan

## Purpose

Give an analyst a browser front end for one-command detonation: drop a
sample onto a page, watch the run progress live, and read the resulting
report — without touching a terminal. It is a thin control plane that shells
out to the existing `bin/kadath detonate` engine; it adds no analysis logic
of its own and does not touch the containment boundary.

This is sub-project 2 of 2. Sub-project 1 (the CLI engine,
`docs/superpowers/specs/2026-09-04-detonate-cli-design.md`) is complete and
merged; this spec builds directly on it.

## Decisions taken during brainstorming

| Question | Decision |
|---|---|
| Deployment | Localhost only, single analyst, no login; binds `127.0.0.1:8090` |
| Live feedback | Start-and-poll with a live phase log streamed from the engine's stderr |
| Tech stack | Pure Python standard library (`http.server`) + one static HTML page with vanilla JS; no dependencies, no build step |
| Run model | One background job at a time, held in memory; the engine's own lock is the backstop |
| Verdict | Computed server-side in Python from `summary.json`, returned as a field |

## Architecture

### Entry points

- `bin/kadath web [--port 8090] [--engine <cmd>]` — start the server.
- `make web` — convenience wrapper calling `bin/kadath web`.

`bin/kadath` gains a `web` subcommand alongside `detonate`. The server is a
single stdlib module `kadath/web.py` (standard library only, consistent with
the engine). It shells out only to `bin/kadath detonate`; it never calls
Docker, `make`, or `wp` directly, so the containment model is unchanged.

`--engine <cmd>` overrides the detonate command (default:
`<repo>/bin/kadath detonate`) so tests can inject a fake engine. It is a host
operator flag, not exposed in the UI.

### Job model

One `Job` at a time, in memory in the single server process:

```
Job = {
  id: str,              # url-safe token
  state: str,           # "running" | "done" | "error"
  phase_lines: [str],   # engine stderr lines, appended live
  report_dir: str|None, # set on success
  summary_path: str|None,
  error: str|None,      # set on failure
  started: float,
}
```

`POST /run` writes the uploaded sample under `.kadath/web/<job-id>/`, spawns
`bin/kadath detonate <sample> --json [--recipe <path>] [--reset]` via
`subprocess.Popen`, and starts a daemon reader thread that:
- reads the engine's **stderr** line by line into `job.phase_lines`,
- captures **stdout** (the `summary.json` path the engine prints on success),
- on process exit sets `state` to `done` (rc 0, with `report_dir` derived from
  the summary path's parent) or `error` (rc != 0, with the tail of stderr as
  `error`).

Only one job runs at a time. A second `POST /run` while a job is `running`
returns HTTP 409 with a clear message. The engine's `flock` is the ultimate
backstop, but the web layer refuses first so the user gets a clean message.

Jobs are kept in memory only; a server restart forgets them (the reports on
disk survive and remain readable via the CLI). This is acceptable for a
single-analyst local tool.

### Endpoints

| Method + path | Purpose |
|---|---|
| `GET /` | the single HTML page |
| `GET /app.js`, `GET /app.css` | the page's script and styles (static, so CSP can forbid inline script) |
| `POST /run` | multipart upload (sample, optional recipe, reset checkbox, CSRF token) → `{job_id}` or 409 |
| `GET /status/<id>` | `{state, phase_lines, report_dir}` — polled ~1s |
| `GET /report/<id>` | `{summary, iocs, verdict}` for a finished job |
| `GET /artifact/<id>/<name>` | download one allowlisted artifact of the run |

All other paths return 404. Only `GET` and `POST` are accepted.

### The page (`kadath/web_index.html` + `app.js` + `app.css`)

Three sequential states in one page, vanilla JS:

1. **Upload** — a form: required sample file, optional `.kadath` recipe file,
   a "Reset stack first (clean slate)" checkbox, and a hidden CSRF token.
   Submits `POST /run` as `multipart/form-data` via `fetch`; on success
   switches to Running with the returned job id.
2. **Running** — a live log panel that appends new `phase_lines` from
   `GET /status/<id>` polled every ~1 s, with a visible note that the first
   run can take several minutes (the self-test gate) so it does not read as a
   hang. On `state: error`, shows the error text and a "start over" control.
3. **Report** — on `state: done`, fetches `/report/<id>` and renders:
   - **Verdict banner** (server-computed): red / amber / green (see Verdict).
   - **Database changes**: users added (new administrators flagged red),
     role changes, options added, cron added.
   - **What the sample did**: call chain (its own functions, `file:line`),
     dangerous calls with first argument, files written.
   - **Network**: DNS names, decrypted flows (host/method/path/status, with
     `wp_core` rows dimmed), dropped connections.
   - **IOCs**: the `iocs.json` indicator table.
   - **Artifacts & raw**: a download link per artifact and for the raw
     `summary.json`/`iocs.json`, plus the report directory path for CLI
     follow-up.

Every value originating from the sample is inserted with `textContent`, never
`innerHTML`.

### Verdict (server-side)

`GET /report` computes a `verdict` object `{level, reasons: [str]}` from
`summary.json`:

- **red** if `db_diff.users_added` contains a user whose roles include
  `administrator`, or `db_diff.users_role_changed` grants `administrator`, or
  `network` has any non-`wp_core` flow or any `dropped` entry.
- **amber** if not red but there are `dangerous_calls`, `files_written`, or
  any `db_diff` change at all.
- **green** otherwise.

`reasons` lists the specific facts that set the level (e.g. "administrator
`sys_maint` created", "3 files written", "blocked TCP to 1.1.1.1:6667"), so
the banner explains itself. Verdict logic lives in a pure function
(`kadath/web_verdict.py`) so it is unit-tested directly.

## Security

The server spawns detonations and serves sample-controlled bytes, so:

1. **Bind `127.0.0.1` only.** Never `0.0.0.0`. `--port` changes the port, not
   the interface.
2. **Host-header allowlist.** Every request's `Host` must be
   `127.0.0.1:<port>` or `localhost:<port>`; otherwise 421. This blocks
   DNS-rebinding attacks that resolve an attacker domain to `127.0.0.1`.
3. **CSRF token on state change.** A random token is minted at server start
   and embedded in the page; `POST /run` requires it (form field), else 403.
   Combined with the Host allowlist this stops a page in the same browser from
   triggering a detonation.
4. **Artifact serving is allowlisted and inert.** `GET /artifact/<id>/<name>`
   serves only a path that appears in that run's `summary.json` `artifacts`
   list. The resolved `realpath` must stay within the repo root, else 403
   (rejects `..`, absolute paths, symlinks that escape). Every artifact is
   sent as `text/plain; charset=utf-8` with `Content-Disposition: attachment`
   and `X-Content-Type-Options: nosniff` — nothing renders as HTML.
5. **Strict CSP on all responses.**
   `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline';
   img-src 'self'; base-uri 'none'; form-action 'self'`. The page's JS is a
   separate `/app.js` file so no inline script is needed.
6. **Uploads are opaque bytes.** Total request body capped at 25 MB (413 over
   the cap). The sample is written under `.kadath/web/<job-id>/` with a
   sanitized basename (alnum, `-`, `_`, `.`; no path separators). The web
   layer never parses or executes the sample or any artifact — it hands the
   sample path to the engine and reads back the engine's JSON.
7. **Only the engine is spawned.** The subprocess argv is fixed
   (`bin/kadath detonate <sample> --json` plus the boolean/`--recipe` flags);
   no request value is ever interpolated into a shell — `Popen` is called with
   an argv list, `shell=False`.

The web layer holds the same line as the rest of the sandbox: it never edits
`docker-compose.yml`, `netguard`, `gateway`, or any container setting; never
adds a capability or publishes a container port; treats sample and artifact
content as data.

## Repository layout additions

```
KadathSandbox/
  kadath/
    web.py            the http.server: request handler, routing, job model
    web_verdict.py    pure verdict computation from summary.json
    web_index.html    the page
    web_app.js        the page's script (served at /app.js)
    web_app.css       the page's styles (served at /app.css)
  bin/kadath          + the `web` subcommand dispatch
  Makefile            + the `web` target
  tests/
    test_web_verdict.py    verdict levels + reasons
    test_web_paths.py      artifact path-safety (traversal, non-allowlist)
    test_web_guards.py     Host allowlist, CSRF, method/size limits
    test_web_flow.py       full job lifecycle against a FAKE engine stub
    fixtures/fake_engine.sh a stub that prints canned stderr + a summary path
    fixtures/web_summary.json a canned report for verdict/report tests
```

`.kadath/web/` is gitignored (already covered by `.kadath/`).

## Testing

**Unit (stdlib, no real detonation):**
- `test_web_verdict.py`: red for an added administrator / a non-wp_core flow /
  a dropped entry; amber for dangerous calls or files written with no red
  trigger; green for a benign run; `reasons` name the specific facts.
- `test_web_paths.py`: `/artifact` serves an allowlisted file; rejects a path
  not in `summary.json.artifacts`, a `..` traversal, an absolute path, and a
  symlink escaping the repo.
- `test_web_guards.py`: a foreign `Host` → 421; `POST /run` without the CSRF
  token → 403; a non-GET/POST method → 405; a body over 25 MB → 413.
- `test_web_flow.py`: with `--engine fixtures/fake_engine.sh`, drive the whole
  flow over `http.client` on an ephemeral port — `POST /run` returns a job id,
  `GET /status` transitions running→done with the stub's phase lines, a second
  `POST /run` while running → 409, `GET /report` returns the canned summary +
  computed verdict, `GET /artifact` downloads an allowlisted file.

The fake engine (`fixtures/fake_engine.sh`) prints two or three canned phase
lines to stderr, writes a canned `summary.json`/`iocs.json` into a report dir,
prints that summary path to stdout, and exits 0 — so `test_web_flow.py` never
starts Docker.

**End-to-end (gated, needs the stack):** `tests/test_web_e2e.sh` starts the
real server on an ephemeral port, `POST`s `tests/probe.php`, polls
`GET /status` to `done`, and asserts `GET /report` returns a summary with a
non-empty call chain and a computed verdict. Skipped when Docker is not
available, like the detonate e2e.

## Error handling

| Condition | Behaviour |
|---|---|
| Second run while one is active | `POST /run` → 409, clear message; UI shows it |
| Engine exits non-zero | job `state: error`, stderr tail in `error`; UI shows it + start-over |
| Upload over 25 MB | 413 before spawning anything |
| Missing/failed sample (engine reports unsupported) | surfaces as job error with the engine's message |
| Foreign Host / missing CSRF / bad method | 421 / 403 / 405, no side effect |
| `GET /status` or `/report` for an unknown id | 404 |
| Artifact path not allowlisted or escaping repo | 403 |

## Out of scope

- Multi-user, authentication, or a shared/hosted deployment (localhost single
  analyst only).
- Persisting job history across server restarts (reports persist on disk;
  the CLI and `kadath-analyze` read them).
- Editing or re-running a report, diffing runs, or a run history list.
- Narrative report or YARA generation (still the `kadath-analyze` skill's job).
- Any change to the detonate engine's behaviour beyond adding the `web`
  subcommand dispatch in `bin/kadath`.

## Security notes for the analyst

- The page runs on your machine and drives real detonations; keep it on
  `127.0.0.1` and do not expose the port. The Host/CSRF guards defend against
  a malicious site in the same browser, not against deliberately publishing
  the port to a network.
- Downloaded artifacts are hostile content served as inert attachments; treat
  them as you would any malware artifact. Do not open a downloaded trace or
  flow in a browser tab.
