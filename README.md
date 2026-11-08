# KadathSandbox

An isolated WordPress sandbox for offering untrusted PHP: plugins, themes, webshells, droppers.
Nothing the sample does can leave except through a decrypting proxy and DNS lookups, which are
logged, and it cannot switch the recording off: the packet capture, the proxy and the DNS log run in containers it has no access
to, and the in-process off switches (`xdebug_stop_trace`, `ini_set('error_log', ...)`) are
disabled. It *can* delete artifact files that have already been written — the observation layer
needs those directories writable by the same uid the sample runs as — so run `make snapshot`
after every offering. See [Caveats](#caveats).

The tool speaks in the vocabulary of Lovecraft's *Dream-Quest of Unknown Kadath* — the Offering, the Wards, the Gaunts, the Omens, the Scrying. [LORE.md](LORE.md) is the dictionary between that and plain security terms.

## What you get

| Layer | Tool | Output |
|---|---|---|
| Every PHP function call, with arguments, return values and eval'd code | Xdebug 3.5 trace mode | `artifacts/xdebug/trace.<time>.<req>.xt` (one per request) |
| Dangerous PHP calls (`system`, `exec`, `curl_exec`, `unserialize`, `base64_decode`, remote `include`, ...) | Snuffleupagus 0.14 in simulation mode | `artifacts/php/php-error.log` (every call, with arguments), `artifacts/sp-dumps/` (one `sp_dump.<sha256>` file per matching rule, not per call) |
| Decrypted HTTP and HTTPS | mitmproxy 12 transparent mode | `artifacts/mitm/flows.mitm`, UI at http://127.0.0.1:8081 |
| DNS lookups | dnsmasq on the gateway | `artifacts/dns/dns.log` |
| Every packet from the sandbox | tcpdump in the `netcap` sidecar, inside the sandbox's own network namespace | `artifacts/pcap/sandbox-<ts>.pcap00`… (rotated, 20 × 100 MB) |
| Anything the sandbox put on the wire that it was not supposed to (IRC, raw C2, SMTP...) | tcpdump filter in `netcap`; dropped by the gateway. Lines from the management interface are prefixed `mgmt` | `artifacts/dropped.log` |
| Syscalls, file I/O, process spawns | strace, bpftrace sidecar | `artifacts/strace/`, terminal |

`artifacts/sp-dumps/` will already be non-empty right after `make up` finishes installing WordPress:
WP-CLI itself trips the `base64_decode` rule during install, and Snuffleupagus writes one dump per
rule that matches, not one per call. For per-call detail (every hooked call with every argument),
read `artifacts/php/php-error.log` instead.

## Requirements

- Docker with Compose v2 or later. Developed on macOS (Apple Silicon) with OrbStack; works on Linux Docker hosts.
- About 2 GB of disk for images, plus whatever traces the samples produce.

**On a native Linux Docker host**, the `artifacts/` bind mounts arrive owned by your user,
and PHP inside the container runs as uid 33. Before the first `make up`:

```bash
chown -R 33:33 artifacts/
```

The `wordpress` entrypoint checks this and refuses to start with a clear message otherwise —
without the check, traces and dumps would silently never be written. macOS (Docker Desktop,
OrbStack) remaps ownership and needs nothing.

## Deploy

```bash
cp .env.example .env          # edit passwords if you like; defaults are fine for a local sandbox
make up                        # builds images, starts db, gateway, wpnet, netguard, netcap, wordpress
make selftest                  # proves every layer works. Do this before loading real malware.
```

Then:
- WordPress: http://127.0.0.1:8088 (admin login from `.env`, default `admin` / `sandbox`)
- mitmweb: http://127.0.0.1:8081 (password from `.env`, default `sandbox`)

## Driving the sandbox with a Claude Code agent

This repo ships four skills under `.claude/skills/` (also packaged as the `kadath-sandbox`
plugin) so an agent can run the whole workflow:

- **kadath-offer** — stage a sample, trigger it through the traced path, mark the run.
- **kadath-scry** — read one run's artifacts into a report, `iocs.json`, and a draft YARA rule.
- **kadath-gaunt** — attach strace/bpftrace to php-fpm for OS-level evidence.
- **kadath-ward** — start, reset, snapshot, self-test, and troubleshoot without weakening containment.

Open this directory in Claude Code and the skills are discovered automatically (a fresh session
picks up newly added skills). Elsewhere, install with `/plugin marketplace add Automattic/KadathSandbox`
then `/plugin install kadath-sandbox@kadath`. An offering writes its report to `reports/<slug>-<ts>/`.

## One-command offering

For a scripted run without an agent:

    make offer SAMPLE=path/to/sample.php
    # or, with options:
    python3 bin/kadath offer path/to/sample.php [--recipe r.kadath] [--reset] [--json] [--stub-missing] [--adopt-wp]

`--stub-missing` is for a single file lifted out of a kit: when PHP reports a
missing include or an undefined function, the engine writes an empty stand-in
under `samples/webroot/` (functions return `null`) and triggers again, up to
three rounds, so the sample gets past its first `require`. What was stubbed is
recorded in `summary.json` under `run.stubs`, and `run.fatal` says whether a
fatal survived the last round.

`--adopt-wp` is for a file lifted out of a plugin or theme: as a bare webshell
it dies on its first `add_action()` because WordPress is not loaded. Adopted, it
is wrapped as a synthetic plugin (`Plugin Name: kadath-adopted <slug>`) with an
empty shims file loaded before it, staged under `samples/plugins/`, and
activated — WordPress functions and classes exist, its hooks fire on `GET /`,
and shims for non-core helpers it still misses go into the shims file.
`run.adopted` records it. The pilgrimage passes both flags, adopting whenever
the source references WordPress APIs.

It brings the stack up, runs the self-test gate once per build, isolates any
prior sample, stages and triggers this one by type, snapshots, and writes
`reports/<slug>-<ts>/` with `run.env`, `summary.json` (DB diff, call chain,
network summary, artifact list), and a pre-filled `iocs.json`. The narrative
report and YARA rule are still the `kadath-scry` skill's job, working from
that structured input. Every value in `run.env` is shell-quoted with control characters stripped,
because the scry skill sources it and the sample's path is attacker data; the trigger actions are
no longer in it but in `summary.json`, under `run.trigger_actions`.

The default triggers for a plugin log in as the WordPress admin the stack was installed with,
read from `WP_ADMIN_USER` / `WP_ADMIN_PASSWORD` (environment first, then `.env`), not from a
hard-coded login. Success is judged by a `wordpress_logged_in_*` cookie that the login POST itself returned (one the
sample planted on an earlier response does not count), since the HTTP code is the same either way; `summary.json` records it as `run.login_ok` (`true`, `false`, or `null`
when no login was attempted), a failed login adds a warning, and the trigger action reads
`LOGIN admin -> 200 ok` or `FAILED`. A run that never got past the login proves little about the sample.

Between offerings the engine puts the WordPress docroot back to the image's pristine tree: files a
previous sample dropped anywhere under `/var/www/html` (an uploads shell, an mu-plugin, a
`.user.ini`, a patched core file) are removed, and `wp-config.php` is deleted so the entrypoint
regenerates it with fresh salts (appending to it is textbook persistence). The cleanup itself runs `wp`, which loads `wp-config.php`,
the mu-plugins and the drop-ins, so before running any `wp` command the engine checks the docroot for
code the previous sample persisted (anything in `mu-plugins`, a drop-in such as `db.php` or
`object-cache.php`, a `wp-config.php` that changed or became a symlink). If it finds any, it restores
the docroot and recreates the container first; a restore that fails is fatal (exit 3). The same check
runs after the trigger: what it finds goes into `run.docroot_tainted`, with a warning that the
database diff read through `wp` is untrusted. The restore copes with filenames containing newlines
and with directories the sample made read-only. The database is put
back too: the engine records a baseline of what the install legitimately holds (option names,
cron hooks, post IDs, in `.kadath/db-baseline.json`, taken after `--reset` or, failing that, from
the live database on the first offering, which then skips the reset and says so), and before each
offering deletes the options, cron events and posts (with their postmeta) that are not in it, drops
users other than the install admin, and rewrites `active_plugins` to the plugins whose files still
exist. Transients, `cron` and `recently_activated` are left to WordPress. The baseline is tied to
the install, so a `make reset` run by hand makes it stale and it is re-recorded. If the install admin
cannot be read (a sample deleted it), the baseline cannot be validated: the engine then does not
re-record it and skips the DB reset, and a warning says residue may remain, instead of crashing. Not undone: a
stock option whose *value* a sample changed (`users_can_register`, `admin_email`; the baseline
holds names only), custom tables, and usermeta on the admin, so `--reset` remains the full clean
slate. If a sample kills php-fpm or supervisord (it shares their uid), the engine records a
warning and writes the summary with an empty DB diff instead of crashing. The container
restarts itself (`restart: unless-stopped`; the network namespace belongs to `wpnet`, so the
guard survives, and the entrypoint refuses to start without it), and the engine compares the
container's start time before and after the trigger. A changed start time adds the warning
"wordpress container restarted during the run (the sample likely killed php-fpm or supervisord;
the restart policy brought it back)" and sets `run.wp_restarted: true` in `summary.json`, so a
kill is recorded even when the restart was fast. Zip samples are refused
above 256 MiB uncompressed or 20000 entries. A zip is classified by its own top level before anything
nested: a plugin header in a `.php` directly under the package root wins over a theme `style.css`
deeper in the tree. A loose PHP sample named like a reserved WordPress entry point (`index.php`,
`wp-config.php`, a dotfile, or a top-level core file such as `wp-login.php`) is refused with a message,
because the entrypoint would not link it and the engine would end up requesting WordPress's own file;
rename it, or offer it with `--adopt-wp`.

For a sample the defaults can't drive (a webshell needing specific parameters,
or an admin action), drop a `<sample>.kadath` recipe next to it:

    LOGIN admin sandbox
    GET  /shell.php?c=id
    POST /wp-admin/admin-ajax.php  action=foo&x=1

A recipe path must start with a single `/` and hold no whitespace or control characters, so it cannot
retarget the host. The engine's HTTP client never follows redirects (the sample picks the `Location`)
and ignores proxy environment variables, and `<sample>.kadath` is read only if it is a regular file,
not a symlink.

Only one offering runs at a time; the lock is taken before the preflight, so a second offering
cannot start `make up` or the self-test under the first. Every shell call the engine makes has a
10-minute timeout (30 minutes for `make up`, `reset` and `selftest`) and runs in its own process
group, so a timeout or Ctrl-C kills what `make` and `docker` spawned, not just the direct child. A
plugin or theme that fails to activate is a warning, not an abort: the trigger still runs. The
command never edits the containment
configuration; to reach a private lab target use the `GATEWAY_BLOCKED_DESTS`
override described above.

## Web UI

For a browser front end instead of the CLI:

    make web        # serves http://127.0.0.1:8090

Open it, choose a sample (and optionally a `.kadath` recipe), tick "reset" for a
clean slate if you like, and click Offer. The page streams the run's live
progress, then shows a verdict banner (red / amber / green) and the report — the run's login,
restart and fatal flags and its warnings, then DB changes, call chain, network, IOCs, and
downloadable artifacts.

The level is computed by `web_verdict.compute`, which the pilgrimage also uses as its deterministic
level. Red: an administrator created or promoted, an outbound flow that is not verified WordPress
core (a spoofed Host header included), or a blocked egress attempt. Otherwise amber when there is
anything to look at, and never green when the run has warnings, `run.login_ok` is false, or
`run.wp_restarted` or `run.fatal` is set: a run that was blind or unauthenticated fails closed.
`files_written` is deduplicated by operation and path and capped at 2000, with a final `truncated`
entry as the marker.

It runs the same `bin/kadath offer` engine, one offering at a time. It binds
`127.0.0.1` only and guards against other pages in your browser (Host allowlist +
CSRF token); keep the port local — do not expose it to a network. Downloaded
artifacts are hostile content served as inert attachments; do not open a
downloaded trace or flow in a browser tab.

`Origin` and `Sec-Fetch-Site` are checked before the upload body is read, so a cross-site POST is
refused unbuffered. The page's Content-Security-Policy allows its own scripts, styles and `fetch`
(`connect-src 'self'`) and forbids framing. An engine run that fails, or outlasts 30 minutes, ends
the job in an error (its process group is killed) instead of leaving the server answering "busy"
forever. Downloads are streamed as `application/octet-stream`; when a report file and a bundle file
share a name, the report file is the one served. Uploaded filenames keep Unicode letters and are cut
to 100 characters.

Uploads are kept under `.kadath/web/<token>/`, and the server deletes upload directories older
than 7 days when it starts. A report's `sample.path` may therefore point at an upload that has
been pruned; the hashes in the report remain the record.

## The Pilgrimage — batch triage with a local model

`bin/kadath pilgrimage` walks a threat-library `for-later-review/` directory and
triages every single-PHP case with a local Ollama model, no Claude in the loop.
Three passes, each resumable from `kadath-triage.csv`:

1. **Cavern** — the Cavern of Flame: a static judgment from the source: verdict, family, malicious
   line ranges, and whether detonation would teach anything a static read cannot.
   The script forces "worthy" on anything using WordPress APIs, network
   primitives, or encoded blobs, on anything the model is not confident about, and on anything whose static facts
   show a dangerous primitive (`eval`, `system`, `unserialize` and their kin) unless the model is
   already confidently red (0.8 or more), since a confident red needs no run to be acted on.
2. **Runes** — before detonation, the sample is statically deobfuscated (literal
   `base64`/`gzinflate`/`rot13`/hex chains peeled layer by layer, no code run) and
   a security-tuned model (default CyberSecQwen-4B) reads the payload. Its verdict
   enriches the Offering, and *is* the verdict when the Offering cannot run the
   sample at all — so the tail of broken, un-runnable malware stops looping through
   the detonator. Writes `runes.json` and `unpacked/layer-*.php`. A decoy chain that will not decode does not stop
   the unpacker: it tries up to 32 candidate chains per layer, within the first 2,000,000 characters
   of the layer.
3. **Offer** — `bin/kadath offer` detonates each worthy case; the model writes
   `report.md`, `iocs.json` extras, and `draft.yar` from a compact evidence pack.
   The deterministic verdict travels with it: the model can argue, but never
   lowers it — the higher of the two wins, and any disagreement sends the case
   to the Deep Scrying.
   The Offering runs with `--stub-missing`, and the final verdict is the highest
   of the Cavern's, the deterministic, and the model's. A run whose `coverage`
   is not `full` — `stubbed` (ran against empty stand-ins), `unauthenticated`
   (never got its password, or the engine's admin login failed), `errored` (fataled) — cannot settle a green:
   runtime silence is not evidence. A case is settled when the Cavern and the
   model agree and the deterministic layer does not exceed them; everything
   else — amber, a disagreement, an unexercised green — goes to the Scry.
   The case's `scry_status`, not its offer verdict, decides this, so an unexercised green
   reaches the Scry. A verdict that came only from the Runes (the Offering could not run the
   sample, so there is no run bundle) is marked skipped with an explanatory error: there is
   nothing of this sample's to scry, and the live `artifacts/` belong to another run. If the detonation did succeed and only the verdict
   model failed, the Runes' read stands in but the deterministic verdict and the run bundle are kept,
   so the case can still be scried. When an Offering fails, the pilgrimage tells a broken sandbox from
   a broken sample by parsing `docker compose ps --format json` and requiring the wordpress service
   itself to be running; if it is not, it cycles the stack and the failure counts toward the breaker.
4. **Scry** — ambers, low-confidence reds, and every disagreement get an agentic
   re-examination with read-only tools; every claim must quote a tool result
   verbatim (at least 12 characters, or the quote would match almost anything) or it is dropped.
   It never lowers a deterministic verdict, and it cannot clear a red — deterministic, or from the
   Cavern, the Runes or the offering model — to green: that becomes amber, status `disagreement`. A
   scry that fails (budget spent, claims unverified) leaves the prior verdict, floored at amber. Tool
   output is cut at 8000 characters with a `[truncated: N more chars]` marker, and the listing tools
   take an `offset` to page through the rest.

Everything from the library is treated as hostile text. The walk skips a symlinked case directory or
`.php` file (a library entry can point anywhere); the Cavern, Runes and Offering prompts fence their
evidence and rewrite any `` ``` `` inside an interpolated field, so sample text cannot close the fence
and pose as instructions; and the models' JSON is checked against a schema that rejects `NaN` and
`Infinity`, which parsers accept and which pass every bound check.

Results are written beside each sample under `<case>/kadath/` and never
committed; promotion into the library stays a human PR.

```bash
ollama pull orcarouter/Qwen3.8-27B-Uncensored:latest
ollama pull hf.co/ree2raz/CyberSecQwen-4B-GGUF:Q4_K_M   # the Runes model (override with --runes-model)
make pilgrimage LIBRARY=~/WORK/jetpack-threat-library/for-later-review PASS=cavern LIMIT=50
```

Run the Cavern pass over everything first (~20–30 s per case), read the manifest,
then `PASS=offer` (~2–3 min and ~30 MB of `reports/` per worthy case) and
`PASS=scry`. `make pilgrimage-smoke LIBRARY=… CASES='ID1 ID2 ID3'` runs all three
passes on hand-picked cases against the real model and stack before a long run.

Knobs: `--model`, `--ollama` (env `KADATH_MODEL`, `KADATH_OLLAMA_URL`),
`--sampling deepscry.temperature=0.4` (repeatable), `--profiles file.json`,
`--seed N`, `--retry-errors`, `--force`, `--min-free-gb`. Deep Scrying must not run
at temperature 0 (Qwen3 loops with thinking on); keep `repeat_penalty` ≤ 1.1 or
JSON and YARA output degrade. The profile, model, and prompt hashes used are
recorded in every `verdict.json`.

## Loading a sample

**Drop-in (webshells, loose PHP, unpacked plugins/themes):**
```
samples/plugins/<plugin-dir>/   -> wp-content/plugins/<plugin-dir>
samples/themes/<theme-dir>/     -> wp-content/themes/<theme-dir>
samples/webroot/<file>          -> /<file> in the document root
```
The mounts are read-only and are linked on container start, so after adding files run:
```bash
docker compose up -d --force-recreate wordpress
```
Activate plugins from wp-admin or with `docker compose exec wordpress wp plugin activate <name>`.

The `wp` command inside the container runs with Xdebug off and with `--skip-plugins --skip-themes`.
WP-CLI bootstraps WordPress and fires `init`, so without that an active malicious plugin would run
inside every `wp` command, untraced, and its hooks would hide users and plugins from `wp user list`
and `wp plugin list`. Skipping plugins gives you the unfiltered database state. Set `WP_LOAD_PLUGINS=1`
when you deliberately want the sample loaded, and use wp-admin when you want activation-time
behaviour traced.

**Upload path (zips, to observe installer hooks):** wp-admin → Plugins → Add New → Upload, as a victim would.

## Analysing

- Trigger the sample from your browser or `curl http://127.0.0.1:8088/...`. Each request writes one Xdebug trace.
- `grep -n "eval\|base64_decode\|system" artifacts/xdebug/<latest>.xt` finds deobfuscation stages; eval strings and other values are recorded up to 64 KB each.
- `artifacts/php/php-error.log` lists every hooked call with its arguments.
- Open mitmweb, or replay later with `docker compose exec gateway mitmproxy -nr /artifacts/mitm/flows.mitm`.
- A request that never got a response (dead C2, a pinned certificate, a timeout) is still recorded in
  `summary.json` with `status: null` and an `error` string, and the deterministic verdict counts it red
  like a completed flow: it is an outbound attempt. A DNS lookup of a non-WordPress-core name with no flow
  behind it is amber ("DNS lookup of <name>").
- Each flow in `summary.json` carries `dst`, the IP the proxy actually connected to, and `sni`. The Host
  header is only the sample's claim, so a flow is WordPress core (`wp_core`) only when the Host names
  wordpress.org, `dst` is an address the sandbox's resolver returned for that name during the run (read
  from `dns.log`, CNAME chains followed) and the SNI, if sent, agrees. Otherwise it is marked
  `host_spoofed` and the verdict is red: "outbound HTTP(S) to <dst> with a spoofed Host header
  '<host>'". Flow extraction reads only this run's tail of `flows.mitm`; if it fails, the summary
  carries the warning "flow extraction failed (...); network summary incomplete" instead of an empty
  list that would read as silence.
- `artifacts/dropped.log` shows what the sample put on the wire that was not HTTP/DNS. In `summary.json`
  each `network.dropped` entry has `dst`, `port` and `proto` (`tcp`, `udp`, `icmp`, or `other` for any
  other IP protocol; port 0 for the last two), plus `iface: mgmt` when it came off the management
  interface; UDP and ICMP attempts are counted along with TCP. Note what it
  cannot show: packet capture taps the outbound path after the firewall, so connections `netguard`
  drops inside the namespace — anything aimed at 172.30.0.1 or another internal neighbour, or at a
  broadcast or multicast address — never reach the device and leave no line here (the management
  interface has its own tap; its lines are prefixed `mgmt`).
  Those attempts are contained one layer earlier; you will still see them in the Xdebug trace and
  in `php-error.log`, and `docker compose run --rm --no-deps --entrypoint sh netguard -c 'iptables
  -nvL OUTPUT'` gives per-rule drop counters.
- `make logs` tails gateway and wordpress.
- **The run's evidence is preserved automatically.** `make offer` bundles each run into
  `reports/<slug>-<ts>/artifacts/` with the traces gzipped (~16x), and clears the prior run's
  traces on the next offer, so `artifacts/` stays at roughly one run and each bundle is tens of
  MB. The append-only files (`dns.log`, `dropped.log`, `php-error.log`, `nginx-access.log`,
  `flows.mitm`) are bundled from the byte offset recorded before the trigger, and the live pcap is
  cut to this run's packets by timestamp, so a bundle holds this run's slice, not the history. `summary.json` lists the files of the
  bundle under `artifacts.bundle`, relative to the report directory (the gzipped traces and logs,
  the pcap slice), and the web UI's artifact links serve from the bundle, so they outlive the next
  offering; the `traces`, `sp_dumps` and `pcaps` lists remain the live paths at collection time. The sample runs as uid 33 and can `unlink()` its own live traces, but the bundle is the
  durable copy. The sample can also plant things in those mounted directories, so the bundle and the
  trace readers open files without following links and ignore anything that is not a regular file (a
  symlink, a FIFO); the engine records a warning `skipped non-regular artifact <path>` for each one it
  passes over while collecting. For a hand-staged run, `make snapshot` (also gzipped).

## OS-level monitoring (strace, eBPF)

The tracer shares the PHP-FPM PID namespace and runs privileged. It is behind a Compose profile, so it only exists when you ask for it.

```bash
make trace                                          # shell in the tracer
/opt/tracer/strace-fpm.sh                           # strace -f on all php-fpm -> artifacts/strace/
bpftrace /opt/tracer/phpfpm.bt | cat -v             # live openat / connect / execve / unlink
strace -f -e trace=network -p $(pgrep -d, -x php-fpm) 2>&1 | cat -v
```

Filter bpftrace by `comm == "php-fpm"`, not by PID: bpftrace reports PIDs from the initial namespace.

**Pipe live tracer output through `cat -v`.** Paths, argv and buffer contents printed by strace
and bpftrace are bytes the sample chose. Raw, they can carry ANSI escape sequences that repaint
or mislead your terminal, or worse on a terminal with risky escape handling. `cat -v` renders
them printable. The same applies to `grep`ping artifacts: prefer `grep -a ... | cat -v` on
`dropped.log`, `php-error.log` and trace files.

### On a native Linux Docker host

The same commands work from the host without the sidecar:
```bash
cid=$(docker compose ps -q wordpress)
pid=$(docker inspect --format '{{.State.Pid}}' "$cid")
sudo strace -f -p "$(pgrep -d, -x php-fpm)" -e trace=file,network,process
sudo bpftrace tracer/scripts/phpfpm.bt
sudo nsenter -t "$pid" -p -m -- ps aux         # look inside the container's namespaces
```

## Restarting pieces

`wordpress`, `netguard` and `netcap` live inside `wpnet`'s network namespace. If `wpnet` is ever
recreated, recreate them too, or just run `make up`, which handles ordering. Recreating only
`wordpress` (as the sample-loading step does) is always safe.

You do not have to remember this: the `wordpress` entrypoint checks, before it starts anything,
that the namespace has exactly one default route and that it points at the gateway. If `netguard`
did not re-run, the container exits with a message instead of offering the sample unguarded.

WordPress makes loopback requests to its own site URL (`http://127.0.0.1:8088`) from inside the
container — wp-cron above all. nginx listens on both 8080 and 8088 so these succeed and scheduled
tasks actually fire; you will see them in traces and in `artifacts/php/nginx-access.log`.

## Artifact growth, snapshots and reset

Three artifacts grow without bound during a long offering and are worth watching:

- `artifacts/pcap/` — capped by rotation at 20 slices of 100 MB (2 GB) per `netcap` start; the
  oldest slice is overwritten, so a very chatty sample eventually loses its earliest packets.
- `artifacts/mitm/flows.mitm` — **not** capped. Every decrypted request and response body is
  appended. A sample downloading large payloads in a loop will fill your disk.
- `artifacts/xdebug/` — one trace file per HTTP request; a WordPress page view is ~100-230 MB
  (`collect_assignments=1`, values up to 64 KB each). Live traces are not capped, but the engine
  clears the prior run's on the next offer and stores each run's gzipped (~16x) in the report
  bundle, so they do not accumulate. The report bundle copies only this run's part of the
  three growing files above, so it does not grow with their history.

```bash
make snapshot     # gzip artifacts/ (traces compressed) + container logs into snapshots/<timestamp>/
make reset        # down -v: wipes WordPress, database, the mitmproxy CA, and everything in artifacts/
```

`make snapshot` before `make reset`, always: `reset` is unrecoverable. It removes only this
project's own volumes and the contents of `artifacts/`; nothing outside the sandbox is touched.
`snapshots/` is gitignored. **Never blanket-delete files under `artifacts/` while the stack is
up** (`find artifacts -delete` and the like): `dns.log`, `dropped.log`, `flows.mitm` and the pcap
are held open by the gateway and netcap containers, and unlinking them silently stops network
capture until those containers restart. Use `make reset`, or restart `gateway`/`netcap` after.

## How containment works

- `wordpress` runs as uid 33 with every capability dropped, a read-only root, and no ability to change routes or firewall rules.
- Its network namespace is owned by `wpnet`, which sits on an `internal` Docker network (no route out) plus a management bridge that exists only to publish `127.0.0.1:8088`. `netguard` sets the default route to the gateway and installs an iptables policy inside that namespace whose outbound rules are destination-specific: the gateway (172.30.0.2) and the database (172.30.0.3) are allowed, the rest of 172.30.0.0/24 is dropped — **including 172.30.0.1, the Docker host's own address on that bridge** — and everything beyond the subnet goes out the default route into the gateway. Only *unicast* leaves on that route: broadcast, multicast and anycast datagrams (which would reach the host bridge directly, never passing the gateway) hit an explicit `DROP`. The default route is installed last, after the rules, so the route the `wordpress` entrypoint treats as proof of containment never exists without the firewall. An `ip6tables` DROP policy backs up the IPv6-off sysctls.
- The gateway redirects TCP 80/443 into mitmproxy and port 53 into dnsmasq. Its `INPUT` and `FORWARD` policies are DROP, so anything else the sample sends is captured and discarded. The proxy port (8080) accepts only connections that were REDIRECTed (`--ctstate DNAT`), and the gateway rejects its own loopback connections to it. A sample that connects straight to `172.30.0.2:8080` is not NATed, so mitmproxy would read its own address as the original destination and connect to itself in a loop (one raw connect produced ~34k self-connections), a one-line denial of service against the observation layer. The gateway also runs with `net.ipv4.ip_forward=0` (nothing is forwarded; REDIRECT delivers locally, so non-HTTP/DNS traffic is discarded by the kernel before any chain), `cap_drop: [ALL]` plus only `NET_ADMIN`, `NET_BIND_SERVICE`, `SETUID` and `SETGID` (iptables, dnsmasq on :53 dropping to `nobody`), `no-new-privileges`, a 1 GiB memory limit and `restart: unless-stopped`, and mounts only `artifacts/mitm` and `artifacts/dns`. mitmweb runs with `stream_large_bodies=1m`: request/response bodies over 1 MiB are streamed through and not stored in the flow, which bounds the proxy's memory against a sample moving gigabytes (such flows keep their headers but no body).
- The gateway also refuses to *fetch* private destinations. The sample never connects anywhere itself: it names a host and mitmproxy does the connecting, so without this the proxy would happily retrieve `http://192.168.1.1/`, `http://169.254.169.254/`, or `http://host.docker.internal/` on its behalf. The gateway `REJECT`s egress to `10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 0.0.0.0/8 127.0.0.0/8 198.18.0.0/15 192.0.0.0/24`; override with `GATEWAY_BLOCKED_DESTS` in `.env`. Public internet egress is unaffected.
- Packet capture runs in `netcap`, inside the sandbox's network namespace — the only place that sees sandbox→database and sandbox→host traffic. It shares only the network namespace with `wordpress`, so the sample can neither see nor kill the tcpdumps. It runs with `cap_drop: [ALL]` and only `NET_RAW` (no `NET_ADMIN`: it dissects sample-chosen packets as root inside the guarded namespace and has no business reconfiguring it).
- The observation layer has no in-process off switch. `xdebug_stop_trace`, `xdebug_start_trace`, `xdebug_set_filter`, `xdebug_get_tracefile_name` and `xdebug_get_function_stack` are in `disable_functions`, and Snuffleupagus pins `error_log` read-only, so `ini_set('error_log', '/dev/null')` fails. Nothing a sample needs for its own behaviour is disabled. The sample shares uid 33 with php-fpm, so it could also reconfigure the observation through `ini_set()` or a dropped `.user.ini` (`xdebug.var_display_max_data=0` would blind argument capture). The pool therefore pins the observation keys (`error_log`, `log_errors`, the `xdebug.*` trace and display settings, `auto_prepend_file`, `auto_append_file`) with `php_admin_value` / `php_admin_flag`, which neither can override, and `user_ini.filename=` is empty so `.user.ini` files in the docroot are ignored entirely. `error_reporting` is pinned to `E_ALL` too, so `ini_set()` and `.user.ini` cannot silence the fatals the engine reads; calling `error_reporting(0)` or using `@` still can, because they bypass the ini pin (a Snuffleupagus rule on `error_reporting` would close that). The pool sets `request_terminate_timeout = 120s` because `max_execution_time` counts CPU time and a `sleep()` loop would otherwise hold one of the four workers forever and starve every later trigger, and supervisord restarts php-fpm effectively without limit (`startretries=1000000`) so a sample killing it in a loop cannot leave it `FATAL` while nginx still answers.
- The `wordpress` healthcheck hits `/fpm-ping` (nginx passes it, from 127.0.0.1 only, to php-fpm's `ping.path`) and requires the body `pong`, so a sample that unlinks or hijacks the FPM socket turns the container unhealthy; `/healthz` is answered by nginx alone and is kept only for tools that want a bare liveness route. Every service's Docker log is capped (`json-file`, 50 MB x 3), because php-fpm's `catch_workers_output` would otherwise let a sample grow it without bound.
- TLS is decrypted because the sample's PHP trusts only the mitmproxy CA. WordPress's own HTTP API (`wp_remote_get` and friends, which most WordPress malware uses for C2) ignores `openssl.cafile` and verifies against `wp-includes/certificates/ca-bundle.crt`, so the entrypoint appends the mitmproxy CA to that bundle (the engine's docroot restore re-applies it). Only the certificate is mounted into the container, not the whole mitmproxy config volume: the CA private key lives there too.
- The database's `root` account is confined to the db container's own loopback (`MARIADB_ROOT_HOST=localhost`), so the published default root password is not usable from the sample's container.

## Caveats

- This is container isolation, not a VM. Run it on a machine you can afford to rebuild, never one holding production credentials.
- DNS is a real egress channel. Every lookup the sample makes is forwarded by dnsmasq to the host's resolver and answered truthfully, so a sample can exfiltrate data in query names (DNS tunnelling). It is logged in `artifacts/dns/dns.log` but not blocked.
- HTTP(S) C2 traffic is real: the attacker sees your egress IP. Use a VPN or burner network if attribution matters.
- Certificate-pinned samples will fail the TLS handshake; mitmproxy logs the SNI, and the engine records the failed attempt as a flow with an `error`. To pass a host through undecrypted, set `MITM_EXTRA_ARGS=--ignore-hosts 'host\.example:443'` in `.env`.
- No IPv6 rules exist on the gateway: IPv6 is disabled in the WordPress namespace (sysctls on `wpnet`, `/proc/net/if_inet6` empty, checked by the self-test, with an `ip6tables` DROP policy as a backstop) and the Compose networks have no IPv6 subnets. If you enable IPv6 on these networks, the containment must be revisited.
- **A child interpreter escapes the PHP-level pins and Xdebug.** The pool pins (`php_admin_value`, the empty `user_ini.filename`) cover php-fpm only. A sample that starts its own interpreter — `exec('php -n script.php')`, `XDEBUG_MODE=off php ...`, or the `wp` wrapper, which sets `XDEBUG_MODE=off` — runs with no pins and no Xdebug trace (`make selftest` prints an informational line proving `php -n` works as uid 33). What remains for that code: the Snuffleupagus `exec`/`system` line (with argv) that spawned it, the pcap and the mitmproxy flows, and `kadath-gaunt` (strace) for OS-level evidence.
- Treat `artifacts/` as hostile: decrypted flows and dumps can contain second-stage payloads. Read them with `cat -v` / `grep -a ... | cat -v` rather than letting raw sample bytes hit your terminal.
- **Use a throwaway browser profile** for http://127.0.0.1:8088 and http://127.0.0.1:8081. You are pointing a browser at attacker-controlled HTML with a real session; a profile holding your normal cookies, extensions and saved passwords is exposed to whatever the sample serves, and mitmweb renders sample-controlled request and response bodies too.
- **The sample can delete artifacts that were already written.** It runs as uid 33 and the artifact directories must be writable by uid 33 for the observation layer to work at all, so anti-forensic `unlink()` is available to it. It cannot stop the recording — `netcap`, mitmproxy and dnsmasq write from containers it has no access to, and the PHP-side off switches are disabled — but it can destroy what is on disk. `make snapshot` after each offering is the mitigation.

**Durability.** The pilgrimage mirrors its progress ledger (`kadath-triage.csv`) to `<repo>/.kadath/manifests/<library>-<hash>-kadath-triage.csv`, outside the threat-library repo, and restores from it if the in-library copy is lost (e.g. a `git clean -fdx` on the library). Per-case `kadath/` artifacts are regenerable by re-running a pass; the ledger is the expensive state, so it is the one kept safe.
