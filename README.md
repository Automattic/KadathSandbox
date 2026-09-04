# KadathSandbox

An isolated WordPress sandbox for detonating untrusted PHP: plugins, themes, webshells, droppers.
Nothing the sample does can leave except through a decrypting proxy, and it cannot switch the
recording off: the packet capture, the proxy and the DNS log run in containers it has no access
to, and the in-process off switches (`xdebug_stop_trace`, `ini_set('error_log', ...)`) are
disabled. It *can* delete artifact files that have already been written — the observation layer
needs those directories writable by the same uid the sample runs as — so run `make snapshot`
after every detonation. See [Caveats](#caveats).

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

- **kadath-detonate** — stage a sample, trigger it through the traced path, mark the run.
- **kadath-analyze** — read one run's artifacts into a report, `iocs.json`, and a draft YARA rule.
- **kadath-syscalls** — attach strace/bpftrace to php-fpm for OS-level evidence.
- **kadath-ops** — start, reset, snapshot, self-test, and troubleshoot without weakening containment.

Open this directory in Claude Code and the skills are discovered automatically (a fresh session
picks up newly added skills). Elsewhere, install with `/plugin marketplace add Automattic/KadathSandbox`
then `/plugin install kadath-sandbox@kadath`. A detonation writes its report to `reports/<slug>-<ts>/`.

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
- `artifacts/dropped.log` shows what the sample put on the wire that was not HTTP/DNS. Note what it
  cannot show: packet capture taps the outbound path after the firewall, so connections `netguard`
  drops inside the namespace — anything aimed at 172.30.0.1 or another internal neighbour, and
  anything originated on the management interface — never reach the device and leave no line here.
  Those attempts are contained one layer earlier; you will still see them in the Xdebug trace and
  in `php-error.log`, and `docker compose run --rm --no-deps --entrypoint sh netguard -c 'iptables
  -nvL OUTPUT'` gives per-rule drop counters.
- `make logs` tails gateway and wordpress.
- `make snapshot` — **do this at the end of every detonation.** It copies `artifacts/` and the
  `wordpress`/`gateway` container logs into `snapshots/<timestamp>/`. The sample runs as uid 33
  and the artifact directories have to be writable by uid 33 for PHP to write into them at all,
  so a sample that wants to cover its tracks can `unlink()` traces it has already produced.
  Snapshotting is what makes that a nuisance rather than a loss.

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
did not re-run, the container exits with a message instead of detonating the sample unguarded.

WordPress makes loopback requests to its own site URL (`http://127.0.0.1:8088`) from inside the
container — wp-cron above all. nginx listens on both 8080 and 8088 so these succeed and scheduled
tasks actually fire; you will see them in traces and in `artifacts/php/nginx-access.log`.

## Artifact growth, snapshots and reset

Three artifacts grow without bound during a long detonation and are worth watching:

- `artifacts/pcap/` — capped by rotation at 20 slices of 100 MB (2 GB) per `netcap` start; the
  oldest slice is overwritten, so a very chatty sample eventually loses its earliest packets.
- `artifacts/mitm/flows.mitm` — **not** capped. Every decrypted request and response body is
  appended. A sample downloading large payloads in a loop will fill your disk.
- `artifacts/xdebug/` — one trace file per HTTP request, and traces of a busy request are large
  (`collect_assignments=1`, values up to 64 KB each). Expect roughly 100 MB per WordPress page view. Not capped either.

```bash
make snapshot     # copy artifacts/ + wordpress and gateway logs into snapshots/<timestamp>/
make reset        # down -v: wipes WordPress, database, the mitmproxy CA, and everything in artifacts/
```

`make snapshot` before `make reset`, always: `reset` is unrecoverable. It removes only this
project's own volumes and the contents of `artifacts/`; nothing outside the sandbox is touched.
`snapshots/` is gitignored.

## How containment works

- `wordpress` runs as uid 33 with every capability dropped, a read-only root, and no ability to change routes or firewall rules.
- Its network namespace is owned by `wpnet`, which sits on an `internal` Docker network (no route out) plus a management bridge that exists only to publish `127.0.0.1:8088`. `netguard` sets the default route to the gateway and installs an iptables policy inside that namespace whose outbound rules are destination-specific: the gateway (172.30.0.2) and the database (172.30.0.3) are allowed, the rest of 172.30.0.0/24 is dropped — **including 172.30.0.1, the Docker host's own address on that bridge** — and everything beyond the subnet goes out the default route into the gateway.
- The gateway redirects TCP 80/443 into mitmproxy and port 53 into dnsmasq. Its `INPUT` and `FORWARD` policies are DROP, so anything else the sample sends is captured and discarded.
- The gateway also refuses to *fetch* private destinations. The sample never connects anywhere itself: it names a host and mitmproxy does the connecting, so without this the proxy would happily retrieve `http://192.168.1.1/`, `http://169.254.169.254/`, or `http://host.docker.internal/` on its behalf. The gateway `REJECT`s egress to `10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 0.0.0.0/8 127.0.0.0/8`; override with `GATEWAY_BLOCKED_DESTS` in `.env`. Public internet egress is unaffected.
- Packet capture runs in `netcap`, inside the sandbox's network namespace — the only place that sees sandbox→database and sandbox→host traffic. It shares only the network namespace with `wordpress`, so the sample can neither see nor kill the tcpdumps.
- The observation layer has no in-process off switch. `xdebug_stop_trace`, `xdebug_start_trace`, `xdebug_set_filter`, `xdebug_get_tracefile_name` and `xdebug_get_function_stack` are in `disable_functions`, and Snuffleupagus pins `error_log` read-only, so `ini_set('error_log', '/dev/null')` fails. Nothing a sample needs for its own behaviour is disabled.
- TLS is decrypted because the sample's PHP trusts only the mitmproxy CA. Only the certificate is mounted into the container, not the whole mitmproxy config volume: the CA private key lives there too.
- The database's `root` account is confined to the db container's own loopback (`MARIADB_ROOT_HOST=localhost`), so the published default root password is not usable from the sample's container.

## Caveats

- This is container isolation, not a VM. Run it on a machine you can afford to rebuild, never one holding production credentials.
- HTTP(S) C2 traffic is real: the attacker sees your egress IP. Use a VPN or burner network if attribution matters.
- Certificate-pinned samples will fail the TLS handshake; mitmproxy logs the SNI. To pass a host through undecrypted, set `MITM_EXTRA_ARGS=--ignore-hosts 'host\.example:443'` in `.env`.
- No IPv6 rules exist on the gateway: IPv6 is disabled in the WordPress namespace and the Compose networks have no IPv6 subnets. If you enable IPv6 on these networks, the containment must be revisited.
- Treat `artifacts/` as hostile: decrypted flows and dumps can contain second-stage payloads. Read them with `cat -v` / `grep -a ... | cat -v` rather than letting raw sample bytes hit your terminal.
- **Use a throwaway browser profile** for http://127.0.0.1:8088 and http://127.0.0.1:8081. You are pointing a browser at attacker-controlled HTML with a real session; a profile holding your normal cookies, extensions and saved passwords is exposed to whatever the sample serves, and mitmweb renders sample-controlled request and response bodies too.
- **The sample can delete artifacts that were already written.** It runs as uid 33 and the artifact directories must be writable by uid 33 for the observation layer to work at all, so anti-forensic `unlink()` is available to it. It cannot stop the recording — `netcap`, mitmproxy and dnsmasq write from containers it has no access to, and the PHP-side off switches are disabled — but it can destroy what is on disk. `make snapshot` after each detonation is the mitigation.
