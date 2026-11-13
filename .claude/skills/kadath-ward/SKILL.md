---
name: kadath-ward
description: Use when operating, starting, resetting, snapshotting, self-testing, or troubleshooting the KadathSandbox WordPress malware sandbox at /Users/fioa8c/WORK/KadathSandbox — bringing the stack up, fixing a failing self-test or a container that will not come healthy, and understanding the containment model so you never weaken it to make a sample run.
user-invocable: true
---

# Operate KadathSandbox

Run the stack, keep it trustworthy, and never trade containment for convenience.

## Everyday commands

| Goal | Command | Notes |
|---|---|---|
| Build and start | `make up` | builds, starts db/gateway/wpnet/netcap/wordpress, waits for health |
| Prove it works | `make selftest` | 26 assertions across all layers (including pinned ini keys, an ignored `.user.ini`, a dropped direct connection to the proxy port, `wp_remote_get` over https being decrypted, firewall counters that rise on blocked traffic, broadcast/multicast drops, IPv6 off and `ip_forward=0`), plus two informational `INFO:` lines (child interpreter, `error_reporting(0)`) that are not counted; **the gate before any real sample** |
| Save a run | `make snapshot` | copies `artifacts/` (traces/logs gzipped) + container logs to `snapshots/<ts>/` |
| Wipe everything | `make reset` | `down -v` + clears `artifacts/`; rebuilds WordPress, DB, and the mitmproxy CA from scratch (minutes) |
| Tail logs | `make logs` | gateway + wordpress |
| Shell in WordPress | `make shell` | uid 33, read-only rootfs |
| Stop | `make down` | keeps volumes |

WordPress is `http://127.0.0.1:8088` (admin/sandbox), mitmweb `http://127.0.0.1:8081` (sandbox). Defaults live in `.env.example`; copy to `.env` to change them.

## The self-test is the gate

`make selftest` is not optional ceremony. It proves, from outside, that tracing writes, TLS is intercepted, DNS is logged, raw egress is dropped and captured, and the WordPress namespace has exactly one route out via the gateway. **A "clean" offering on a stack whose self-test has not passed proves nothing** — the recording or the containment could be silently broken. If the self-test is red, fix the stack before you trust any result.

## Containment model — what you must never weaken

Three independent layers keep the sample off your machine and the internet-at-large. Read `docs/superpowers/specs/2026-09-03-wp-malware-sandbox-design.md` for the full model; the operating rule is short:

- `wordpress` runs as uid 33, read-only rootfs, `cap_drop: [ALL]`, `no-new-privileges`.
- The observation ini keys (`error_log`, the `xdebug.*` trace settings, `auto_prepend_file`/`auto_append_file`) are pinned with `php_admin_value` in `zz-sandbox.conf`, and `user_ini.filename=` is empty, so a sample cannot change them with `ini_set()` or a `.user.ini`.
- `netguard` installs its rules first and the default route (via the gateway) last, forwards only unicast (broadcast/multicast/anycast are dropped), drops everything else including the Docker host at 172.30.0.1, and sets an `ip6tables` DROP policy as a backstop to the IPv6-off sysctls.
- `gateway` runs with `ip_forward=0`, `cap_drop: [ALL]` plus `NET_ADMIN`/`NET_BIND_SERVICE`/`SETUID`/`SETGID`, `no-new-privileges`, a memory limit, and only the `artifacts/mitm` and `artifacts/dns` mounts. It redirects 80/443 into mitmproxy (bodies over 1 MiB are streamed, not stored: `stream_large_bodies=1m`) and 53 into dnsmasq, REJECTs a private-range blocklist, and drops the rest.
- `netcap` has `cap_drop: [ALL]` and only `NET_RAW`.
- Every service's Docker log is capped (50 MB x 3); the `wordpress` healthcheck is php-fpm's own `/fpm-ping` (body `pong`), the pool kills requests after 120 s wall-clock (`request_terminate_timeout`), and supervisord keeps restarting php-fpm. Its proxy port 8080 accepts only REDIRECTed connections (`--ctstate DNAT`) and rejects its own loopback connections to it: a direct, un-NATed connect makes mitmproxy connect to itself in a loop, a denial of service against observation.

**Known limit (do not "fix" by widening anything):** the pool pins and Xdebug cover php-fpm only. A child interpreter the sample starts (`exec('php -n x.php')`, `XDEBUG_MODE=off php ...`, or the `wp` wrapper) is untraced; the evidence for it is the Snuffleupagus `exec`/`system` line with argv, the pcap and flows, and `kadath-gaunt` (strace).

**Never, to make a sample run or a test pass:** add `cap_add`, publish a port on `0.0.0.0`, edit `netguard`/`gateway` iptables rules, loosen a container's `read_only`/`cap_drop`/`user`, or comment out a self-test assertion. Those are the boundary. If a self-test assertion fails, it is reporting a real regression in the boundary — fix the cause, do not silence the check.

The one legitimate way to let a sample reach a private lab target: the documented `GATEWAY_BLOCKED_DESTS` override in `.env`, scoped as narrowly as possible (a single `/32`), which keeps the traffic going through mitmproxy so it is still decrypted and captured. That is a configuration knob, not a hole.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `make up` fails, port 8088 in use | another process owns `127.0.0.1:8088` | `lsof -nP -iTCP:8088 -sTCP:LISTEN`; stop it, or change the published port in `docker-compose.yml` (host side only) |
| wordpress unhealthy, log says CA not readable | gateway not up, or CA volume empty | ensure gateway healthy first; `make reset` regenerates the CA if the volume is stale |
| wordpress never healthy and `make up` times out; `docker compose logs wordpress` repeats FATAL "default route not via 172.30.0.2" (the container restart-loops rather than exiting, by design) | `netguard` did not run in this namespace | `docker compose up -d --force-recreate wpnet netguard wordpress` so netguard re-runs, or just `make up` |
| self-test: TLS/`https` assertion fails | PHP does not trust the mitmproxy CA | check `openssl.cafile` points at `/gateway-ca/...`; `make reset` if the CA rotated |
| wordpress `unhealthy` while nginx still serves `/healthz`; `docker compose logs wordpress` shows nothing wrong | php-fpm is down or its socket was unlinked/hijacked by the sample (the healthcheck is `/fpm-ping`, which needs a live FPM answering `pong`) | supervisord restarts php-fpm by itself; if the socket was hijacked, `docker compose up -d --force-recreate wordpress` (safe: the namespace belongs to `wpnet`) |
| self-test: `dot`/drop assertion (1.1.1.1:853) "connected" not "blocked" | netguard or gateway policy not applied | `docker compose logs netguard`; confirm it exited 0; re-`make up` |
| self-test: `wp_remote_get` assertion fails | WordPress's own TLS bundle lacks the mitmproxy CA (it ignores `openssl.cafile`) | the entrypoint appends the CA to `wp-includes/certificates/ca-bundle.crt`; `docker compose up -d --force-recreate wordpress`, or `make reset` if the CA rotated |
| image build fails fetching Xdebug | Xdebug is built from the GitHub tag archive (`github.com/xdebug/xdebug/archive/refs/tags/<v>.tar.gz`) and checked against the `XDEBUG_SHA256` build arg; pecl.php.net and xdebug.org were unreachable from the Docker build network on one host | if you bump `XDEBUG_VERSION`, update `XDEBUG_SHA256` to match; a mismatch is a refusal, not something to bypass |
| artifacts empty / permission denied on Linux | bind mounts owned by the wrong uid | `chown -R 33:33 artifacts/` on a native Linux host (not needed on OrbStack) |
| `dropped.log` missing a blocked connection | capture taps after the firewall; netns-dropped packets never reach the device | expected — see it in the Xdebug trace and `docker compose run --rm --no-deps --entrypoint sh netguard -c 'iptables -nvL OUTPUT'` counters |
| a previous sample's options/posts reappear, or a green looks dirty | DB baseline stale or recorded from an already-dirty DB | `bin/kadath offer --reset <sample>` re-records `.kadath/db-baseline.json` from a fresh install |
| traces are enormous | a page view records ~100 MB | normal; use `grep`/`awk`, never load a whole trace; `make reset` between runs to reclaim disk |

## Between samples

The `bin/kadath offer` engine bundles each run's evidence (traces gzipped) into `reports/<slug>-<ts>/artifacts/` and clears the prior run's traces on the next offer, so `artifacts/` stays at roughly one run and per-run bundles are ~tens of MB, not tens of GB. The bundle holds only this run's slice of the append-only logs and live pcap. The engine also restores the WordPress docroot to the image's pristine tree between offerings, and puts the database residue back from a baseline in `.kadath/db-baseline.json` (options, cron events, posts and postmeta, extra users and dead `active_plugins` entries are removed if they are not in it). Not undone: changed values of stock options, custom tables and admin usermeta, so use `bin/kadath offer --reset` (or `make reset`) for a true clean slate. A hand-run `make reset` makes the baseline stale; the engine notices and re-records it. For a hand-staged run, `make snapshot` (now compressed). `make reset` still wipes everything for a guaranteed clean slate. **Never blanket-delete files under `artifacts/` (e.g. `find artifacts -delete`) while the stack is up** — `dns.log`, `dropped.log`, `flows.mitm` and the pcap are held open by the gateway and netcap containers, and unlinking them stops network capture until those containers restart. Clear via `make reset`, or restart `gateway`/`netcap` after any such deletion.
