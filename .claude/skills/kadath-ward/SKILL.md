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
| Prove it works | `make selftest` | 15 assertions across all layers; **the gate before any real sample** |
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
- `netguard` pins the sandbox's only route out through the gateway and drops everything else, including the Docker host at 172.30.0.1.
- `gateway` redirects 80/443 into mitmproxy and 53 into dnsmasq, REJECTs a private-range blocklist, and drops the rest.

**Never, to make a sample run or a test pass:** add `cap_add`, publish a port on `0.0.0.0`, edit `netguard`/`gateway` iptables rules, loosen a container's `read_only`/`cap_drop`/`user`, or comment out a self-test assertion. Those are the boundary. If a self-test assertion fails, it is reporting a real regression in the boundary — fix the cause, do not silence the check.

The one legitimate way to let a sample reach a private lab target: the documented `GATEWAY_BLOCKED_DESTS` override in `.env`, scoped as narrowly as possible (a single `/32`), which keeps the traffic going through mitmproxy so it is still decrypted and captured. That is a configuration knob, not a hole.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `make up` fails, port 8088 in use | another process owns `127.0.0.1:8088` | `lsof -nP -iTCP:8088 -sTCP:LISTEN`; stop it, or change the published port in `docker-compose.yml` (host side only) |
| wordpress unhealthy, log says CA not readable | gateway not up, or CA volume empty | ensure gateway healthy first; `make reset` regenerates the CA if the volume is stale |
| wordpress exits: "default route not via 172.30.0.2" | `netguard` did not run in this namespace | `docker compose up -d --force-recreate wpnet netguard wordpress` so netguard re-runs, or just `make up` |
| self-test: TLS/`https` assertion fails | PHP does not trust the mitmproxy CA | check `openssl.cafile` points at `/gateway-ca/...`; `make reset` if the CA rotated |
| self-test: `irc`/drop assertion "connected" not "blocked" | netguard or gateway policy not applied | `docker compose logs netguard`; confirm it exited 0; re-`make up` |
| artifacts empty / permission denied on Linux | bind mounts owned by the wrong uid | `chown -R 33:33 artifacts/` on a native Linux host (not needed on OrbStack) |
| `dropped.log` missing a blocked connection | capture taps after the firewall; netns-dropped packets never reach the device | expected — see it in the Xdebug trace and `docker compose run --rm --no-deps --entrypoint sh netguard -c 'iptables -nvL OUTPUT'` counters |
| traces are enormous | a page view records ~100 MB | normal; use `grep`/`awk`, never load a whole trace; `make reset` between runs to reclaim disk |

## Between samples

The `bin/kadath offer` engine bundles each run's evidence (traces gzipped) into `reports/<slug>-<ts>/artifacts/` and clears the prior run's traces on the next offer, so `artifacts/` stays at roughly one run and per-run bundles are ~tens of MB, not tens of GB. For a hand-staged run, `make snapshot` (now compressed). `make reset` still wipes everything for a guaranteed clean slate. **Never blanket-delete files under `artifacts/` (e.g. `find artifacts -delete`) while the stack is up** — `dns.log`, `dropped.log`, `flows.mitm` and the pcap are held open by the gateway and netcap containers, and unlinking them stops network capture until those containers restart. Clear via `make reset`, or restart `gateway`/`netcap` after any such deletion.
