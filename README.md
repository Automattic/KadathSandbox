# KadathSandbox

An isolated WordPress sandbox for detonating untrusted PHP: plugins, themes, webshells, droppers.
Everything the sample does is recorded; nothing it does can leave except through a decrypting proxy.

## What you get

| Layer | Tool | Output |
|---|---|---|
| Every PHP function call, with arguments, return values and eval'd code | Xdebug 3.5 trace mode | `artifacts/xdebug/trace.<time>.<req>.xt` (one per request) |
| Dangerous PHP calls (`system`, `exec`, `curl_exec`, `unserialize`, `base64_decode`, remote `include`, ...) | Snuffleupagus 0.14 in simulation mode | `artifacts/php/php-error.log` (every call, with arguments), `artifacts/sp-dumps/` (one `sp_dump.<sha256>` file per matching rule, not per call) |
| Decrypted HTTP and HTTPS | mitmproxy 12 transparent mode | `artifacts/mitm/flows.mitm`, UI at http://127.0.0.1:8081 |
| DNS lookups | dnsmasq on the gateway | `artifacts/dns/dns.log` |
| Every packet from the sandbox | tcpdump on the gateway | `artifacts/pcap/sandbox-<ts>.pcap` |
| Non-HTTP/DNS attempts (IRC, raw C2, SMTP...) | tcpdump filter; dropped by iptables | `artifacts/dropped.log` |
| Syscalls, file I/O, process spawns | strace, bpftrace sidecar | `artifacts/strace/`, terminal |

`artifacts/sp-dumps/` will already be non-empty right after `make up` finishes installing WordPress:
WP-CLI itself trips the `base64_decode` rule during install, and Snuffleupagus writes one dump per
rule that matches, not one per call. For per-call detail (every hooked call with every argument),
read `artifacts/php/php-error.log` instead.

## Requirements

- Docker with Compose v2 or later. Developed on macOS (Apple Silicon) with OrbStack; works on Linux Docker hosts.
- About 2 GB of disk for images, plus whatever traces the samples produce.

## Deploy

```bash
cp .env.example .env          # edit passwords if you like; defaults are fine for a local sandbox
make up                        # builds images, starts db, gateway, wpnet, netguard, wordpress
make selftest                  # proves every layer works. Do this before loading real malware.
```

Then:
- WordPress: http://127.0.0.1:8088 (admin login from `.env`, default `admin` / `sandbox`)
- mitmweb: http://127.0.0.1:8081 (password from `.env`, default `sandbox`)

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

**Upload path (zips, to observe installer hooks):** wp-admin → Plugins → Add New → Upload, as a victim would.

## Analysing

- Trigger the sample from your browser or `curl http://127.0.0.1:8088/...`. Each request writes one Xdebug trace.
- `grep -n "eval\|base64_decode\|system" artifacts/xdebug/<latest>.xt` finds deobfuscation stages; the eval string is recorded in full.
- `artifacts/php/php-error.log` lists every hooked call with its arguments.
- Open mitmweb, or replay later with `docker compose exec gateway mitmproxy -nr /artifacts/mitm/flows.mitm`.
- `artifacts/dropped.log` shows what the sample tried that was not HTTP/DNS.
- `make logs` tails gateway and wordpress.

## OS-level monitoring (strace, eBPF)

The tracer shares the PHP-FPM PID namespace and runs privileged. It is behind a Compose profile, so it only exists when you ask for it.

```bash
make trace                                  # shell in the tracer
/opt/tracer/strace-fpm.sh                   # strace -f on all php-fpm processes -> artifacts/strace/
bpftrace /opt/tracer/phpfpm.bt              # live openat / connect / execve / unlink from php-fpm
strace -f -e trace=network -p $(pgrep -d, -x php-fpm)
```

Filter bpftrace by `comm == "php-fpm"`, not by PID: bpftrace reports PIDs from the initial namespace.

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

`wordpress` and `netguard` live inside `wpnet`'s network namespace. If `wpnet` is ever recreated, recreate them too, or just run `make up`, which handles ordering. Recreating only `wordpress` (as the sample-loading step does) is always safe.

WordPress makes loopback requests to its own site URL from inside the container (wp-cron). These fail
harmlessly and show up as `connect 127.0.0.1:8088` in traces; ignore them.

## Reset

```bash
make reset        # down -v: wipes WordPress, database, the mitmproxy CA, and everything in artifacts/
```

## How containment works

- `wordpress` runs as uid 33 with every capability dropped, a read-only root, and no ability to change routes or firewall rules.
- Its network namespace is owned by `wpnet`, which sits on an `internal` Docker network (no route out) plus a management bridge that exists only to publish `127.0.0.1:8088`. `netguard` sets the default route to the gateway and installs an iptables policy that drops any new outbound connection not going to the internal network.
- The gateway redirects TCP 80/443 into mitmproxy and port 53 into dnsmasq. Its `INPUT` and `FORWARD` policies are DROP, so anything else the sample sends is captured and discarded.
- TLS is decrypted because the sample's PHP trusts only the mitmproxy CA, which is generated once into a volume and mounted read-only.

## Caveats

- This is container isolation, not a VM. Run it on a machine you can afford to rebuild, never one holding production credentials.
- HTTP(S) C2 traffic is real: the attacker sees your egress IP. Use a VPN or burner network if attribution matters.
- Certificate-pinned samples will fail the TLS handshake; mitmproxy logs the SNI. To pass a host through undecrypted, set `MITM_EXTRA_ARGS=--ignore-hosts 'host\.example:443'` in `.env`.
- No IPv6 rules exist on the gateway: IPv6 is disabled in the WordPress namespace and the Compose networks have no IPv6 subnets. If you enable IPv6 on these networks, the containment must be revisited.
- Treat `artifacts/` as hostile: decrypted flows and dumps can contain second-stage payloads.
