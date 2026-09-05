---
name: kadath-gaunt
description: Use when you need OS-level evidence — syscalls, spawned processes with argv, file opens, raw connect() calls — from a WordPress sample running in KadathSandbox at /Users/fioa8c/WORK/KadathSandbox, rather than PHP-level Xdebug traces. Covers attaching strace and bpftrace to php-fpm via the tracer sidecar during a trigger.
user-invocable: true
---

# OS-level tracing in KadathSandbox

When the PHP trace is not enough — you want the actual `execve` of a spawned shell with its argv, every file php-fpm opens, or a raw `connect()` the sample makes below the PHP layer — attach the tracer sidecar to php-fpm while you trigger the sample.

The tracer is a privileged container sharing php-fpm's PID namespace, behind a Compose profile so it only exists when asked. It is built by `make up`/`make build` like the rest.

**Sample-controlled bytes reach your terminal raw.** Filenames, argv, and buffers that the malware controls appear in strace/bpftrace output. Pipe every live tracer command through `cat -v` so a crafted path cannot inject terminal escape sequences. This matters here more than anywhere else in the sandbox.

## The shape of a tracing run

Tracing must be running *before* the trigger, so it is a two-actor dance: start the tracer, then in a second shell fire the HTTP request.

1. Stage the sample and confirm the stack is healthy (see kadath-offer; `make selftest` must have passed).
2. Start the tracer in the background, writing to `artifacts/strace/` (a bind mount you can read from the host afterwards), or run it foreground in one terminal.
3. Trigger with `curl http://127.0.0.1:8088/...` from another shell.
4. Stop the tracer, read the output from `artifacts/strace/`.

Because php-fpm uses `pm=static` with a few persistent workers, attach to all of them.

## strace: processes, network, files

```bash
# background run, output lands in artifacts/strace/ on the host
docker compose --profile trace run --rm -d tracer bash /opt/tracer/strace-fpm.sh
# ... trigger the sample in another shell ...
# stop it and read
docker ps -q --filter label=com.docker.compose.service=tracer | xargs -r docker rm -f
grep -aE 'execve|connect|openat' artifacts/strace/fpm-*.log | cat -v | tail -40
```

`strace-fpm.sh` attaches `strace -f -tt -s 256 -e trace=file,network,process` to every php-fpm PID. Look for:
- `execve("/bin/sh", ["sh","-c","<command>"], ...)` — the sample shelling out, with the exact command.
- `connect(fd, {AF_INET, ...}, ...)` — raw sockets. In transparent mode the destination is the real IP; the gateway redirects web ports later.
- `openat(... "/var/www/html/...")` / `unlinkat(...)` — files read, written, or deleted.

## bpftrace: live, low-overhead, comm-filtered

```bash
docker compose --profile trace run --rm tracer bpftrace /opt/tracer/phpfpm.bt | cat -v
```

`phpfpm.bt` prints every `openat`, `connect` (with IPv4 dest and port), `execve`, and `unlinkat` from processes whose comm is `php-fpm`. It filters on **comm, not PID**, because bpftrace reports initial-namespace PIDs that differ from the ones `pgrep` shows inside the container. Trigger the sample in another shell while it runs; Ctrl-C to stop.

`make trace` drops you into a tracer shell with both scripts on `/opt/tracer` and prints the `cat -v` reminder.

## Correlating with the PHP layer

The OS trace tells you *that* a shell ran or a socket opened; the Xdebug trace tells you *which PHP call* did it and with what surrounding logic. Match them by wall-clock time (strace `-tt` timestamps vs the trace's `TRACE START` and per-record time index) and hand both to **kadath-scry**. A `connect()` in strace with no corresponding decrypted flow in `flows.mitm` usually means the destination was blocked by the gateway or netguard — expected, and itself an indicator.

## On a native Linux host (no sidecar)

The same tools work from the host against the container's PIDs:

```bash
cid=$(docker compose ps -q wordpress)
pid=$(docker inspect --format '{{.State.Pid}}' "$cid")
sudo strace -f -p "$(pgrep -d, -x php-fpm)" -e trace=file,network,process | cat -v
sudo bpftrace tracer/scripts/phpfpm.bt | cat -v
```
