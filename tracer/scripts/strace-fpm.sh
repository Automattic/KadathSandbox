#!/usr/bin/env bash
# Attach strace to every php-fpm process (master + workers, following forks).
#
# Output goes to a file, not your terminal: strace prints paths, argv and buffer
# contents chosen by the sample, and raw ANSI escapes in those would be interpreted by
# your terminal. Read the log with `cat -v` (or `grep -a ... | cat -v`), and if you
# watch live output from any tracer, pipe it: `bpftrace /opt/tracer/phpfpm.bt | cat -v`.
set -euo pipefail
pids="$(pgrep -d, -x php-fpm || true)"
if [ -z "$pids" ]; then echo "no php-fpm processes visible; is wordpress running?" >&2; exit 1; fi
out="/artifacts/strace/fpm-$(date +%Y%m%d-%H%M%S).log"
echo "strace -> $out (pids: $pids). Ctrl-C to stop."
echo "read it with: cat -v $out   # sample-controlled bytes, do not cat it raw"
exec strace -f -tt -s 256 -e trace=file,network,process -p "$pids" -o "$out"
