#!/usr/bin/env bash
# Attach strace to every php-fpm process (master + workers, following forks).
set -euo pipefail
pids="$(pgrep -d, -x php-fpm || true)"
if [ -z "$pids" ]; then echo "no php-fpm processes visible; is wordpress running?" >&2; exit 1; fi
out="/artifacts/strace/fpm-$(date +%Y%m%d-%H%M%S).log"
echo "strace -> $out (pids: $pids). Ctrl-C to stop."
exec strace -f -tt -s 256 -e trace=file,network,process -p "$pids" -o "$out"
