# bash, not /bin/sh: the snapshot recipe uses `read -d ''` to survive newlines in filenames.
SHELL := /bin/bash

.PHONY: up down reset selftest snapshot logs trace shell build offer web pilgrimage pilgrimage-smoke

# --wait-timeout: wordpress has restart: unless-stopped, so an entrypoint FATAL (route guard,
# CA, DB) restart-loops instead of exiting; without a bound, --wait would hang on it.
up:
	docker compose up -d --build --wait --wait-timeout 300 db gateway wpnet netcap wordpress

down:
	docker compose --profile trace down --remove-orphans

reset:
	docker compose --profile trace down -v --remove-orphans
	find artifacts -type f ! -name .gitkeep -delete
	find artifacts -mindepth 2 -type d -empty -delete

build:
	docker compose --profile trace build

selftest:
	bash tests/selftest.sh

# End-of-offering step. The sample runs as uid 33 and the artifact dirs are bind
# mounts owned by the same uid, so a sample that wants to cover its tracks can delete
# what has already been written. Snapshotting off the live tree after every offering
# is what makes that a nuisance instead of a loss.
snapshot:
	@set -e; ts=$$(date +%Y%m%d-%H%M%S); dir=snapshots/$$ts; \
	  mkdir -p "$$dir/artifacts"; \
	  ( cd artifacts && find . -type f ! -name .gitkeep -print0 | while IFS= read -r -d '' f; do \
	      mkdir -p -- "../$$dir/artifacts/$$(dirname -- "$$f")" || exit 1; \
	      case "$$f" in \
	        *.xt|*.log|*.mitm) gzip -c -- "$$f" > "../$$dir/artifacts/$$f.gz" || exit 1 ;; \
	        *) cp -a -- "$$f" "../$$dir/artifacts/$$f" || exit 1 ;; \
	      esac; \
	    done ); \
	  docker compose logs --no-color wordpress gateway > "$$dir/compose-logs.txt" 2>&1 || true; \
	  echo "snapshot: $$dir ($$(du -sh "$$dir" | cut -f1)) — traces/logs gzipped"

logs:
	docker compose logs -f gateway wordpress

# Opens a shell in the tracer sidecar. Sample-controlled bytes (paths, argv, buffers)
# reach your terminal through strace/bpftrace output, so pipe it through `cat -v`:
#   bpftrace /opt/tracer/phpfpm.bt | cat -v
trace:
	@echo "tracer: pipe live output through 'cat -v' -- sample-controlled bytes reach your terminal raw otherwise."
	docker compose --profile trace run --rm tracer

shell:
	docker compose exec wordpress bash

# Offer a sample end to end. SAMPLE is required; RECIPE and RESET optional.
#   make offer SAMPLE=path/to/sample.php
offer:
	@test -n "$(SAMPLE)" || { echo "usage: make offer SAMPLE=<path> [RECIPE=<path>] [RESET=1]"; exit 2; }
	python3 bin/kadath offer "$(SAMPLE)" \
	  $(if $(RECIPE),--recipe "$(RECIPE)") \
	  $(if $(RESET),--reset)

# Start the localhost web UI at http://127.0.0.1:8090
web:
	python3 bin/kadath web $(if $(PORT),--port $(PORT))

# The Pilgrimage: triage a threat-library for-later-review directory with a local
# Ollama model. LIBRARY is required. PASS defaults to all (cavern -> offer -> scry).
#   make pilgrimage LIBRARY=~/WORK/jetpack-threat-library/for-later-review PASS=cavern LIMIT=50
pilgrimage:
	@test -n "$(LIBRARY)" || { echo "usage: make pilgrimage LIBRARY=<for-later-review dir> [PASS=cavern|offer|scry|all] [LIMIT=N]"; exit 2; }
	python3 bin/kadath pilgrimage "$(LIBRARY)" --pass $(or $(PASS),all) $(if $(LIMIT),--limit $(LIMIT))

# Three hand-picked cases against the real model and the real stack: the
# pre-flight before a week-long pilgrimage. CASES is a space-separated list.
pilgrimage-smoke:
	@test -n "$(LIBRARY)" && test -n "$(CASES)" || { echo "usage: make pilgrimage-smoke LIBRARY=<dir> CASES='ID1 ID2 ID3'"; exit 2; }
	python3 bin/kadath pilgrimage "$(LIBRARY)" --pass all --limit 3 $(foreach c,$(CASES),--case $(c))
