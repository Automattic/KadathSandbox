.PHONY: up down reset selftest snapshot logs trace shell build detonate web

up:
	docker compose up -d --build --wait db gateway wpnet netcap wordpress

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

# End-of-detonation step. The sample runs as uid 33 and the artifact dirs are bind
# mounts owned by the same uid, so a sample that wants to cover its tracks can delete
# what has already been written. Snapshotting off the live tree after every detonation
# is what makes that a nuisance instead of a loss.
snapshot:
	@ts=$$(date +%Y%m%d-%H%M%S); dir=snapshots/$$ts; \
	  mkdir -p "$$dir"; \
	  cp -a artifacts "$$dir/artifacts"; \
	  docker compose logs --no-color wordpress gateway > "$$dir/compose-logs.txt" 2>&1 || true; \
	  echo "snapshot: $$dir ($$(du -sh "$$dir" | cut -f1))"

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

# Detonate a sample end to end. SAMPLE is required; RECIPE and RESET optional.
#   make detonate SAMPLE=path/to/sample.php
detonate:
	@test -n "$(SAMPLE)" || { echo "usage: make detonate SAMPLE=<path> [RECIPE=<path>] [RESET=1]"; exit 2; }
	python3 bin/kadath detonate "$(SAMPLE)" \
	  $(if $(RECIPE),--recipe "$(RECIPE)") \
	  $(if $(RESET),--reset)

# Start the localhost web UI at http://127.0.0.1:8090
web:
	python3 bin/kadath web $(if $(PORT),--port $(PORT))
