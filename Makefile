.PHONY: up down reset selftest logs trace shell build

up:
	docker compose up -d --build --wait db gateway wpnet wordpress

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

logs:
	docker compose logs -f gateway wordpress

trace:
	docker compose --profile trace run --rm tracer

shell:
	docker compose exec wordpress bash
