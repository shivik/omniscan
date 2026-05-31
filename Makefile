.PHONY: setup run bootstrap dev api dashboard worker cli migrate fmt lint test test-adapters check

# One-command install & setup (Python + dashboard + scanner images).
setup:
	./scripts/install.sh

# Run the full stack: API (:8000) + dashboard (:5173).
run:
	./scripts/dev.sh

bootstrap:
	uv sync --extra dev

api:
	uv run uvicorn api.main:app --reload

dashboard:
	cd dashboard && npm run dev

dev: run

worker:
	@echo "dev uses the in-process job backend (no separate worker). Prod: arq worker."

cli:
	uv run omniscan $(ARGS)

migrate:
	uv run alembic upgrade head

migration:
	uv run alembic revision --autogenerate -m "$(m)"

fmt:
	uv run ruff format .

lint:
	uv run ruff check .
	uv run mypy core api engine adapters normalize cli

test:
	uv run pytest -q

test-adapters:
	uv run pytest -q tests/adapters

check: lint test
