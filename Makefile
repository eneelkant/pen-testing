.PHONY: help install doctor smoke test lint compose-build compose-doctor clean

PYTHON ?= python3
export PYTHONPATH := $(CURDIR)$(if $(PYTHONPATH),:$(PYTHONPATH),)

help:
	@echo "Targets:"
	@echo "  install         Install orchestrator package (editable) with dev deps"
	@echo "  doctor          Environment diagnostics"
	@echo "  smoke           Safe local smoke tests (no external attacks)"
	@echo "  test            Run unit tests"
	@echo "  compose-build   Build docker compose images (requires Docker)"
	@echo "  compose-doctor  Run doctor inside orchestrator container"
	@echo "  clean           Remove local caches and generated reports"

install:
	$(PYTHON) -m pip install -e ".[dev]"

doctor:
	$(PYTHON) -m core.cli doctor

smoke:
	bash scripts/smoke.sh

test:
	$(PYTHON) -m pytest -q tests/unit

lint:
	$(PYTHON) -m compileall core integrations providers
	$(PYTHON) -m pytest -q tests/unit

compose-build:
	docker compose build

compose-doctor:
	docker compose run --rm orchestrator

clean:
	rm -rf .pytest_cache .coverage htmlcov dist build *.egg-info
	rm -rf reports/out/*
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
