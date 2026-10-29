# ExportGuard developer commands. See README.md.
-include .env
export

VENV   := .venv
PY     := $(VENV)/bin/python
STAMP  := $(VENV)/.installed

.PHONY: up down test lint doctor seed incident faults verify-all bench dashboard demo

$(STAMP): pyproject.toml
	python3 -m venv $(VENV)
	$(PY) -m pip install -q --upgrade pip
	$(PY) -m pip install -q -e '.[dev]'
	touch $(STAMP)

up:
	docker compose up -d --wait

down:
	docker compose down

test: $(STAMP)
	$(PY) -m pytest -q

lint: $(STAMP)
	$(VENV)/bin/ruff check .
	$(VENV)/bin/ruff format --check .

doctor: $(STAMP)
	$(VENV)/bin/eguard doctor

seed: $(STAMP)
	$(PY) -m sim.incident seed

incident: $(STAMP)
	$(PY) -m sim.incident run

# Stubs: fail loudly until their phase lands, so a stub never looks like success.
faults:
	@echo "make $@: not implemented yet (phases 1-4)" >&2; exit 1
verify-all:
	@echo "make $@: not implemented yet (phase 6)" >&2; exit 1
dashboard bench demo:
	@echo "make $@: not implemented yet (phase 8)" >&2; exit 1
