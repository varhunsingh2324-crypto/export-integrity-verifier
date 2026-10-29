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

faults: $(STAMP)                # F2, F3 so far (F1, F4-F7 with phases 3, 4, 7)
	$(PY) -m sim.faults

bench: $(STAMP)                 # L1 streaming memory/throughput so far (full bench: phase 8)
	$(PY) bench/l1_memory.py

# Stubs: fail loudly until their phase lands, so a stub never looks like success.
verify-all:
	@echo "make $@: not implemented yet (phase 6)" >&2; exit 1
dashboard demo:
	@echo "make $@: not implemented yet (phase 8)" >&2; exit 1
