# Contributing to ExportGuard

Read [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) before any non-trivial change: it is the
source of truth for architecture, algorithms and acceptance criteria. Code and comments refer to
the rules below by number ("rule 9").

## Setup

```bash
cp .env.example .env   # PG_DSN, SCRATCH_DSN, MANIFEST_HMAC_KEY (e.g. `openssl rand -hex 32`)
make up                # PostgreSQL 16 in Docker
make test              # creates .venv on first run; database tests need `make up`
make lint              # ruff check + ruff format --check
```

Run `pg_dump`/`psql` inside the container (`docker compose exec -T db ...`) to avoid a
client/server version mismatch; pipe the output to host-side `gzip`/`pigz`/`compress`.

## Engineering rules

1. **Streaming only.** Never write a decompressed dump to disk and never load a whole file into
   memory. One decompression pass fans out to all consumers.
2. **Bounded memory.** Use sketches (HyperLogLog, reservoir, Bloom filter) for anything that scales
   with rows.
3. **Every check returns evidence** (`CheckResult` with an `evidence` dict and a human `message`),
   never a bare bool.
4. **Thresholds live in `config/policy.yaml`.** Never change a threshold, expected verdict or fault
   definition just to make a test pass. If a test fails, fix the code, or explain why the test is
   wrong in the pull request.
5. **No fabricated numbers.** Benchmarks, sizes and percentages in docs, README and slides must come
   from an actual run (`bench/results.md`, `data/reports/*.json`). If a number is not measured yet,
   write `TBD`.
6. **Scratch restore is tiny and always cleaned up** (`try/finally` drop of the scratch schema).
7. **Exit codes:** 0 VERIFIED, 1 SUSPECT, 2 CORRUPT, 3 tool error.
8. Bash scripts start with `set -euo pipefail` and check `PIPESTATUS`, except
   `scripts/legacy_export.sh`, which deliberately reproduces the naive pipeline (keep the comment
   explaining why).
9. **No demo special-casing.** Detection logic never looks at file names, fault IDs (F1–F7), row
   counts or paths to decide a verdict. Every verdict comes from the file's bytes, the manifest and
   the database only. A test renames every fault file to random names and must get identical
   verdicts.
10. **Disk budget: the whole project stays under ~1.5 GB** (check with `make disk`; `.venv` alone
    is ~764 MB).
    - The full dataset is 300,000 rows (`config/sim.yaml` `base_rows`).
    - Fault files are always built from the 50,000-row variant (`faults.source_rows`), never from
      the full dataset.
    - Benchmarks never keep large datasets: for each scale, generate, measure and delete before the
      next. Only the numbers are kept, in `bench/results.md`.
    - Everything in `data/` must be regenerable and listed in `DATA_GENERATED` for
      `make clean-data`.

## Code style

- Python: type hints everywhere, `pydantic` models in `models.py`, `ruff` + `ruff format`,
  functions under ~50 lines.
- CLI: Typer + Rich; human output by default, `--json` for machine output.
- Tests: pytest; fixtures small and hand-crafted; `tests/test_fault_matrix.py` is the end-to-end
  truth table.
- Keep `README.md` accurate when behaviour changes.
- Discuss a new dependency before adding it to `pyproject.toml`.

## Before a pull request

- `make test` and `make lint` pass.
- For a change that touches detection, `make verify-all` still matches the fault matrix in
  `IMPLEMENTATION_PLAN.md` §6.
- Any number you add to the docs comes from a run you can point to (rule 5).
