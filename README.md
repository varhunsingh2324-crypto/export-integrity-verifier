# ExportGuard — Proving a Compressed Database Export Is Restorable *Without* Re-importing It

> **The incident:** A table export grew by **+30 % rows**, yet the compressed file **shrank by 20 %**.
> Management asked the only question that matters for a backup: *"Can we actually recover from this file?"*
> There was no time and no tablespace to re-import the table into a scratch database to find out.

**ExportGuard** answers that question in a single streaming pass over the compressed file — no import,
no tablespace, constant memory — and produces a signed, evidence-backed verdict:

| Verdict | Meaning |
|---|---|
| ✅ **VERIFIED** | Every integrity layer passed. The file is restorable and complete. |
| ⚠️ **SUSPECT** | Nothing is provably broken, but some evidence is missing (e.g. a legacy export with no manifest). |
| ❌ **CORRUPT** | At least one layer proved data loss or damage. The report says *where* and *why*. |

It also answers the second question management never asked out loud: **"Why did the file shrink?"**
ExportGuard decomposes the size change into *rows × bytes-per-row ÷ compression-ratio* and drills
down to the column(s) and the compressor settings responsible.

---

## Why `gzip -t` is not enough

The classic pipeline `export | gzip > table.dmp.gz` has a silent failure mode: if the export
process dies halfway through, `gzip` simply sees end-of-input, writes a perfectly valid trailer and
exits `0`. **`gzip -t` passes. The file is half a table.** Plain Unix `compress` (`.Z`) is worse — it
has no checksum at all, so a flipped bit can pass through unnoticed.

ExportGuard therefore checks five independent layers. Each one catches failures the others miss:

| Layer | Checks | Catches |
|---|---|---|
| **L1 Container** | gzip/`.Z` magic, header flags, CRC32, ISIZE, trailing garbage | truncation, bit-rot, wrong/changed compressor |
| **L2 Structure** | dump grammar: headers, per-table data blocks, terminators, completion marker | export killed mid-stream (*the pipe-masking failure*) |
| **L3 Row validity** | every row: field count, type parse, PK uniqueness | partial rows, encoding damage, duplicated chunks |
| **L4 Reconciliation** | row counts & content fingerprints vs. a manifest captured at export time / the source DB in the same snapshot | missing or altered rows that still "look" valid |
| **L5 Restore drill** | statistically sized random sample restored into a tiny scratch schema and compared to source | anything that only shows up on an actual restore |

The result is a **Recoverability Assurance Level (RAL 0–5)** — the number of layers that passed —
so management gets one number, and engineers get the evidence chain behind it.

## Development setup

Needs Python 3.11+, Docker, and `gzip`/`pigz`/`compress` on `PATH`.

```bash
cp .env.example .env   # PG_DSN, SCRATCH_DSN, MANIFEST_HMAC_KEY
make up                # PostgreSQL 16 in Docker; waits until healthy (port: PG_PORT, default 5432)
make test              # creates .venv on first run, then pytest
make lint              # ruff check + ruff format --check
make doctor            # eguard doctor: toolchain + database reachability
```

`make test` runs the database tests when `PG_DSN` is set and **fails** if the DB is unreachable.
They are skipped only when `PG_DSN` is unset.

## Quick start

> Implemented so far: phases 0–1 (skeleton, incident simulation). Targets from `make faults`
> onward still exit non-zero with "not implemented yet" until their phase lands.

```bash
make up            # start PostgreSQL 16 in Docker (the simulated "production" DB)
make seed          # create the large table (configurable rows)
make incident      # reproduce the incident: export v1, business change, export v2 (+30% rows, −20% size)
                   # (`python -m sim.incident run --scale 0.02` for a fast 20 000-row run)
make faults        # generate the fault-injection gallery
make verify-all    # verify every export and print the scorecard
make dashboard     # open the Streamlit dashboard
```

CLI:

```bash
eguard verify  data/exports/v2.sql.gz --manifest data/manifests/v2.json --dsn $PG_DSN
eguard explain data/exports/v1.sql.gz data/exports/v2.sql.gz      # size-anomaly forensics
eguard export  --table transactions --out data/exports/v3.sql.gz   # hardened export + manifest
```

Exit codes: `0` VERIFIED · `1` SUSPECT · `2` CORRUPT · `3` tool error — so it drops straight into cron/CI/monitoring.

### The simulated incident

`make incident` seeds `transactions` inside PostgreSQL (`generate_series`, fixed `setseed`), exports
**v1** through the deliberately naive `scripts/legacy_export.sh` (`pg_dump | gzip`, no `pipefail`),
runs a privacy purge (old rows lose `remarks` and `meta.trace`) plus +30 % low-entropy new rows, then
exports **v2** the same way. Every knob is in `config/sim.yaml`; results are written to
`data/reports/incident.json`, and the command exits 1 if the targets in `sim.yaml` are missed.

Measured at the default 1 000 000 rows (`data/reports/incident.json`):

| | rows | raw dump bytes | gzip bytes |
|---|---:|---:|---:|
| v1 | 1,000,000 | 327,100,588 | 164,938,516 |
| v2 | 1,300,000 | 287,392,155 | 131,090,638 |
| change | +30.00 % | −12.14 % | −20.52 % |

Data is reproducible run to run; gzip sizes vary by a few bytes only because pg_dump ≥ 16.10 writes a
random `\restrict` key into each dump.

## Documentation

| File | For |
|---|---|
| [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) | Architecture, algorithms, phases, acceptance criteria |
| [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) | 12-minute demo runbook, slide outline, judge Q&A |
| [`docs/ORACLE_PRODUCTION_RUNBOOK.md`](docs/ORACLE_PRODUCTION_RUNBOOK.md) | How the same method applies to Oracle `exp`/`expdp` in production |

## Tech stack

Python 3.11 · PostgreSQL 16 (Docker) · gzip / pigz / ncompress · Typer + Rich (CLI) ·
psycopg 3 · Streamlit + Plotly (dashboard) · Jinja2 (HTML report) · pytest
