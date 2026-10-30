# ExportGuard

**Prove a compressed database export is complete and restorable — without re-importing it.**

[![ci](https://github.com/varhunsingh2324-crypto/export-integrity-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/varhunsingh2324-crypto/export-integrity-verifier/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## The problem

A table export grew by **+30 % in rows**, yet the gzip file **shrank by 20 %**. Management asked
the only question that matters for a backup: *can we recover from this file?* There was no time
and no tablespace to re-import it and find out.

The usual check does not answer it. In `pg_dump | gzip > table.sql.gz`, if the exporter dies
halfway, gzip just sees end-of-input, writes a valid trailer and exits 0. **`gzip -t` passes; the
file is half a table.** Plain Unix `compress` (`.Z`) has no checksum at all.

ExportGuard streams the compressed file once, runs five independent integrity layers and issues a
verdict with evidence. A second command, `eguard explain`, explains *why* the size changed.

## How it works

One decompression pass fans out to every layer. Nothing decompressed is written to disk or held
whole in memory; anything that scales with rows uses a bounded sketch (HyperLogLog, reservoir
sample, Bloom filter).

| Layer | Checks | Catches |
|---|---|---|
| **L1 Container** | gzip/`.Z` magic, header, CRC32, ISIZE, members, trailing bytes | truncation, bit rot |
| **L2 Structure** | dump grammar: COPY blocks opened and closed, completion marker | exporter killed mid-stream (the pipe-masking failure) |
| **L3 Row validity** | every row: field count, type parse per column, primary-key uniqueness | partial rows, damaged bytes, duplicated chunks |
| **L4 Reconciliation** | row counts and content fingerprints against an HMAC-signed manifest written at export time, plus the source's same-snapshot `count(*)` | missing or altered rows that still look valid |
| **L5 Restore drill** | a statistically sized random sample restored into a throwaway scratch schema, then round-tripped byte for byte | anything that only shows on a real restore |

**Verdicts** (also the exit code):

| Verdict | Exit | Meaning |
|---|---:|---|
| **VERIFIED** | 0 | Every layer passed with full evidence. |
| **SUSPECT** | 1 | Nothing is provably broken, but evidence is missing, e.g. a legacy export with no manifest (L4 SKIP). |
| **CORRUPT** | 2 | A critical check failed. The report says where: table, chunk, row range, byte offset. |
| tool error | 3 | Bad usage, crash or missing dependency. Never mistaken for a verdict. |

**RAL (Recoverability Assurance Level, 0–5)** is the number of layers whose checks all passed with
full evidence. Only a hardened export with a manifest and a scratch database can reach RAL 5.

The L5 sample size is `n = ⌈ln(1 − confidence) / ln(1 − p)⌉`. With the defaults in
`config/policy.yaml` (p = 0.001, confidence 0.95) that is 2,995 rows, independent of table size.

### `eguard explain OLD NEW`: why did the file change size?

Compressed size is decomposed as

```
S = R × W ÷ C        R = rows, W = bytes per row, C = compression ratio
C = C_fixed × E      C_fixed = ratio of the data at a fixed deflate level, E = compressor effect
```

so `S_new / S_old` splits exactly into a rows factor, a row-width factor, a data-compressibility
factor and a compressor factor. The product is checked against the measured ratio; if it does not
match within tolerance, explain exits 3 instead of printing a wrong story. A re-compress probe
separates "the compressor changed" from "the data changed", and a per-column drill-down (width,
NULL share, HyperLogLog distinct count, entropy) names the columns responsible.

## Results

All numbers below come from real runs: `bench/results.md` and the JSON reports written by
`make verify-all` / `make explain`.

### The incident, reproduced

PostgreSQL 16, 300,000 rows, exported with a deliberately naive `pg_dump | gzip`:

| export | rows | gzip bytes |
|---|---:|---:|
| v1 | 300,000 | 49,476,894 |
| v2 (after a privacy purge + a new low-entropy app release) | 390,000 | 39,288,717 |
| change | **+30.00 %** | **−20.59 %** |

`eguard explain v1 v2`: rows +30.0 %, bytes per row −32.5 % (`remarks` −52.4 B/row as NULLs went
0 → 44.4 %; `meta` −51.1 B/row), data compressibility −9.6 %, compressor +0.0 %, net −20.6 %. The
probe attributes it to the data, not the compressor. No integrity layer failed: the file shrank
because its data did, not because rows were lost.

### Fault gallery: `gzip -t` vs ExportGuard

Built by `make faults` from a 65,000-row export. F1 uses the legacy pipeline; the others derive
from a hardened export with a signed manifest. L5 ran against a scratch database.

| fault | `gzip -t` | L1 | L2 | L3 | L4 | L5 | ExportGuard |
|---|---|---|---|---|---|---|---|
| F0 healthy hardened export | OK | PASS | PASS | PASS | PASS | PASS | **VERIFIED**, RAL 5 |
| F1 exporter killed mid-COPY (legacy) | **OK** | PASS | FAIL | WARN | SKIP | PASS | **CORRUPT**: stream ended inside COPY after row 29,026 |
| F1h same kill, hardened pipeline | **OK** | PASS | FAIL | WARN | FAIL | PASS | **CORRUPT** |
| F2 file truncated at 70 % | FAIL | FAIL | FAIL | WARN | FAIL | PASS | **CORRUPT** |
| F3 one byte flipped (gzip) | FAIL | FAIL | PASS | FAIL | FAIL | PASS | **CORRUPT** |
| F4 one byte flipped (`.Z`) | **OK** | WARN | PASS | PASS | FAIL | PASS | **CORRUPT**: chunk 3 of 7, rows 20,001–30,000 |
| F5 one amount changed, re-gzipped | **OK** | PASS | PASS | PASS | FAIL | PASS | **CORRUPT**: chunk 4 of 7, rows 30,001–40,000 |
| F6 10,000 rows sent twice | **OK** | PASS | PASS | FAIL | FAIL | FAIL | **CORRUPT** |
| F7 compressor change only (`gzip -1`) | OK | PASS | PASS | PASS | PASS | PASS | **VERIFIED**; explain: compressor effect, size +6.5 % |

`gzip -t` passes **five of the seven** damaged files (F1, F1h, F4, F5, F6). ExportGuard marks all
seven CORRUPT and passes both healthy ones. The legacy incident exports v1/v2 have no manifest, so
they are SUSPECT (RAL 4) by design: nothing records what the exporter emitted.

A test copies every fault file and manifest to random names, directories and extensions and gets
identical verdicts: detection never looks at file names.

### Benchmark

AMD Ryzen 7 7840HS, 16 CPUs, 7.4 GiB RAM, WSL2 · PostgreSQL 16.15 · pigz 2.8 · Python 3.12.3.
`eguard verify --manifest` with the L5 drill, on hardened exports at 1×/3×/5× of 300,000 rows:

| scale | rows | compressed | uncompressed | verify | MB/s (compressed / uncompressed) | peak RSS | verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| 1× | 300,000 | 49.5 MB | 98.1 MB | 4.7 s | 10.5 / 20.9 | 97.5 MiB | VERIFIED, RAL 5 |
| 3× | 900,000 | 148.6 MB | 294.4 MB | 13.4 s | 11.1 / 22.0 | 97.8 MiB | VERIFIED, RAL 5 |
| 5× | 1,500,000 | 247.7 MB | 491.2 MB | 22.2 s | 11.2 / 22.1 | 98.7 MiB | VERIFIED, RAL 5 |

Time grows linearly with the data; peak memory stays flat at about 98 MiB.

**Compared with a full re-import** (same machine, idle local Docker database):

| | full re-import (`gzip -dc \| psql`) | ExportGuard |
|---|---|---|
| 1× export, time | 1.5 s | 4.7 s |
| 1× export, space | 118.6 MB of database space | 1.2 MiB of scratch for the 2,995-row sample |
| F5 (one value changed) | psql exit 0, 65,000 / 65,000 rows loaded | CORRUPT, damaged chunk located |
| F1 (exporter killed) | psql exit 3, `invalid input syntax for type json`, 0 rows | CORRUPT, "stream ended inside COPY" |

On this machine a re-import of this table is **faster**. ExportGuard's case is space (it needs no
tablespace) and evidence: a re-import has no record of what the source held, so it loaded F5
without complaint, and its F1 error does not say the export was truncated.

`make demo` (everything in the quick start below, from a clean database) took **1 min 35 s**.

### Dashboard

![ExportGuard dashboard](docs/img/dashboard.png)

`make dashboard` serves a Streamlit app at <http://localhost:8501>: verdict cards with the
evidence per layer, the fault matrix, the size waterfall with column drill-down, and an upload box
that verifies any `.gz`/`.Z` file with the real engine. It makes no external calls.

## Requirements

- Linux (Ubuntu 22.04/24.04) or Windows with WSL2 Ubuntu
- Docker with Compose v2 (runs PostgreSQL 16)
- Python 3.11+ with `venv` (`sudo apt install python3-venv`)
- `gzip`, `pigz`, `ncompress` (`sudo apt install pigz ncompress`), GNU `make`
- ~1.5 GB of disk for the project, including the virtualenv

## Quick start

```bash
git clone https://github.com/varhunsingh2324-crypto/export-integrity-verifier.git
cd export-integrity-verifier
cp .env.example .env   # set MANIFEST_HMAC_KEY (e.g. `openssl rand -hex 32`)
make up
make demo
```

Then open <http://localhost:8501>.

`make demo` creates the virtualenv on first run, resets the database, reproduces the incident,
makes a hardened export, builds the fault gallery, verifies everything (one JSON + HTML report per
export in `data/reports/`), runs `explain`, starts the dashboard and prints the time per step.

## Usage

```bash
# Verify an export: L1–L3 always; L4 with --manifest; L5 when SCRATCH_DSN is set
eguard verify data/exports/v3.sql.gz --manifest data/manifests/v3.manifest.json
eguard verify data/exports/v2.sql.gz --dsn "$PG_DSN"        # + compare the sample with the live table
eguard verify FILE --json --report-dir data/reports           # machine output + JSON/HTML report

# Explain a size change
eguard explain data/exports/v1.sql.gz data/exports/v2.sql.gz

# Hardened export: one snapshot, pg_dump | tee FIFO | pigz, signed manifest, then verify
eguard export --table public.transactions --out data/exports/v3.sql.gz

eguard verify-all data/exports               # every export: gzip -t, L1–L5, verdict
eguard report data/reports/verify_v3.json    # re-render HTML from saved JSON
eguard doctor                                # toolchain + database check
```

`eguard` lives in `.venv/bin` after the first `make` run.

Exit codes: `0` VERIFIED · `1` SUSPECT · `2` CORRUPT · `3` tool error, for every command, so it
drops into cron, CI or monitoring. `explain` issues no verdict: 0 when explained, 3 on error.

Configuration: `.env` (`PG_DSN`, `SCRATCH_DSN`, `MANIFEST_HMAC_KEY`); verdict thresholds in
`config/policy.yaml`; simulation and benchmark settings in `config/sim.yaml`.

### Make targets

| target | does |
|---|---|
| `make up` / `make down` | start / stop PostgreSQL in Docker |
| `make demo` | the whole story from a clean database, timed, then the dashboard |
| `make incident` | seed the table, legacy v1 export, business change, legacy v2 export |
| `make faults` | build the F0–F7 fault gallery from a 50,000-row variant |
| `make verify-all` | verify every export, print the matrix, write reports |
| `make explain` | size forensics for v1 → v2 and F0 → F7 |
| `make dashboard` / `make dashboard-stop` | Streamlit dashboard in the background |
| `make judge-test FILE=… OFFSET=… [MODE=flip\|truncate] [MANIFEST=…]` | damage a copy of any export where you choose, then verify it |
| `make bench` | 1×/3×/5× benchmark + re-import comparison → `bench/results.md` |
| `make test` / `make lint` | pytest (database tests need `make up`) / ruff |
| `make disk` / `make clean-data` | disk usage / delete everything regenerable in `data/` |

## Project structure

```
src/eguard/            the engine
  stream.py              one decompression pass, fanned out to every consumer
  container.py           L1
  parsers/, structure.py L2
  rows.py, sketches.py   L3
  fingerprint.py, manifest.py, reconcile.py   L4
  sampler.py, restore_drill.py, drift.py, l5.py   L5
  verdict.py             policy → verdict + RAL
  profile.py, forensics.py   eguard explain
  report/                JSON + self-contained HTML reports
  cli.py                 Typer CLI
dashboard/             Streamlit app (pure data functions in data.py)
sim/                   incident simulation, fault gallery, judge test
scripts/               legacy_export.sh (the naive pipeline), export_with_manifest.sh (the fix), demo.sh
config/                policy.yaml (thresholds), sim.yaml (simulation, faults, benchmark)
bench/                 benchmarks and results.md
tests/                 unit tests per layer + the end-to-end fault matrix
docs/                  demo runbook, Oracle production runbook, slides
```

Design, algorithms and acceptance criteria: [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md).
Engineering rules for contributors: [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Limitations

- **PostgreSQL plain-format dumps only** (`pg_dump` text with COPY). Custom/directory formats and
  other databases are not parsed. `docs/ORACLE_PRODUCTION_RUNBOOK.md` describes how the method
  maps to Oracle; it is not implemented.
- **Legacy exports top out at SUSPECT.** Without a manifest written at export time, nothing records
  what the exporter emitted, so rows that are missing or changed but still parse cannot be proven
  (F5 passes L1–L3).
- **`.Z` has no checksum.** L1 can only WARN on a damaged `.Z`; detection relies on L3/L4.
- **L5 is statistical.** It detects a damaged-row fraction ≥ 0.1 % with 95 % confidence; it is
  not a full restore.
- **Throughput is about 11 MB/s compressed** on the machine above, limited by row validation in
  pure Python. There, a full re-import of the benchmark table was faster; the gain is space and
  evidence, not speed. A large production table with indexes was not measured.
- **The manifest key is symmetric** (HMAC-SHA256): whoever can verify can also sign. Keep the key
  away from the exports.
- Exercised mainly on one synthetic 10-column table (`transactions`).

## License

MIT — see [LICENSE](LICENSE).

## Author

Varhun
