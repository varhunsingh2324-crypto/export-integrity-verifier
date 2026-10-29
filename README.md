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
make disk              # du -sh .venv, data/, project total; docker system df
make clean-data        # delete everything regenerable in data/ (rebuild: make incident faults)
```

**Disk budget:** the whole project stays under ~1.5 GB. `.venv` alone is ~764 MB.
- The full dataset is 300,000 rows.
- Fault files are built from a 50,000-row variant.
- `make bench` deletes its large inputs as soon as it has measured them.

`make test` runs the database tests when `PG_DSN` is set and **fails** if the DB is unreachable.
They are skipped only when `PG_DSN` is unset.

## Quick start

> Implemented so far: phases 0–3 (skeleton, incident simulation, streaming core + L1 container,
> L2 dump structure + L3 row validity). `eguard verify` runs L1–L3 and reports L4/L5 as SKIP, so a
> healthy file is SUSPECT (exit 1, RAL 3) for now. `make faults` builds F1, F2, F3 and F6 (F1 needs
> the database). `make verify-all`/`dashboard`/`demo` still exit non-zero with "not implemented
> yet" until their phase lands.

```bash
make up            # start PostgreSQL 16 in Docker (the simulated "production" DB)
make seed          # create the large table (configurable rows)
make incident      # reproduce the incident: export v1, business change, export v2 (+30% rows, −20% size)
                   # (`python -m sim.incident run --scale 0.1` for a fast 30 000-row run)
make faults        # fault gallery (F1, F2, F3, F6 so far) from a 50 000-row incident variant
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

Measured at the default 300 000 rows (`data/reports/incident.json`):

| | rows | raw dump bytes | gzip bytes |
|---|---:|---:|---:|
| v1 | 300,000 | 98,052,781 | 49,476,886 |
| v2 | 390,000 | 86,079,490 | 39,288,708 |
| change | +30.00 % | −12.21 % | −20.59 % |

The default used to be 1 000 000 rows, measured at +30.00 % rows and −20.52 % gzip. It was lowered
for the disk budget, and no simulation knob needed recalibrating.

Data is reproducible run to run; gzip sizes vary by a few bytes only because pg_dump ≥ 16.10 writes a
random `\restrict` key into each dump.

### L1 container check (phase 2)

`eguard verify FILE` streams the file once. It picks the format from the magic bytes, never from the
file name. gzip is parsed by hand on top of raw zlib: header fields (MTIME, XFL level hint, OS,
FNAME, FHCRC), multiple members, CRC32 and ISIZE (mod 2³²) per member, unexpected EOF, and trailing
bytes. Trailing non-gzip bytes are a WARN by default (`l1.trailing_garbage` in `config/policy.yaml`).
`.Z` files have their magic and max-bits byte checked and are decoded with `gzip -dc`. They always
get a WARN because the format has no checksum: `gzip -dc` exits 0 on a truncated or bit-flipped
`.Z`, so L1 cannot vouch for the content. One decompression pass fans out to every subscriber
(`eguard.stream.FanOut`), and later layers attach to it.

Against the incident exports. The fault files come from `make faults`: settings in
`config/sim.yaml`, record in `data/reports/faults.json`, and since the disk-budget change they are
built from the 50 000-row variant.

| file | `gzip -t` | `eguard verify` L1 | verdict (exit) |
|---|---|---|---|
| v1, v2 | OK | all PASS | SUSPECT (1): L4/L5 not built yet |
| F2: v2 truncated at 70 % | unexpected end of file | `l1_stream_end` FAIL (unexpected_eof) | CORRUPT (2) |
| F3: one byte XOR 0x01 at 50 % | crc error | `l1_integrity` FAIL (CRC32 mismatch) | CORRUPT (2) |

Memory stays flat as input grows (`make bench`, results in `bench/results.md`). With L1 only
(phase 2, on the earlier 1 M-row v1), peak RSS was 39.6 MiB on v1 (164.9 MB) and 39.5 MiB on a
1,154.6 MB seven-member gzip (2,289.7 MB decompressed), at about 120 MB/s compressed.

### L2 dump structure and L3 row validity (phase 3)

The same pass feeds a state machine for the PostgreSQL plain-dump grammar
(`eguard/parsers/pg_plain.py`): `PREAMBLE → BODY ⇄ COPY_ROWS → COMPLETE`.

**L2** checks four things:
- the dump header is present;
- every `COPY … FROM stdin;` has DDL and is closed by `\.`;
- every table with data has exactly one COPY block;
- the completion marker is present, nothing but the trailer follows it, and the
  `\restrict`/`\unrestrict` keys match.

When the stream stops early, L2 reports the table, the last complete row and the decompressed
line.

**L3** validates every row against the COPY header and the `CREATE TABLE` types in the same dump:
- strict UTF-8;
- field count;
- COPY escapes;
- NOT NULL;
- a type parse for integers, numeric(p,s), floats, boolean, date, timestamp[tz], char/varchar(n),
  text, json/jsonb, uuid and bytea.

Columns of any other type are listed and give a WARN.

**PK uniqueness.** pg_dump declares the PRIMARY KEY only *after* the data, so every NOT NULL
column is tracked as a candidate until the declaration arrives.
- A candidate is dropped once it shows `l3.pk_candidate_prune_dups` duplicates. A healthy key never
  does, and a dropped key's count is reported as a lower bound.
- Keys are 64-bit BLAKE2b hashes in an exact set up to `l3.pk_set_limit`. After that they go into
  a Bloom filter, with every hash also written to a spill file.
- A Bloom hit is only a suspect. It is reported only if the spill shows the hash at least twice, so
  Bloom false positives never become findings. On the earlier 1.3 M-row v2, one suspect was
  raised and rejected this way.

The results below come from the 300 000-row incident exports, and from `make faults`, which
builds the faults from the 50 000-row variant (`data/reports/faults.json`):

| file | `gzip -t` | failing checks (L1–L3) | verdict (exit) |
|---|---|---|---|
| v1 (300,000 rows) | OK | none: every row valid, `id` unique (Bloom, 0 suspects) | SUSPECT (1): L4/L5 not built yet |
| v2 (390,000 rows) | OK | none: every row valid, `id` unique (Bloom, 0 suspects) | SUSPECT (1) |
| F1: `timeout 0.25` killed pg_dump inside `pg_dump \| gzip` | **OK** | `l2_complete`: *stream ended inside COPY eguard_faults.transactions after row 29,589 (decompressed line 29,639), then a partial row of 260 bytes*; `l2_copy_blocks`: COPY never closed | CORRUPT (2) |
| F2: truncated at 70 % | unexpected end of file | `l1_stream_end`; L2 adds: ended inside COPY after row 29,216 | CORRUPT (2) |
| F3: one byte flipped | crc error | `l1_integrity`; L3 adds: 1 row with 9 fields instead of 10 (line 20,919) | CORRUPT (2) |
| F6: COPY rows 10,001–20,000 sent twice | OK | `l3_pk_unique`: ≥1,001 duplicate `id` (counting stops at the prune limit); first at line 20,051 | CORRUPT (2) |

L2 and L3 cost throughput. In `make bench`, the 300 000-row v1 (49.5 MB) takes 4.0 s, or
12.5 MB/s compressed, about 10× slower than L1 alone was. Peak RSS is 81.7 MiB on v1 and 81.6 MiB on
the 7× file (346 MB, deleted after measuring). That file is 7 concatenated dumps, and L3 validates
only the first of them, so it does not measure memory at 7× rows. That measurement is phase 8's
scale bench.

## Documentation

| File | For |
|---|---|
| [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) | Architecture, algorithms, phases, acceptance criteria |
| [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) | 12-minute demo runbook, slide outline, judge Q&A |
| [`docs/ORACLE_PRODUCTION_RUNBOOK.md`](docs/ORACLE_PRODUCTION_RUNBOOK.md) | How the same method applies to Oracle `exp`/`expdp` in production |

## Tech stack

Python 3.11 · PostgreSQL 16 (Docker) · gzip / pigz / ncompress · Typer + Rich (CLI) ·
psycopg 3 · Streamlit + Plotly (dashboard) · Jinja2 (HTML report) · pytest
