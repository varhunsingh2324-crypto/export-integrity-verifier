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

> Implemented so far: phases 0–7 and phase 8 part A (skeleton, incident simulation, streaming core
> + L1 container, L2 dump structure, L3 row validity, fingerprints + signed manifest + L4, hardened
> export, L5 restore drill, verdict engine + `verify-all` matrix, JSON + HTML reports, `explain`
> size forensics, Streamlit dashboard, `make judge-test`). `eguard verify` runs L1–L5. L4 needs `--manifest`; without one it is SKIP. A
> manifest from the hardened export carries snapshot counts and the compressed sha256, so L4 can be
> fully evidenced; any other manifest leaves those two checks SKIP. L5 needs a scratch database
> (`SCRATCH_DSN` or `--scratch-dsn`); without one it is SKIP. Only a hardened export with a scratch
> database can reach VERIFIED (RAL 5). A SUSPECT verdict lists the missing evidence.
> `make faults` builds F0–F7 and F1h (needs the database). `make verify-all` prints the fault matrix.
> `make verify-all` also writes one JSON + HTML report per export to `data/reports/`.
> `make demo` still exits non-zero with "not implemented yet" until phase 8 part B.

```bash
make up            # start PostgreSQL 16 in Docker (the simulated "production" DB)
make seed          # create the large table (configurable rows)
make incident      # reproduce the incident: export v1, business change, export v2 (+30% rows, −20% size)
                   # (`python -m sim.incident run --scale 0.1` for a fast 30 000-row run)
make faults        # fault gallery (F0–F7, F1h) from a 50 000-row variant; F0 is a hardened
                   # export (`python -m sim.faults --only F4 --only F5`: rebuild some from the
                   # existing source and manifest, no database)
make verify-all    # verify every export: fault × (gzip -t, L1–L5, verdict) matrix
make explain       # size forensics: v1 → v2 (the incident) and F0 → F7 (compressor change)
make dashboard     # Streamlit dashboard in the background: prints the URL (make dashboard-stop)
make judge-test FILE=data/exports/v3.sql.gz OFFSET=20000000 MODE=flip \
     MANIFEST=data/manifests/v3.manifest.json   # damage a copy anywhere you like, then verify it
```

CLI:

```bash
eguard export  --table public.transactions --out data/exports/v3.sql.gz  # hardened export + verify
eguard verify  data/exports/v3.sql.gz --manifest data/manifests/v3.manifest.json   # L1–L5
pg_dump … | eguard manifest-build --out m.json   # manifest from any dump stream (stdin)
eguard manifest-seal m.json --compressed f.gz --snapshot ID --taken-at T --db-count s.t=N
eguard verify  data/exports/v2.sql.gz --dsn $PG_DSN --seed 7   # + sample vs live table (drift)
eguard verify  data/exports/v3.sql.gz --manifest … --report-dir data/reports  # + JSON + HTML
eguard verify-all data/exports --json                            # every export, worst exit code
eguard report  data/reports/verify_v3.json                        # re-render HTML from saved JSON
eguard explain data/exports/v1.sql.gz data/exports/v2.sql.gz      # size-anomaly forensics
eguard explain OLD NEW --json --report-dir data/reports           # + explain_<old>__<new>.json/.html
```

Exit codes: `0` VERIFIED · `1` SUSPECT · `2` CORRUPT · `3` tool error — so it drops straight into cron/CI/monitoring.
Every `eguard` command keeps to them: a usage error, a crash or Ctrl-C exits 3 (Click alone would
exit 2 or 1, which would read as CORRUPT or SUSPECT); `manifest-build` exits 2 on an incomplete
dump; `verify-all` exits with its worst row. `explain` issues no verdict: it exits 0 once the
change is explained, 3 on a tool error.

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

### Fingerprints, signed manifest and L4 (phase 4 part A)

Every COPY row is hashed as `h = first 8 bytes of BLAKE2b-512(raw line)`, read as a big-endian
uint64. Each COPY block gets:
- a table fingerprint `(count, Σh mod 2⁶⁴, ⊕h)`, which does not depend on row order;
- one chunk digest per `l4.chunk_rows` rows (10 000) in stream order, a BLAKE2b-128 over the rows'
  hashes;
- a root hash over the chunk digests.

The whole decompressed stream also gets a sha256. `eguard manifest-build` computes all of this
from a dump on stdin, so it can sit behind `tee` in the export pipe. It writes a pydantic
`Manifest`, signed with HMAC-SHA256 using `MANIFEST_HMAC_KEY`.

`eguard verify --manifest` checks the signature *before* the pass. A tampered, unsigned or
unreadable manifest FAILs `l4_manifest_signature`, which makes the verdict CORRUPT, and the
reconciliation checks are SKIPped: nothing is compared against an untrusted manifest. With a valid
manifest, L4 runs four checks:
- `l4_tables`
- `l4_row_counts`
- `l4_fingerprint`, which names each damaged chunk's row range and dump lines
- `l4_stream_digest`, which catches damage outside the rows

`make faults` pairs F2–F6 with the manifest of the source they were derived from
(`data/manifests/fault_source_v2.manifest.json`, 65,000 rows, 7 chunks). F1 is a separate killed
pg_dump run, so it has no manifest; part B's hardened export is what prevents it.

The table below was measured in part A, when the source was a legacy export and its manifest was
built in-process. Part B rebuilt the gallery; the current numbers are in the next section.

| file | L1–L3 | L4 (vs source manifest) | verdict (exit) |
|---|---|---|---|
| source v2 (65,000 rows) | all PASS | all PASS | SUSPECT (1), RAL 4: L5 not built yet |
| F4: `.Z`, one byte XOR 0x01 at 50 % (`gzip -dc` exits 0) | all PASS (L1 WARN: no checksum) | `l4_fingerprint`: *first damaged chunk 3 of 7: rows 20,001–30,000 (dump lines 20,051–30,050)* | CORRUPT (2) |
| F5: row 33,333 `amount` 2213.12 → 2214.12, re-gzipped | all PASS | `l4_fingerprint`: *chunk 4 of 7: rows 30,001–40,000 (dump lines 30,051–40,050)* | CORRUPT (2) |
| F2, F3, F6 | as above | also FAIL: row counts 29,216 / 65,000 (F2) and 75,000 (F6); F3's damaged chunk is 3 | CORRUPT (2) |
| source v2 + manifest with `count` edited | all PASS | `l4_manifest_signature` FAIL, rest SKIP | CORRUPT (2) |

An independent `diff` of the decompressed streams puts F4's single changed byte at dump line
22,160, which is row 22,110, inside the reported chunk 3. The flip landed in free text, so the row
is still valid and only L4 can see it. Fingerprinting costs about 0.1 s per 65,000 rows: verifying
the source took 0.73–0.75 s without a manifest and 0.83–0.84 s with one, at a peak RSS of about
51 MiB.

### Hardened export (phase 4 part B)

`scripts/export_with_manifest.sh` (or `eguard export`) is the fix for `legacy_export.sh`. It starts
with `set -euo pipefail` and runs these steps:
1. A psql session holds `BEGIN ISOLATION LEVEL REPEATABLE READ`, calls `pg_export_snapshot()`,
   and runs `count(*)` per table in that snapshot.
2. `pg_dump --snapshot=<id> | tee FIFO | pigz -6 > OUT.partial`, with `eguard manifest-build`
   reading the FIFO. It's a FIFO rather than `tee >(…)` because a process substitution's exit
   status never reaches `PIPESTATUS`.
3. Every `PIPESTATUS` entry, manifest-build and the psql session are all checked.
4. `eguard manifest-seal` adds the snapshot counts and the compressed sha256, then re-signs.
5. Only then does `OUT.partial` become `OUT`, and `eguard verify --manifest` runs.

On any failure the files become `.FAILED` and the script prints each stage's exit code. Exit codes
follow rule 7:
- verify's own code when the export completed (0 VERIFIED, 1 SUSPECT, 2 CORRUPT);
- 2 if any pipeline stage failed;
- 3 on a configuration error.

A healthy export is VERIFIED (exit 0) only if verify also ran the L5 drill (`SCRATCH_DSN` set).
Otherwise it ends SUSPECT (exit 1), and the script says it is *not* reported as fully verified.

L4 gains two checks:
- `l4_snapshot_counts`: the file's rows against `count(*)` in the snapshot. The manifest is built
  from the exporter's own stream, so only this check catches an exporter that cleanly emitted too
  few rows.
- `l4_compressed_sha256`: a match PASSes. A mismatch is a WARN if the decompressed stream still
  matches (the file was recompressed), otherwise a FAIL.

A manifest without these fields leaves both checks SKIP, so L4 isn't fully evidenced.

**(1) Normal run**, `eguard export --table public.transactions --out data/exports/v3.sql.gz`:
- snapshot `00000003-0000164B-1`: `count(*)` = 390,000;
- the manifest's dump stream has 390,000 rows (39 chunks), and an independent `zcat | awk` count
  of the COPY rows also gives 390,000;
- pigz -6 wrote 39,329,780 bytes;
- every L1–L4 check PASSes: SUSPECT (exit 1), RAL 4, in 10.5 s wall time.

**(2) The same kill for both scripts**, `timeout 0.6` on pg_dump inside the container:

| | exit | `gzip -t` | what is left | rows written (independent oracle) |
|---|---|---|---|---|
| `legacy_export.sh` | **0** | OK | `legacy_killed.sql.gz`, looks finished | 73,603 of 390,000, mid-COPY |
| `export_with_manifest.sh` | **2** | – | only `*.sql.gz.FAILED` + `*.manifest.json.FAILED` | 165,353, mid-COPY; report: `pg_dump exit 124 <-- FAILED`, `manifest-build exit 1 <-- FAILED` (exit 2 since phase 6, rule 7) |

The kill point varies with timing, so the two runs stopped at different rows.

**Fault gallery** (rebuilt: the source is now a hardened export of the 50,000-row variant's v2
state, 65,000 rows, and F2–F6 are checked against its manifest):

| file | failing checks | verdict (exit) |
|---|---|---|
| source `v2_hardened.sql.gz` | none | SUSPECT (1), RAL 4 |
| F1: legacy pg_dump killed (`timeout 0.25`), `gzip -t` OK | `l2_complete`: *after row 30,716 … partial row of 61 bytes*, `l2_copy_blocks` (no manifest) | CORRUPT (2) |
| F2: truncated at 70 % | `l1_stream_end`, L2, `l4_snapshot_counts`: *29,217 rows in the export vs 65,000 in the database* | CORRUPT (2) |
| F3: one byte flipped | `l1_integrity`, `l3_row_validity` (26,016 of 46,885 rows), `l4_snapshot_counts` 46,885 vs 65,000 | CORRUPT (2) |
| F4: `.Z`, one byte flipped (`gzip -dc` exits 0) | only L4: *first damaged chunk 3 of 7: rows 20,001–30,000*; `diff` oracle: row 22,149 | CORRUPT (2) |
| F5: row 33,333 `amount` 2213.12 → 2214.12 | only L4: *chunk 4 of 7: rows 30,001–40,000* | CORRUPT (2) |
| F6: COPY rows 10,001–20,000 sent twice | `l3_pk_unique`, `l4_snapshot_counts` 75,000 vs 65,000 | CORRUPT (2) |

F3 differs from the part-A numbers because the source is now compressed by pigz, so the same
offset flips a different deflate byte.

### L5 restore drill (phase 5)

The same streaming pass reservoir-samples the raw COPY lines (Algorithm L, one reservoir per COPY
block). The sample size is `n = ⌈ln(1 − confidence) / ln(1 − p)⌉`, from `policy.yaml` `l5`:
p = 0.1 % and 95 % give n = 2,995. A table with fewer rows is restored in full. The seed is random
unless you pass `--seed`, and it is recorded in `l5_sample`, so any run can be repeated. A fixed
default would let a crafted dump keep its bad rows outside a predictable sample.

On `SCRATCH_DSN`, inside one transaction:
1. `CREATE SCHEMA eguard_l5_<epoch>_<hex>`, then the dump's own `CREATE TABLE`, with only its name
   changed. A statement that isn't a single plain statement (a second `;`, dollar quoting) is
   refused, not run.
2. `COPY … FROM STDIN` with the sampled lines, the same path a real restore takes. If it fails, every
   row is retried in its own savepoint, so each rejected line is named with PostgreSQL's error.
   Then the dump's PRIMARY KEY is added.
3. Round trip: the table is copied back out in load order (`ORDER BY ctid`), and each row's hash is
   compared with its dump line. pg_dump writes canonical text, so a byte difference means
   PostgreSQL stored something other than what the line says (for example `40.005` stored as
   `40.01` in `numeric(12,2)`). This needs no source database.
4. With `--dsn`, the sampled rows are compared, read-only, with the live table by primary key. The
   PK and its types come from the live catalog. The export snapshot no longer exists, so a
   difference is **drift** (changed or deleted since the export): a WARN, so SUSPECT, never
   CORRUPT. Rows that failed restore or the round trip are left out of this comparison.
5. `finally`: rollback, `DROP SCHEMA … CASCADE`, then a check that the schema has left
   `pg_namespace`. Leftover `eguard_l5_*` schemas older than `l5.stale_scratch_seconds` (1 h) are
   dropped at startup.

Session settings follow pg_dump's (`DateStyle ISO`, `extra_float_digits 3`, …), with `TimeZone`
from `l5.timezone` (UTC). Limitation: a dump taken in a session with another time zone prints
timestamptz with a different offset, so the round trip flags it.

Measured on the 390,000-row exports (`SCRATCH_DSN` from `.env`):

| file | L5 | verdict (exit) | wall, peak RSS |
|---|---|---|---|
| v3 (hardened) + manifest | 2,995 rows restored, scratch space 1,277,952 bytes (1.2 MiB), drill 0.05 s; round trip identical; schema dropped | **VERIFIED (0), RAL 5** | 6.56 s, 97.2 MiB |
| v3 + manifest + `--dsn $PG_DSN` | as above, plus `l5_source`: 2,995 rows identical to the live table | VERIFIED (0), RAL 5 | – |
| v2 (legacy, no manifest) | all PASS | SUSPECT (1), RAL 4; missing evidence: *L4 l4_manifest SKIP: no manifest: nothing records what the exporter emitted …* | 6.73 s, 97.6 MiB |

Fault gallery with L5 (seed 5, `--manifest` for F2–F6). L5 adds evidence but doesn't change any
verdict:
- source `v2_hardened.sql.gz`: VERIFIED (0), RAL 5.
- F3: `l5_restore` FAIL. 1,654 sampled rows were rejected by COPY, the first on line 20,921 with
  *extra data after last expected column*.
- F6: `l5_restore` FAIL. The sample held both copies of a duplicated row, so the PRIMARY KEY could
  not be created.
- F1, F2, F4, F5: the sampled rows restore and round-trip cleanly. F4/F5 change a single row,
  which a 2,995-row sample rarely includes; L4 is what catches them.

### Verdict engine and fault matrix (phase 6 part A)

`verdict.py` folds every check into one status per layer, then applies `config/policy.yaml`
`verdict.corrupt_on_fail` (`[CRITICAL]`):

- A layer is FAIL if any check FAILs, SKIP if nothing ran or everything SKIPped, WARN for a WARN or
  for PASS mixed with SKIP (partial evidence), and PASS only if every check PASSed.
- CORRUPT if a CRITICAL check FAILs; otherwise SUSPECT unless all five layers PASS; VERIFIED then.
  RAL = layers that PASS.
- `--json` carries `layers` (status, reason), `verdict`, `ral`, `exit_code`, every check and `reasons`.

`make verify-all` verifies every `.gz`/`.Z` under `data/exports` (manifest from the gallery record,
else `data/manifests/<name>.manifest.json`), runs `gzip -t` beside it, and writes
`data/reports/verify_all.json`. Measured after `make faults` (L5 drill on, random seeds, 27.3 s):

| export | fault | gzip -t | L1 | L2 | L3 | L4 | L5 | verdict (exit) |
|---|---|---|---|---|---|---|---|---|
| `fault_source/v2_hardened` | F0 | OK | PASS | PASS | PASS | PASS | PASS | **VERIFIED** (0), RAL 5 |
| `F1_killed` (legacy) | F1 | **OK** | PASS | FAIL | WARN | SKIP | PASS | **CORRUPT** (2), RAL 2 |
| `F1h_killed_hardened` | F1h | **OK** | PASS | FAIL | WARN | FAIL | PASS | **CORRUPT** (2), RAL 2 |
| `F2_truncated` | F2 | FAIL | FAIL | FAIL | WARN | FAIL | PASS | **CORRUPT** (2), RAL 1 |
| `F3_byteflip` | F3 | FAIL | FAIL | PASS | FAIL | FAIL | PASS | **CORRUPT** (2), RAL 2 |
| `F4_bitflip.sql.Z` | F4 | **OK** | WARN | PASS | PASS | FAIL | PASS | **CORRUPT** (2), RAL 3 |
| `F5_amount` | F5 | **OK** | PASS | PASS | PASS | FAIL | PASS | **CORRUPT** (2), RAL 4 |
| `F6_dupchunk` | F6 | **OK** | PASS | PASS | FAIL | FAIL | FAIL | **CORRUPT** (2), RAL 2 |
| `F7_gzip1` (gzip -1) | F7 | OK | PASS | PASS | PASS | PASS | PASS | **VERIFIED** (0), RAL 5 |
| `v1`, `v2`, `fault_source/v1`, `v2` (legacy) | – | OK | PASS | PASS | PASS | SKIP | PASS | SUSPECT (1), RAL 4 |
| `v3` (hardened) | – | OK | PASS | PASS | PASS | PASS | PASS | **VERIFIED** (0), RAL 5 |

- L3 WARN on F1/F1h/F2: the dump was cut before `ALTER TABLE … PRIMARY KEY`, so `l3_pk_unique` is
  SKIP while `l3_row_validity` PASSes.
- F1 (legacy) has no manifest, so L4 has no reference: SKIP. F1h is the same kill in the hardened
  pipeline; its manifest, built from the exporter's own stream, says the dump is incomplete.
- F3 in this build: the flip damaged 1 row of 65,000, which the 2,995-row sample did not include,
  so L5 PASSes (L5 promises ≥0.1 % damage at 95 %). Another build garbled 24,786 rows and L5 FAILed.
  pg_dump's random `\restrict` key changes the compressed bytes every build.

### JSON + HTML report (phase 6 part B)

`--report-dir DIR` (`verify`, `verify-all`; `make verify-all` uses `data/reports`) writes
`verify_<name>.json` (the same `VerifyReport` as `--json`) and `verify_<name>.html`. Subdirectories
are part of the name (`verify_fault_source__v2`). `eguard report X.json` re-renders the HTML.

The HTML is one self-contained file: inline CSS (light and dark), no script, no external URL, so it
opens offline. Every value on the page comes from the checks' evidence, never from the file name:

- a verdict banner with RAL n/5, the exit code and one status per layer;
- 2–3 plain-English sentences for management (`report/view.summary`);
- **where in the stream**: table, fingerprint chunk *k of n*, row range, dump line(s), compressed
  byte offset, taken from L1–L5 evidence (e.g. F5: chunk 4 of 7, rows 30,001–40,000);
- every check per layer, with its message and collapsible JSON evidence;
- the L5 confidence statement, or why the drill gives none. On a non-VERIFIED file the page notes
  that the drill only covers the rows that are in the file;
- provenance: compressor and level hint (from the bytes), the compressor the manifest names,
  `gzip -t`, pg_dump and server version, snapshot id and time, manifest signature status, the L5
  seed, the eguard version and time.

Dump text in evidence is HTML-escaped (Jinja2 autoescape). The 14 reports from `make verify-all`
take 300 KB.

`tests/test_fault_matrix.py` (database) builds the whole gallery with the real generators and pins
gzip -t, every layer and the verdict, except F3/F4's L3/L5, which must instead agree with L4 and
with each other. Its rename test copies every file and manifest to random names, directories and
extensions and gets identical verdicts, layers and evidence (rule 9).

### Size forensics: `eguard explain OLD NEW` (phase 7)

Why did the file shrink while the rows grew? `explain` streams each file once (nothing decompressed
touches the disk) and splits the compressed size exactly:

```
S = R × W ÷ C,   C = C_fixed × E
ln(S2/S1) = ln(R2/R1) + ln(W2/W1) − ln(C_fixed2/C_fixed1) − ln(E2/E1)
```

R is the number of rows, W the decompressed bytes per row and C the decompressed bytes over the
compressed bytes. C_fixed is the same stream deflated at `policy.explain.level` (6), with each
table's COPY section compressed on its own, so it measures the data. E = C ÷ C_fixed is what the
original compressor did relative to that level. W is summed from its parts (column bytes,
delimiters, unparsed rows, non-row bytes) and C from the stream total. The waterfall must multiply
back to the observed size ratio within `identity_tolerance` (1 %); if it doesn't, explain exits 3.

- **Profile** for each table and column: rows, bytes, average width, NULL fraction, HyperLogLog
  distinct count (datasketch, p = 14), Shannon entropy in bits per byte (numpy histogram), and each
  table's compressed cost at the fixed level. Memory is bounded: per column, one HLL, one
  histogram and a 1 MiB buffer.
- **Re-compress probe**: a uniform reservoir of 64 KiB blocks, up to `probe_bytes` (32 MiB, also
  `--probe-bytes`) from each decompressed stream. The larger reservoir is cut to the same block
  count and both samples are deflated at the same level.
  - If the probe keeps ≤ 25 % of the files' ratio change, the compressor or its level changed
    (**H1**).
  - If it keeps ≥ 75 %, the data changed (**H2/H3**).
  - In between, both contributed.
  - The container format, gzip XFL level hint and `.Z` max bits are reported alongside.
- **Column drill-down**: every component of W, ranked by its contribution to ΔW (the
  contributions sum exactly to ΔW) and by Δ bits per row (entropy × value bytes ÷ rows).
- **Narrative**: every number is formatted from a field of the JSON (a test checks this). The last
  sentence comes from each file's saved `verify_*.json` in `--reports` (default `data/reports`). A
  report is reused only if its L1 byte counts match this pass; otherwise it is reported as stale.

Measured (`make explain`, `data/reports/explain_*.json`):

| | v1 → v2 (incident) | F0 `pigz -6` → F7 `gzip -1` |
|---|---:|---:|
| rows R | +30.0 % | +0.0 % |
| bytes per row W | 326.8 B → 220.7 B (−32.5 %) | +0.0 % |
| data ratio at level 6 (size effect) | 1.98× → 2.19× (−9.6 %) | 2.18× → 2.18× (+0.0 %) |
| compressor E (size effect) | +0.0 % | 1.00× → 0.94× (+6.5 %) |
| compressed size S | −20.6 % | +6.5 % |
| probe keeps of the ratio change | 99.0 % → **H2/H3** | 0.0 % → **H1** |
| main drivers of W | `remarks` −52.4 B/row (NULL 0 % → 44.4 %), `meta` −51.1 B/row | none |
| wall time / peak RSS | 14.9–15.0 s / 193–202 MiB | 3.5–6.1 s / 140–149 MiB |

`--report-dir` writes `explain_<old>__<new>.json` (= `--json`) and a self-contained `.html`. The
HTML uses the verify report's CSS, with the new export's verdict banner and summary when its verify
report was found, followed by the narrative, the decomposition table with CSS waterfall bars, the
probe, the columns and each table's profile. verify reports themselves are left unchanged.

### Dashboard and judge test (phase 8 part A)

`make dashboard` starts `streamlit run dashboard/app.py` in the background (pid and log in
`data/dev/`). It waits until `/_stcore/health` answers, prints `http://localhost:8501`
(`DASHBOARD_PORT` to change it), and returns. `make dashboard-stop` stops it. Page loads only read
the saved reports in `data/reports` (`EGUARD_REPORTS_DIR`), cached until a file changes, so run
`make verify-all` and `make explain` first. Tabs:

- **Verdict & evidence**: pick any export.
  - The card shows the verdict, RAL x/5, a chip per layer and the management summary.
  - Below it: the "where in the stream" table, the L5 confidence statement, and one expander per
    layer with every check's message and raw evidence.
  - The report's HTML can be downloaded or opened inline.
- **Fault matrix**: `verify_all.json` as a heatmap with columns gzip -t, L1–L5, the verdict, and
  "gzip -t says / ExportGuard says". The last column is flagged where gzip -t passed a CORRUPT
  file. Hover a cell for the layer's reason; a table view is included.
- **Size explained**: the `explain_*.json` pairs, v1 → v2 first.
  - A waterfall: old size × rows × bytes per row × data compressibility × compressor = new size.
    Each step multiplies the running size, so the bars depend on that order and add up to the new
    size within `identity_tolerance` (tested).
  - The narrative.
  - A column drill-down: Δ bytes per row bars, then per-column width, NULL %, HLL distinct count
    and entropy.
- **Verify a file**: upload any `.gz`/`.Z` export, optionally with its manifest.
  - The upload is copied to `data/dev/uploads/<id>/` and verified by the real engine:
    `matrix.verify_one`, the same as `verify-all`, with L5 when `SCRATCH_DSN` is set.
  - Its JSON + HTML report is written next to it.
  - Streamlit can't link to a local HTML file, so the report is offered as a download and inline.

Status colours are Okabe-Ito based: PASS `#0072B2` ✓, WARN `#E69F00` !, FAIL `#B03A00` ✗, SKIP
`#C8C8C8` –. A test checks two things:
- every pair stays ≥ 8 OKLab ΔE apart under simulated deutan, protan and tritan vision, and ≥ 15
  for normal vision;
- each status label has ≥ 4.5:1 contrast on its fill.

Colour is never the only cue: each status also carries its symbol and its word. There are no
external calls: no usage stats, no deploy button, no Plotly logo link, and no URL in
`dashboard/` (tested).

`make judge-test FILE=… OFFSET=… [MODE=flip|truncate] [MANIFEST=…]` lets anyone damage an export
where they choose. OFFSET is a byte offset or a percentage (`50%`). `sim/judge.py` copies the file
to `data/dev/judge_<mode>_<offset>_<name>`; the source is never touched.
- `flip` XORs one byte, by default with the F3 mask from `config/sim.yaml`.
- `truncate` keeps the first OFFSET bytes.

It then runs `eguard verify` on the copy, with the report in `data/dev`. make fails only on a tool
error. Measured on v3 (390,000 rows, 39.3 MB) with its manifest, at OFFSET=20000000:

| MODE | verdict | where | time |
|---|---|---|---|
| flip | CORRUPT (exit 2): L1 CRC32, L2, L3 174,279 rows, L4, L5 | L4 first damaged chunk 13 of 39, rows 120,001–130,000 | 5.1 s |
| truncate | CORRUPT (exit 2): L1 EOF at compressed byte 20,000,000, L2, L4 | after row 127,020, partial row of 85 bytes | 2.3 s |

## Documentation

| File | For |
|---|---|
| [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) | Architecture, algorithms, phases, acceptance criteria |
| [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) | 12-minute demo runbook, slide outline, judge Q&A |
| [`docs/ORACLE_PRODUCTION_RUNBOOK.md`](docs/ORACLE_PRODUCTION_RUNBOOK.md) | How the same method applies to Oracle `exp`/`expdp` in production |

## Tech stack

Python 3.11 · PostgreSQL 16 (Docker) · gzip / pigz / ncompress · Typer + Rich (CLI) ·
psycopg 3 · Streamlit + Plotly (dashboard) · Jinja2 (HTML report) · pytest
