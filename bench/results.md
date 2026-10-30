# Benchmarks

Every number here is produced by a script in `bench/`; newest first.

## Scale benchmark: verify L1–L5 vs full re-import (2026-10-30 11:21 UTC)

`bench/scale.py` · commit eb1944b+dirty

- Machine: AMD Ryzen 7 7840HS w/ Radeon 780M Graphics · 16 CPUs · 7.4 GiB RAM · Linux 6.6.87.2-microsoft-standard-WSL2
- Versions: Python 3.12.3 · PostgreSQL 16.15 (Debian 16.15-1.pgdg13+2) · pg_dump (PostgreSQL) 16.15 (Debian 16.15-1.pgdg13+2) · pigz 2.8 · gzip 1.12

| scale | rows | table in DB | compressed | uncompressed | hardened export | verify | compressed MB/s | uncompressed MB/s | peak RSS | L5 sample | layers | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| 1× | 300,000 | 118.5 MB | 49.5 MB | 98.1 MB | 6.4 s | 4.7 s | 10.5 | 20.9 | 97.5 MiB | 2995 | L1:PASS L2:PASS L3:PASS L4:PASS L5:PASS | VERIFIED RAL 5 (exit 0) |
| 3× | 900,000 | 355.5 MB | 148.6 MB | 294.4 MB | 18.4 s | 13.4 s | 11.1 | 22.0 | 97.8 MiB | 2995 | L1:PASS L2:PASS L3:PASS L4:PASS L5:PASS | VERIFIED RAL 5 (exit 0) |
| 5× | 1,500,000 | 592.4 MB | 247.7 MB | 491.2 MB | 28.4 s | 22.2 s | 11.2 | 22.1 | 98.7 MiB | 2995 | L1:PASS L2:PASS L3:PASS L4:PASS L5:PASS | VERIFIED RAL 5 (exit 0) |

| full re-import of | re-import wall | DB disk used | rows loaded | verify wall | re-import ÷ verify |
|---|---:|---:|---:|---:|---:|
| 1× (300,000 rows, 49.5 MB) | 1.5 s | 118.6 MB | 300,000 | 4.7 s | 0.3× |

verify = `eguard verify --json FILE --manifest MANIFEST` with SCRATCH_DSN set (L5 drill included). Peak RSS comes from wait4() on that process. 'hardened export' is `scripts/export_with_manifest.sh` (pg_dump | pigz -6 + manifest-build, then its own verify). 'table in DB' is pg_total_relation_size (in the Docker volume, outside the project disk budget). Each scale's export, manifest and schema were deleted before the next scale. The re-import DB was dropped afterwards.

Reproduce: `make up && make bench` (needs `.env` with PG_DSN, SCRATCH_DSN, MANIFEST_HMAC_KEY; scales and disk budget in `config/sim.yaml` `bench:`; the fault re-imports need `make faults verify-all` first).

### What re-import proves vs what ExportGuard proves

Each fault file was re-imported the same way as the 1× export (`gzip -dc | psql -v ON_ERROR_STOP=1` into a fresh throwaway database, dropped afterwards). ExportGuard's verdict is from `make verify-all` (`data/reports/verify_all.json`).

| export | psql exit | rows loaded / rows in source table | first psql error | ExportGuard | failing checks |
|---|---:|---:|---|---|---|
| F5 `data/exports/F5_amount.sql.gz` | 0 | 65,000 / 65,000 | – | CORRUPT (exit 2) | l4_fingerprint, l4_stream_digest, l4_compressed_sha256 |
| F1 `data/exports/F1_killed.sql.gz` | 3 | 0 / 65,000 | `ERROR:  invalid input syntax for type json` | CORRUPT (exit 2) | l2_copy_blocks, l2_complete |

- **F5**: psql reported success and loaded 65,000 of 65,000 rows. ExportGuard: CORRUPT, "eguard_faults.transactions: content differs from the manifest; first damaged chunk 4 of 7: rows 30,001–40,000 (dump lines 30,051–40,050); 1 of 7 chunk(s) differ"
- **F1**: psql failed (exit 3) and loaded 0 of 65,000 rows. ExportGuard: CORRUPT, "1 COPY block(s) never closed by '\.'"
- **Space**: the full re-import of 1× used 118.6 MB of database space; ExportGuard's L5 drill on the same file restored a 2,995-row sample into 1.2 MiB of scratch.
- A re-import shows whether the bytes load; it has no record of what the source held, so a load that succeeds says nothing about missing or changed rows. ExportGuard's L4 compares against the signed manifest written at export time.
- Speed: only the times in the tables above were measured; no other speed claim is made.

## Scale benchmark: verify L1–L5 vs full re-import (2026-10-30 11:07 UTC)

`bench/scale.py` · commit eb1944b+dirty

- Machine: AMD Ryzen 7 7840HS w/ Radeon 780M Graphics · 16 CPUs · 7.4 GiB RAM · Linux 6.6.87.2-microsoft-standard-WSL2
- Versions: Python 3.12.3 · PostgreSQL 16.15 (Debian 16.15-1.pgdg13+2) · pg_dump (PostgreSQL) 16.15 (Debian 16.15-1.pgdg13+2) · pigz 2.8 · gzip 1.12

| scale | rows | table in DB | compressed | uncompressed | hardened export | verify | compressed MB/s | uncompressed MB/s | peak RSS | L5 sample | layers | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| 1× | 300,000 | 118.5 MB | 49.5 MB | 98.1 MB | 6.4 s | 4.6 s | 10.7 | 21.2 | 97.5 MiB | 2995 | L1:PASS L2:PASS L3:PASS L4:PASS L5:PASS | VERIFIED RAL 5 (exit 0) |
| 3× | 900,000 | 355.5 MB | 148.6 MB | 294.4 MB | 17.7 s | 13.6 s | 10.9 | 21.6 | 98.0 MiB | 2995 | L1:PASS L2:PASS L3:PASS L4:PASS L5:PASS | VERIFIED RAL 5 (exit 0) |
| 5× | 1,500,000 | 592.4 MB | 247.7 MB | 491.2 MB | 28.5 s | 22.2 s | 11.1 | 22.1 | 98.0 MiB | 2995 | L1:PASS L2:PASS L3:PASS L4:PASS L5:PASS | VERIFIED RAL 5 (exit 0) |

| full re-import of | re-import wall | DB disk used | rows loaded | verify wall | re-import ÷ verify |
|---|---:|---:|---:|---:|---:|
| 1× (300,000 rows, 49.5 MB) | 1.2 s | 118.6 MB | 300,000 | 4.6 s | 0.3× |

verify = `eguard verify --json FILE --manifest MANIFEST` with SCRATCH_DSN set (L5 drill included). Peak RSS comes from wait4() on that process. 'hardened export' is `scripts/export_with_manifest.sh` (pg_dump | pigz -6 + manifest-build, then its own verify). 'table in DB' is pg_total_relation_size (in the Docker volume, outside the project disk budget). Each scale's export, manifest and schema were deleted before the next scale. The re-import DB was dropped afterwards.

Reproduce: `make up && make bench` (needs `.env` with PG_DSN, SCRATCH_DSN, MANIFEST_HMAC_KEY; scales and disk budget in `config/sim.yaml` `bench:`).

## verify streaming memory (L1–L3) — 2026-10-29 17:21 UTC

`bench/l1_memory.py` · commit b32ffd1+dirty · Python 3.12.3 · AMD Ryzen 7 7840HS w/ Radeon 780M Graphics · 16 CPUs

| file | compressed | uncompressed | members | lines | L3 rows | wall | compressed MB/s | uncompressed MB/s | peak RSS | steady RSS min / median / max | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `data/exports/v1.sql.gz` | 49.5 MB | 98.1 MB | 1 | 300,067 | 300,000 | 4.0 s | 12.5 | 24.7 | 81.7 MiB | 55.8 / 63.5 / 81.7 MiB (16 samples) | SUSPECT (exit 1) |
| `data/bench/v1x7.sql.gz` | 346.3 MB | 686.4 MB | 7 | 2,100,469 | 300,000 | 7.7 s | 44.9 | 89.0 | 81.6 MiB | 55.0 / 64.6 / 81.6 MiB (31 samples) | CORRUPT (exit 2) |

Input grew 7.0× (compressed); peak RSS changed 1.00×. L4/L5 are not implemented yet, so a healthy file is SUSPECT. Failing checks: `data/exports/v1.sql.gz`: none; `data/bench/v1x7.sql.gz`: l2_complete. The big file is 7 complete dumps concatenated: L2 rightly flags everything after the first completion marker and does not parse it, so L3 validates the first dump only (see the L3 rows column). Row-scaled L3 memory is benched at 5×/10× scale in phase 8.

## verify streaming memory (L1–L3) — 2026-10-29 17:16 UTC

`bench/l1_memory.py` · commit b32ffd1+dirty · Python 3.12.3 · AMD Ryzen 7 7840HS w/ Radeon 780M Graphics · 16 CPUs

| file | compressed | uncompressed | members | lines | L3 rows | wall | compressed MB/s | uncompressed MB/s | peak RSS | steady RSS min / median / max | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `data/exports/v1.sql.gz` | 164.9 MB | 327.1 MB | 1 | 1,000,067 | 1,000,000 | 12.9 s | 12.8 | 25.4 | 81.5 MiB | 55.8 / 62.2 / 81.5 MiB (52 samples) | SUSPECT (exit 1) |
| `data/bench/v1x7.sql.gz` | 1,154.6 MB | 2,289.7 MB | 7 | 7,000,469 | 1,000,000 | 27.2 s | 42.4 | 84.1 | 81.7 MiB | 55.4 / 64.4 / 81.7 MiB (109 samples) | CORRUPT (exit 2) |

Input grew 7.0× (compressed); peak RSS changed 1.00×. L4/L5 are not implemented yet, so a healthy file is SUSPECT. Failing checks: `data/exports/v1.sql.gz`: none; `data/bench/v1x7.sql.gz`: l2_complete. The big file is 7 complete dumps concatenated: L2 rightly flags everything after the first completion marker and does not parse it, so L3 validates the first dump only (see the L3 rows column). Row-scaled L3 memory is benched at 5×/10× scale in phase 8.

## L1 streaming memory — 2026-10-29 16:51 UTC

`bench/l1_memory.py` · commit c1a42cb+dirty · Python 3.12.3 · AMD Ryzen 7 7840HS w/ Radeon 780M Graphics · 16 CPUs

| file | compressed | uncompressed | members | lines | wall | compressed MB/s | uncompressed MB/s | peak RSS | steady RSS min / median / max | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `data/exports/v1.sql.gz` | 164.9 MB | 327.1 MB | 1 | 1,000,067 | 1.5 s | 110.9 | 219.9 | 39.6 MiB | 38.9 / 38.9 / 38.9 MiB (6 samples) | SUSPECT (exit 1) |
| `data/bench/v1x7.sql.gz` | 1,154.6 MB | 2,289.7 MB | 7 | 7,000,469 | 9.6 s | 120.0 | 238.0 | 39.5 MiB | 37.2 / 38.7 / 39.2 MiB (39 samples) | SUSPECT (exit 1) |

Input grew 7.0× (compressed); peak RSS changed 1.00×. Verdict is SUSPECT because L2–L5 are not implemented yet; all L1 checks: PASS

