# Benchmarks

Every number here is produced by a script in `bench/`; newest first.

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

