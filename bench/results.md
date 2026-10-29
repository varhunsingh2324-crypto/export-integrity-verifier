# Benchmarks

Every number here is produced by a script in `bench/`; newest first.

## L1 streaming memory — 2026-10-29 16:51 UTC

`bench/l1_memory.py` · commit c1a42cb+dirty · Python 3.12.3 · AMD Ryzen 7 7840HS w/ Radeon 780M Graphics · 16 CPUs

| file | compressed | uncompressed | members | lines | wall | compressed MB/s | uncompressed MB/s | peak RSS | steady RSS min / median / max | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `data/exports/v1.sql.gz` | 164.9 MB | 327.1 MB | 1 | 1,000,067 | 1.5 s | 110.9 | 219.9 | 39.6 MiB | 38.9 / 38.9 / 38.9 MiB (6 samples) | SUSPECT (exit 1) |
| `data/bench/v1x7.sql.gz` | 1,154.6 MB | 2,289.7 MB | 7 | 7,000,469 | 9.6 s | 120.0 | 238.0 | 39.5 MiB | 37.2 / 38.7 / 39.2 MiB (39 samples) | SUSPECT (exit 1) |

Input grew 7.0× (compressed); peak RSS changed 1.00×. Verdict is SUSPECT because L2–L5 are not implemented yet; all L1 checks: PASS

