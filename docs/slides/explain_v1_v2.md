# Why v2 has +30 % rows but a 20.6 % smaller file

Source: `data/reports/explain_v1__v2.json` (`eguard explain data/exports/v1.sql.gz data/exports/v2.sql.gz`, eguard 0.0.1, generated 2026-10-30T10:39:05+00:00). Every number below is copied from that file by a script, never typed by hand (CONTRIBUTING.md rule 5). Regenerate with `make explain` if the exports are rebuilt.

## The answer (the tool's own narrative)

> Rows +30.0 % (300,000 → 390,000).
>
> Average row narrowed from 326.8 B to 220.7 B (−32.5 %), driven by `remarks` (120.0 B → 67.6 B per row; NULL fraction 0.0 % → 44.4 %) and `meta` (128.9 B → 77.8 B per row; NULL fraction 0.0 % → 0.0 %).
>
> Compression ratio 1.98× → 2.19× (+10.6 %): deflated at a fixed level 6, the data alone goes 1.98× → 2.19× (+10.6 %), and the original compressor's efficiency against that level changes +0.0 %.
>
> Re-compress probe (32.0 MiB from each stream, deflate level 6): 1.98× vs 2.19× (+10.4 %), i.e. 99.0 % of the files' ratio change: the gap persists at an equal level, so the data itself changed (H2 narrower rows / H3 more repetitive data), not the compressor (gzip, level hint default/unspecified → gzip, level hint default/unspecified).
>
> Net compressed size −20.6 %; waterfall: rows +30.0 %, row width −32.5 %, data compressibility −9.6 %, compressor +0.0 %, which multiply back to −20.6 %.
>
> Integrity: no integrity layer failed (old export SUSPECT, RAL 4; new export SUSPECT, RAL 4; L4 without full evidence), so nothing points to data loss (H5): the size change is explained by data shape.
>

## Waterfall: S = R × W ÷ C

| Step | v1 | v2 | Change | Effect on file size |
|---|---:|---:|---:|---:|
| Rows R | 300,000 | 390,000 | +30.0 % | +30.0 % |
| Bytes per row W | 326.8 B | 220.7 B | −32.5 % | −32.5 % |
| Data compressibility C_fixed (deflate level 6) | 1.98× | 2.19× | +10.6 % | −9.6 % |
| Compressor efficiency E = C ÷ C_fixed | 1.00× | 1.00× | +0.0 % | +0.0 % |
| **Compressed size S** | 49,476,886 B | 39,288,708 B | **−20.6 %** | product of steps −20.6 % |

Check: 1.3000 × 0.6753 × 0.9045 × 1.0001 = 0.7941; observed S2/S1 = 0.7941 (identity error 0.0e+00).

## Compressor or data? (re-compress probe)

32.0 MiB sampled from each decompressed stream, both deflated at level 6: 1.98× vs 2.19× (+10.4 %), against +10.6 % for the files themselves. The probe keeps 99.0 % of the gap → **H2/H3: the data changed, not the compressor**. Both files are gzip with XFL 0 / 0 (default/unspecified).

## What changed in the rows

| Column | bytes/row v1 → v2 | Δ | NULL fraction v1 → v2 | entropy bits/B v1 → v2 |
|---|---:|---:|---:|---:|
| `remarks` | 120.0 B → 67.6 B | -52.4 B | 0.0 % → 44.4 % | 4.00 → 4.00 |
| `meta` | 128.9 B → 77.8 B | -51.1 B | 0.0 % → 0.0 % | 4.55 → 4.61 |
| `txn_ts` | 28.9 B → 27.3 B | -1.6 B | 0.0 % → 0.0 % | 3.63 → 3.60 |
| `account_id` | 5.4 B → 4.8 B | -0.6 B | 0.0 % → 0.0 % | 3.27 → 3.28 |
| `amount` | 6.8 B → 6.3 B | -0.5 B | 0.0 % → 0.0 % | 3.42 → 3.35 |

## Integrity

v1 SUSPECT (RAL 4), v2 SUSPECT (RAL 4). Failed layers: none. Layers without full evidence: L4 (legacy exports have no manifest, so L4 cannot reconcile).
