# ExportGuard — Demo Runbook (12 minutes + Q&A)

Audience: industry experts (likely DBAs, SREs, backup/recovery people). They have *lived* this problem.
They will not be impressed by a dashboard; they will be impressed when you show a failure they have seen
in production and prove your tool catches it when the usual check does not.

**The one sentence they should leave with:**
> "`gzip -t` said the backup was fine. It was half a table. ExportGuard caught it in one streaming pass —
> no import, no tablespace — and also proved the *real* incident file was healthy and explained why it shrank."

---

## 0. Screen layout

- **Left (60 %)**: terminal, font ≥ 18 pt, dark theme, prompt shortened (`PS1='$ '`).
- **Right (40 %)**: browser with the Streamlit dashboard, already open.
- Second terminal tab with `docker compose ps` ready, in case someone asks "is that a real database?".

## 1. Pre-demo checklist (T−30 min)

- [ ] `make down && make demo` completed today on *this* laptop; note wall-clock time.
- [ ] Rehearsal check passed: `make verify-all` matches the fault matrix in `IMPLEMENTATION_PLAN.md` §6;
      incident within target (+30 % ± 1 % rows, −20 % ± 3 % size); `eguard explain v1 v2` multiplies out;
      `gzip -t` OK on F1 while ExportGuard says CORRUPT; one HTML report per export; dashboard starts.
- [ ] All exports + reports pre-generated in `data/` (live commands re-run quickly; heavy generation is not live).
- [ ] Dashboard loads; every chart renders.
- [ ] Laptop on power, notifications off, Wi-Fi not required (everything is local).
- [ ] **Fallback**: screen recording of a full run + PDF of the slides + static HTML reports on a USB stick.

---

## 2. Run of show

| Time | Segment | What you do / say |
|---|---|---|
| 0:00–1:00 | **Hook** | "A backup you can't restore isn't a backup. Our export grew 30 % in rows and the file shrank 20 %. Is that a disaster or a non-event? Today we answer that *without importing a single row*." |
| 1:00–2:30 | **Reproduce the incident** | Show `ls -lh data/exports/v1.sql.gz v2.sql.gz` and the row counts from `incident.py` output. "This is a real Postgres, real `pg_dump`, piped into `gzip` exactly like the production job." |
| 2:30–4:00 | **Why the usual checks fail** | Run `gzip -t data/exports/F1_killed.sql.gz && echo OK` → **OK**. Then `zcat … \| tail -3` → it ends mid-row. "The exporter was killed; gzip saw end-of-input and wrote a valid trailer. The pipeline exit code was gzip's — zero. Every cron job in the world would mark this green." |
| 4:00–6:00 | **ExportGuard on the incident file** | `eguard verify data/exports/v2.sql.gz --dsn $PG_DSN` → layer-by-layer output → **VERIFIED, RAL n/5** (forensic mode: say honestly why it's not 5). Then `eguard explain v1 v2` → waterfall on the dashboard: rows (+), row width (−), compressibility (−) = −20 %. Read the generated narrative aloud. **This answers management's question.** |
| 6:00–8:30 | **Fault gallery — defence in depth** | Dashboard matrix F1–F7 × L1–L5. Click through three: **F1** (L2: stream ended inside COPY block at row X), **F4** (`.Z` bit flip — "compress has no checksum, L1 is blind; L3/L4 catch it"), **F5** (valid gzip, valid rows, one amount changed — "only the fingerprint sees it, and it tells you which 100 000-row chunk"). |
| 8:30–10:00 | **Prevention, not just detection** | Show `scripts/export_with_manifest.sh`: `pipefail`, `PIPESTATUS`, same-snapshot `count(*)`, manifest via `tee`, HMAC. Run `eguard export` live on a small table → auto-verify → **VERIFIED RAL 5/5**. |
| 10:00–11:00 | **Numbers** | `bench/results.md`: throughput, peak memory, vs measured full re-import time and space. Only quote measured numbers. |
| 11:00–12:00 | **Production & close** | One slide: how it maps to Oracle `exp`/`expdp` (see `ORACLE_PRODUCTION_RUNBOOK.md`). Close: "Every export now ships with a verdict, an assurance level, and evidence. Management doesn't have to trust; they can check." |

---

## 3. The defence-in-depth matrix (your key slide)

Fill each cell from the **real** `make verify-all` output. Expected shape:

| Fault | `gzip -t` | L1 | L2 | L3 | L4 | L5 | Verdict |
|---|---|---|---|---|---|---|---|
| F0 v2 (healthy incident file) | ✔ OK | pass | pass | pass | pass | pass | VERIFIED |
| F1 exporter killed in pipe | ✔ **OK** | pass | **FAIL** | – | **FAIL** | – | CORRUPT |
| F2 truncated at rest | ✘ | **FAIL** | – | – | – | – | CORRUPT |
| F3 bit flip (gzip) | ✘ | **FAIL** | – | – | – | – | CORRUPT |
| F4 bit flip (`.Z`) | n/a | *blind* | ? | **FAIL** | **FAIL** | – | CORRUPT |
| F5 one value altered | ✔ **OK** | pass | pass | pass | **FAIL** | (maybe) | CORRUPT |
| F6 duplicated chunk | ✔ **OK** | pass | pass | **FAIL** | **FAIL** | – | CORRUPT |
| F7 compressor change only | ✔ OK | pass | pass | pass | pass | pass | VERIFIED (+ explained) |

The bold "OK"s in the `gzip -t` column are the story: **three of six real faults pass the standard check.**

---

## 4. Slide outline (10 slides max)

1. **Title** — ExportGuard: Restorability without re-import. Team, guide.
2. **The incident** — +30 % rows, −20 % size, no time/tablespace to re-import. Management's question.
3. **Two questions** — (a) Is it complete and restorable? (b) Why did it shrink? `S = R × W ÷ C`.
4. **Why existing checks fail** — pipe exit-code masking; `compress` has no checksum; `gzip -t` ≠ completeness.
5. **Architecture** — one streaming pass, five layers, verdict + RAL (the mermaid diagram from the plan).
6. **Key techniques** — gzip CRC/ISIZE/multi-member; dump grammar state machine; order-independent fingerprints + chunk Merkle; same-snapshot reconciliation; statistical sample size `n = ln α / ln(1−p)`.
7. **Defence-in-depth matrix** — the table above with real results.
8. **Size forensics** — the waterfall + column drill-down + re-compress probe result.
9. **Prevention** — hardened pipeline, signed manifest, cron/CI exit codes; Oracle mapping.
10. **Results & limits** — measured throughput/memory vs re-import; honest limitations; next steps.

---

## 5. Likely judge questions — and crisp answers

**"Why not just run `gzip -t`?"**
It only proves the compressed container is self-consistent. If the exporter dies inside a pipe, gzip
compresses a *short* input perfectly. We show exactly that with F1.

**"Isn't comparing `count(*)` enough?"**
Counts catch missing rows, not altered or duplicated-and-missing ones (F5, F6 can keep the count right).
That's why L3 validates every row and L4 compares content fingerprints.

**"The table changes after the export — how can counts match?"**
In assured mode we export and count inside the *same* MVCC snapshot (`pg_export_snapshot` +
`pg_dump --snapshot`), so they must match exactly. Oracle equivalent: `FLASHBACK_SCN` + `AS OF SCN`.
In forensic mode we can't make it exact, and the tool says SUSPECT instead of guessing.

**"Sampling 3 000 rows out of millions — isn't that weak?"**
Sampling is only L5. Every row is already parsed, typed and fingerprinted in L3/L4. L5 answers a different
question — "does it actually restore?" — and the sample size is chosen so ≥ 0.1 % damage is caught with
95 % probability.

**"Hash collisions?"**
64-bit fingerprints: accidental collision ≈ 2⁻⁶⁴ per comparison. Tampering is covered separately by the
HMAC-signed manifest.

**"Does this scale to terabytes?"**
It's I/O- and inflate-bound, single pass, bounded memory (sketches, Bloom filter). Parallelism comes from
multi-member/pigz or zstd seekable frames — chunks verify independently. Quote your measured MB/s.

**"We run Oracle, not Postgres."**
The method is database-agnostic; the parser is the dialect-specific part. Show the Oracle runbook:
`exp` log parsing, `imp SHOW=Y` read-through, `AS OF SCN` counts, `ORA_HASH` fingerprints,
`impdp QUERY` sampled restores for Data Pump.

**"Why did the file actually shrink in your scenario?"**
Read the narrative from `explain`: which column changed, by how much, and whether the re-compress probe
points at data or compressor.

**"What would you do on day one in a real company?"**
Wrap the existing export job with the hardened pipeline (pipefail + manifest + verify), alert on any
non-zero exit code, and schedule a full restore drill on a clone quarterly. Verification doesn't replace
restore drills — it makes them rare instead of impossible.

---

## 6. Things that lose points (avoid)

- Quoting numbers you didn't measure. Every number on a slide must trace to `bench/` or `data/reports/`.
- Claiming "100 % guarantee". Say *assurance level* and show the evidence.
- Live-generating millions of rows during the demo. Pre-generate; re-run only verification live.
- Explaining code line by line. Explain *failure modes* and *how each layer catches them*.
