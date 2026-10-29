# Applying ExportGuard's Method to Oracle in Production

The prototype uses PostgreSQL because it is free, scriptable and runs on a laptop. The problem statement's
wording — *"compressed by a Unix utility while the export command is being executed"* and *"tablespace scope"* —
describes a classic Oracle setup. This runbook shows how each layer maps to Oracle tooling.

> Commands below are standard Oracle utilities, but syntax and behaviour vary by version. Validate on a
> non-production instance of your Oracle release before relying on them.

---

## 1. What the original job almost certainly looked like

Data Pump (`expdp`) writes through a database directory object and cannot stream into a Unix pipe, so
"compressing while exporting" points to **classic `exp` writing into a named pipe**:

```bash
mknod /tmp/exp.pipe p
compress < /tmp/exp.pipe > BIG_TABLE.dmp.Z &      # or gzip
exp userid=... tables=APP.BIG_TABLE file=/tmp/exp.pipe log=exp.log
rm /tmp/exp.pipe
```

Failure modes hidden by this pattern:
- `exp` aborts (ORA-01555 snapshot too old, lost session, space in the log dir, killed process) → the
  compressor sees EOF and closes a *valid-looking* file.
- The script checks only the last command's exit code, or none at all.
- `compress` (`.Z`) has **no checksum**, so later bit-rot is undetectable by the container.

## 2. Why an Oracle export can legitimately shrink (H1–H4)

| Cause | What to check |
|---|---|
| Compressor changed (`compress` → `gzip`/`pigz`, or level change) | First two bytes: `1F 9D` = compress, `1F 8B` = gzip; gzip XFL byte |
| `exp` parameters changed: `INDEXES=N`, `GRANTS=N`, `STATISTICS=NONE`, `CONSTRAINTS=N`, `DIRECT=Y` | Compare the parameter files / job scripts and the `exp` log headers |
| Character set conversion (e.g. multibyte → single-byte client `NLS_LANG`) | "Export done in … character set" line in the log |
| Data shape: columns purged/NULLed, LOBs moved/archived, more repetitive values | Column stats (`AVG_COL_LEN`, `NUM_NULLS`, `NUM_DISTINCT` in `DBA_TAB_COL_STATISTICS`) before vs after |
| *Common myth*: `COMPRESS=Y` | This `exp` parameter is about consolidating extents in the generated DDL, **not** about dump file size |

## 3. Layer mapping

| Layer | Oracle-world implementation |
|---|---|
| **L1 Container** | `gzip -t file.dmp.gz`; for `.Z`, `uncompress -c file.dmp.Z > /dev/null` only proves decodability (no checksum) — record a `sha256sum` at creation time from now on |
| **L2 Structure** | (a) the `exp` log must contain `Export terminated successfully without warnings.` and no `EXP-`/`ORA-` lines; (b) read the whole dump through `imp ... SHOW=Y` via a pipe — it lists the contents without inserting rows; a damaged/truncated dump typically fails with IMP- errors such as `IMP-00009: abnormal end of export file` |
| **L3 Row validity** | Classic `exp` format is not publicly specified; rely on the `imp SHOW=Y` full read-through (+ row parsing only if you build a format reader) |
| **L4 Reconciliation** | `exp` log line `. . exporting table BIG_TABLE  N rows exported` vs `SELECT COUNT(*) FROM APP.BIG_TABLE AS OF SCN :scn` where `:scn` is the `FLASHBACK_SCN` the export used — must match exactly |
| **L5 Restore drill** | Data Pump: `impdp ... TABLES=APP.BIG_TABLE QUERY=... REMAP_SCHEMA=APP:SCRATCH` imports only a small subset into a scratch schema (MBs, not the table's tablespace). Classic `imp` has no row filter, so for `exp` dumps L5 means a periodic full restore drill on a clone/standby |

Read-through without import (classic exp dump, compressed):

```bash
mknod /tmp/imp.pipe p
gzip -dc BIG_TABLE.dmp.gz > /tmp/imp.pipe &          # or: uncompress -c BIG_TABLE.dmp.Z
imp userid=... file=/tmp/imp.pipe full=y show=y log=imp_show.log
wait $!; rm /tmp/imp.pipe
grep -E "IMP-|ORA-" imp_show.log && echo "DUMP NOT READABLE"
```

Data Pump metadata check (no data imported): `impdp ... SQLFILE=ddl_check.sql` writes the DDL that *would*
run. It validates the dump's metadata is readable — not every data row — so combine it with L4 and L5.

## 4. Source-side content fingerprint (for sampled comparisons)

```sql
-- Same SCN the export used; one aggregate per table, no data leaves the database
SELECT COUNT(*)                                            AS row_count,
       SUM(ORA_HASH(id || '|' || account_id || '|' ||
                    TO_CHAR(txn_ts,'YYYY-MM-DD"T"HH24:MI:SS.FF') || '|' ||
                    amount || '|' || status))              AS content_sum
FROM   app.big_table AS OF SCN :export_scn;
```

Run the same expression on the restored sample in the scratch schema, restricted to the sampled
primary keys, and compare row by row. Use explicit `TO_CHAR` formats so NLS settings can't change the hash input.

## 5. Hardened Oracle export wrapper (the R6 fix)

```bash
#!/usr/bin/env bash
set -euo pipefail
TABLE=APP.BIG_TABLE; OUT=/backup/big_table_$(date +%F).dmp.gz; LOG=${OUT%.dmp.gz}.exp.log
PIPE=$(mktemp -u /tmp/exp.XXXX.pipe); mkfifo "$PIPE"; trap 'rm -f "$PIPE"' EXIT

SCN=$(sqlplus -s "$EXP_USER" <<< "set head off feed off
select current_scn from v\$database;" | tr -d '[:space:]')

gzip -6 < "$PIPE" > "$OUT.partial" & GZ_PID=$!
set +e
exp userid="$EXP_USER" tables="$TABLE" file="$PIPE" log="$LOG" flashback_scn="$SCN"
EXP_RC=$?
wait "$GZ_PID"; GZ_RC=$?
set -e

# Exit codes alone are not trusted: also require the success line and no EXP-/ORA- errors
grep -q "Export terminated successfully without warnings" "$LOG" || EXP_RC=99
grep -Eq "EXP-[0-9]+|ORA-[0-9]+" "$LOG" && EXP_RC=98
DUMP_ROWS=$(grep -oP 'exporting table\s+\S+\s+\K[0-9]+(?=\s+rows exported)' "$LOG" || echo MISSING)
SRC_ROWS=$(sqlplus -s "$EXP_USER" <<< "set head off feed off
select count(*) from $TABLE as of scn $SCN;" | tr -d '[:space:]')

if [[ $EXP_RC -ne 0 || $GZ_RC -ne 0 || "$DUMP_ROWS" != "$SRC_ROWS" ]]; then
  mv "$OUT.partial" "$OUT.FAILED"; echo "EXPORT FAILED exp=$EXP_RC gzip=$GZ_RC rows=$DUMP_ROWS/$SRC_ROWS"; exit 2
fi
if ! gzip -t "$OUT.partial"; then mv "$OUT.partial" "$OUT.FAILED"; echo "CONTAINER CHECK FAILED"; exit 2; fi
mv "$OUT.partial" "$OUT"
sha256sum "$OUT" > "$OUT.sha256"
printf '{"table":"%s","scn":%s,"rows":%s}\n' "$TABLE" "$SCN" "$SRC_ROWS" > "$OUT.manifest.json"
```

(`$EXP_USER` needs SELECT on `V$DATABASE` and FLASHBACK on the table.)

Key points to say to an Oracle DBA:
- `flashback_scn` makes the export consistent *and* gives you the SCN to reconcile against.
- Both processes' exit codes are captured; the compressor finishing cleanly no longer hides an exporter failure.
- The file is only renamed to its final name after every check passes — anything else is visibly `.FAILED`.
- The manifest and checksum let anyone re-verify the file later without the database.

## 6. Operating it

- Schedule the wrapper plus verification; alert on any non-zero exit code.
- Keep manifests in a different location from the dumps.
- Quarterly full restore drill on a clone (storage snapshot) — verification makes these rare, not unnecessary.
