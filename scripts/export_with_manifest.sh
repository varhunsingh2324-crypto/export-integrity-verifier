#!/usr/bin/env bash
# Hardened export (IMPLEMENTATION_PLAN.md §7): the fix for scripts/legacy_export.sh.
#
#   1. A psql session holds a REPEATABLE READ transaction, exports its snapshot and counts every
#      table in it. pg_dump --snapshot then dumps exactly that snapshot, so the counts must match
#      the dump exactly.
#   2. pg_dump | tee FIFO | pigz > OUT.partial, with `eguard manifest-build` reading the FIFO.
#      A FIFO, not `tee >(...)`: a process substitution's exit status never reaches PIPESTATUS, so
#      it could fail unseen. Every PIPESTATUS entry, manifest-build and psql are all checked.
#   3. `eguard manifest-seal` adds the snapshot counts and the compressed sha256, and re-signs.
#   4. OUT.partial becomes OUT only after every stage succeeded; then `eguard verify` runs.
#
# Any failure: OUT.partial -> OUT.FAILED, the manifest -> .FAILED, a per-stage report, non-zero exit.
# Exit codes (CONTRIBUTING.md rule 7): eguard verify's own code (0 VERIFIED, 1 SUSPECT, 2 CORRUPT) when
# the export completed; 2 if any pipeline stage failed (the export is unusable); 3 config error.
# A CORRUPT or tool-error verify also quarantines the files as .FAILED.
#
# usage: export_with_manifest.sh [-m manifest.json] <out.sql.gz> <schema.table>...
#
# Environment: MANIFEST_HMAC_KEY (required); PGUSER/PGDATABASE (default eguard); PIGZ_LEVEL (6);
# EXPORT_DUMP_TIMEOUT=<seconds> runs pg_dump under coreutils `timeout` inside the container, the
# same kill as LEGACY_DUMP_TIMEOUT, for the side-by-side demo; EXPORT_COMPRESSOR and EXPORT_EGUARD
# replace pigz / eguard (tests inject failing stages with them); SNAPSHOT_TIMEOUT (30 s per answer).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/docker-compose.yml")
PGUSER="${PGUSER:-eguard}"
PGDATABASE="${PGDATABASE:-eguard}"
LEVEL="${PIGZ_LEVEL:-6}"
COMPRESSOR="${EXPORT_COMPRESSOR:-pigz}"
SNAPSHOT_TIMEOUT="${SNAPSHOT_TIMEOUT:-30}"
if [ -n "${EXPORT_EGUARD:-}" ]; then
    EGUARD="$EXPORT_EGUARD"
elif [ -x "$ROOT/.venv/bin/eguard" ]; then
    EGUARD="$ROOT/.venv/bin/eguard"
else
    EGUARD=eguard
fi

STATE=setup      # setup -> exporting -> verifying -> done
WORK=""
MB_PID=""
OUT=""
MANIFEST=""

die() {  # die <exit code> <message>
    echo "export_with_manifest: $2" >&2
    exit "$1"
}

quarantine() {
    local f
    for f in "$OUT.partial" "$OUT" "$MANIFEST.partial" "$MANIFEST"; do
        if [ -n "$f" ] && [ -e "$f" ]; then
            mv -f "$f" "${f%.partial}.FAILED"
            echo "  quarantined: ${f%.partial}.FAILED" >&2
        fi
    done
}

on_exit() {
    local rc=$?
    trap - EXIT
    if [ -n "$MB_PID" ]; then kill "$MB_PID" 2>/dev/null || true; fi
    if [ -n "${PSQL_PID:-}" ]; then kill "$PSQL_PID" 2>/dev/null || true; fi
    if [ -n "$WORK" ]; then rm -rf "$WORK"; fi
    if [ "$STATE" = exporting ] || [ "$STATE" = verifying ]; then
        # An unexpected error mid-export must never look like 0/1: the export is unusable.
        if [ "$rc" -ne 2 ] && [ "$rc" -ne 3 ]; then rc=2; fi
        echo "EXPORT FAILED (exit $rc)" >&2
        quarantine
    fi
    exit "$rc"
}
trap on_exit EXIT
trap 'exit 2' INT TERM

# -- arguments -------------------------------------------------------------------------------
while getopts "m:" opt; do
    case "$opt" in
        m) MANIFEST="$OPTARG" ;;
        *) die 3 "usage: export_with_manifest.sh [-m manifest.json] <out.sql.gz> <schema.table>..." ;;
    esac
done
shift $((OPTIND - 1))
[ $# -ge 2 ] || die 3 "usage: export_with_manifest.sh [-m manifest.json] <out.sql.gz> <schema.table>..."
OUT="$1"
shift
TABLES=("$@")
[ -n "$MANIFEST" ] || MANIFEST="$ROOT/data/manifests/$(basename "$OUT" .sql.gz).manifest.json"
[ -n "${MANIFEST_HMAC_KEY:-}" ] || die 3 "MANIFEST_HMAC_KEY is not set (cp .env.example .env)"
for t in "${TABLES[@]}"; do
    # Lower-case schema.table only, so count keys equal the names pg_dump writes in COPY headers.
    [[ "$t" =~ ^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$ ]] || die 3 "table must be schema.table: $t"
done
command -v "$COMPRESSOR" >/dev/null || die 3 "compressor not found: $COMPRESSOR"
mkdir -p "$(dirname "$OUT")" "$(dirname "$MANIFEST")"
WORK="$(mktemp -d)"

# -- 1. snapshot session ---------------------------------------------------------------------
STATE=exporting
coproc PSQL { "${COMPOSE[@]}" exec -T db psql -U "$PGUSER" -d "$PGDATABASE" -X -q -tA -v ON_ERROR_STOP=1; }
ask() {  # ask <sql>: one answer line from the snapshot session into $ANSWER
    printf '%s\n' "$1" >&"${PSQL[1]}"
    IFS= read -r -t "$SNAPSHOT_TIMEOUT" -u "${PSQL[0]}" ANSWER \
        || die 2 "snapshot session gave no answer to: $1"
}
ask "BEGIN ISOLATION LEVEL REPEATABLE READ; SELECT pg_export_snapshot() || '|' || now();"
SNAP="${ANSWER%%|*}"
TAKEN="${ANSWER#*|}"
[[ "$SNAP" =~ ^[0-9A-F]+-[0-9A-F]+-[0-9]+$ ]] || die 2 "unexpected snapshot id: $ANSWER"
COUNT_ARGS=()
DUMP_ARGS=()
for t in "${TABLES[@]}"; do
    ask "SELECT count(*) FROM $t;"
    [[ "$ANSWER" =~ ^[0-9]+$ ]] || die 2 "unexpected count for $t: $ANSWER"
    COUNT_ARGS+=(--db-count "$t=$ANSWER")
    DUMP_ARGS+=(-t "$t")
    echo "snapshot $SNAP: $t has $ANSWER rows" >&2
done

# -- 2. dump | tee | compress, manifest-build on the FIFO ----------------------------------
LIMIT=()
if [ -n "${EXPORT_DUMP_TIMEOUT:-}" ]; then LIMIT=(timeout "$EXPORT_DUMP_TIMEOUT"); fi
mkfifo "$WORK/dump"
"$EGUARD" manifest-build --out "$MANIFEST.partial" <"$WORK/dump" &
MB_PID=$!
set +e
"${COMPOSE[@]}" exec -T db "${LIMIT[@]}" pg_dump -U "$PGUSER" -d "$PGDATABASE" \
    --snapshot="$SNAP" "${DUMP_ARGS[@]}" \
    | tee "$WORK/dump" \
    | "$COMPRESSOR" "-$LEVEL" >"$OUT.partial"
ST=("${PIPESTATUS[@]}")
wait "$MB_PID"
MB=$?
MB_PID=""
printf 'COMMIT;\n\\q\n' >&"${PSQL[1]}"
wait "$PSQL_PID"
PS=$?
set -e

NAMES=(pg_dump tee "$COMPRESSOR" manifest-build "psql snapshot session")
CODES=("${ST[0]}" "${ST[1]}" "${ST[2]}" "$MB" "$PS")
FAILED=0
for i in "${!NAMES[@]}"; do
    [ "${CODES[$i]}" -eq 0 ] || FAILED=1
done
if [ "$FAILED" -ne 0 ]; then
    echo "export_with_manifest: a pipeline stage failed:" >&2
    for i in "${!NAMES[@]}"; do
        printf '  %-22s exit %s%s\n' "${NAMES[$i]}" "${CODES[$i]}" \
            "$([ "${CODES[$i]}" -eq 0 ] || echo '  <-- FAILED')" >&2
    done
    exit 2
fi

# -- 3. seal the manifest, publish the files ------------------------------------------------
"$EGUARD" manifest-seal "$MANIFEST.partial" --compressed "$OUT.partial" --snapshot "$SNAP" \
    --taken-at "$TAKEN" --compressor "$COMPRESSOR -$LEVEL" "${COUNT_ARGS[@]}" \
    || die 2 "manifest-seal failed"
mv -f "$OUT.partial" "$OUT"
mv -f "$MANIFEST.partial" "$MANIFEST"
rm -f "$OUT.FAILED" "$MANIFEST.FAILED"  # a stale quarantine from an earlier run is not this one

# -- 4. verify ----------------------------------------------------------------------------
STATE=verifying
set +e
"$EGUARD" verify "$OUT" --manifest "$MANIFEST"
V=$?
set -e
case "$V" in
    0) echo "export_with_manifest: $OUT VERIFIED (exit 0)" >&2 ;;
    1) echo "export_with_manifest: $OUT exported; verdict SUSPECT (exit 1): evidence missing (listed above, e.g. no SCRATCH_DSN for the L5 restore drill) — NOT reported as fully verified." >&2 ;;
    *)
        echo "export_with_manifest: verify exited $V — quarantining" >&2
        quarantine
        STATE=done
        exit "$V"
        ;;
esac
echo "manifest: $MANIFEST" >&2
STATE=done
exit "$V"
