#!/usr/bin/env bash
# Legacy export: reproduces the production job exactly as it ran — `pg_dump | gzip > file`.
#
# DELIBERATELY NAIVE: no `set -euo pipefail`, no PIPESTATUS check (rule 8 exception).
# A pipeline's exit status is that of its LAST command. If pg_dump dies mid-stream, gzip just sees
# end-of-input, writes a valid trailer and exits 0: the job "succeeds" and `gzip -t` passes on half
# a table. That silent failure is exactly what ExportGuard must detect, so this script must keep it.
# Do not "fix" it here; the hardened pipeline is scripts/export_with_manifest.sh.
#
# usage: legacy_export.sh <schema.table> <out.sql.gz>

TABLE="${1:?usage: legacy_export.sh <schema.table> <out.sql.gz>}"
OUT="${2:?usage: legacy_export.sh <schema.table> <out.sql.gz>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

docker compose -f "$ROOT/docker-compose.yml" exec -T db \
    pg_dump -U "${PGUSER:-eguard}" -d "${PGDATABASE:-eguard}" -t "$TABLE" | gzip > "$OUT"
