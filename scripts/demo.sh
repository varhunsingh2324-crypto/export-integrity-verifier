#!/usr/bin/env bash
# `make demo`: the whole story end-to-end from a clean database, timed (phase 8 target: < 5 min).
#
#   reset DB -> incident (seed v1, legacy export, purge + growth, legacy v2) -> v3 hardened export
#   -> fault gallery -> verify-all (JSON + HTML report per export) -> explain -> dashboard
#
# `make incident` seeds the table itself, so there is no separate seed step (it would load the rows
# twice). Exit: 0 when every step succeeded, otherwise the failing step's code (3 for a tool error).
set -euo pipefail

cd "$(dirname "$0")/.."
if [ -f .env ]; then set -a; . ./.env; set +a; fi  # as make does (-include .env + export)
EGUARD=.venv/bin/eguard
TARGET_MS=300000
STEPS=9
n=0

now_ms() { local t=${EPOCHREALTIME/./}; echo $((t / 1000)); }  # bash 5: no bc/date forks
fmt_ms() { printf '%d.%d s' $(($1 / 1000)) $(($1 % 1000 / 100)); }
T0=$(now_ms)

step() {  # step NAME CMD...: run CMD, print its wall time, stop the demo on failure
  local name=$1 rc=0 t
  shift
  n=$((n + 1))
  echo "== [$n/$STEPS] $name"
  t=$(now_ms)
  "$@" || rc=$?
  echo "== [$n/$STEPS] $name: $(fmt_ms $(($(now_ms) - t))) (exit $rc)"
  echo
  if [ "$rc" -ne 0 ]; then
    echo "demo FAILED at step $n ($name)" >&2
    exit "$rc"
  fi
}

reset_db() {  # drop everything the simulation, faults, bench and L5 drill create
  # || return: inside step's "$@" || rc=$? context, set -e is off
  docker compose exec -T db psql -U eguard -d eguard -X -q -v ON_ERROR_STOP=1 <<'SQL' || return
DROP TABLE IF EXISTS public.transactions;
DROP SCHEMA IF EXISTS eguard_faults CASCADE;
DROP SCHEMA IF EXISTS eguard_bench CASCADE;
DO $$
DECLARE s text;
BEGIN
  FOR s IN SELECT nspname FROM pg_namespace WHERE nspname LIKE 'eguard\_l5\_%' LOOP
    EXECUTE format('DROP SCHEMA %I CASCADE', s);
  END LOOP;
END $$;
SQL
  echo "database reset: no transactions table, no eguard_faults/eguard_bench/eguard_l5_* schemas"
}

reports() {
  local html
  html=$(find data/reports -maxdepth 1 -name '*.html' | wc -l)
  echo "data/reports: $html HTML report(s), $(find data/reports -maxdepth 1 -name '*.json' | wc -l) JSON"
  [ "$html" -gt 0 ]
}

step "start PostgreSQL" make --no-print-directory up
step "reset database" reset_db
step "incident: seed v1, legacy v1/v2 exports" make --no-print-directory incident
step "hardened export v3 (+ manifest, verify)" \
  "$EGUARD" export --table public.transactions --out data/exports/v3.sql.gz
step "fault gallery F0-F7" make --no-print-directory faults
# the gallery is CORRUPT by design: make verify-all fails only on a tool error (3)
step "verify-all + reports" make --no-print-directory verify-all
step "explain v1->v2 and F0->F7" make --no-print-directory explain
step "reports" reports

step "dashboard" make --no-print-directory dashboard

total=$(($(now_ms) - T0))
echo "demo total: $((total / 60000))m $(fmt_ms $((total % 60000))) (target < $((TARGET_MS / 60000)) min)"
if [ "$total" -gt "$TARGET_MS" ]; then
  echo "WARNING: over the $((TARGET_MS / 60000)) min target" >&2
fi
