"""L5 checks (IMPLEMENTATION_PLAN §4): sample -> scratch restore -> round trip -> source drift.

    l5_sample      the reservoir sample and the sample-size formula behind it
    l5_restore     COPY FROM STDIN of the sample into a scratch schema (+ the dump's PRIMARY KEY)
    l5_round_trip  each restored row copied back out equals its dump line (carries the confidence
                   statement); needs no source database
    l5_source      only with --dsn: sampled rows vs the live table by PK; differences are DRIFT
                   (WARN -> SUSPECT), never CORRUPT
A missing or unusable database is SKIP (the export is not proven bad, only unproven).
"""

from typing import Any

import psycopg

from eguard.drift import compare_source
from eguard.models import CheckResult, DrillResult, Severity, SourceTable, Status
from eguard.restore_drill import first_line, run_drill
from eguard.sampler import ReservoirSampler, check_sample, confidence_statement

LAYER = 5
DDL_PROBLEMS = {"no_ddl", "ddl_refused", "ddl_error"}


def _check(
    name: str, status: Status, evidence: dict[str, Any], message: str, severity: Severity
) -> CheckResult:
    return CheckResult(
        layer=LAYER, name=name, status=status, severity=severity, evidence=evidence, message=message
    )


def _skip(name: str, message: str) -> CheckResult:
    return _check(name, Status.SKIP, {}, message, Severity.INFO)


def size(n: int) -> str:
    return f"{n / 1048576:.1f} MiB" if n >= 1048576 else f"{n / 1024:.1f} KiB"


def _restore_evidence(d: DrillResult) -> dict[str, Any]:
    keep = {"table", "scratch_table", "seen", "sampled", "status", "detail", "restored"}
    keep |= {"rejected_count", "rejected", "pk_error", "scratch_bytes"}
    return {
        "schema": d.schema_name,
        "dropped": d.dropped,
        "stale_dropped": d.stale_dropped,
        "scratch_bytes": d.scratch_bytes,
        "seconds": d.seconds,
        "tables": [t.model_dump(include=keep) for t in d.tables],
    }


def check_restore(d: DrillResult) -> CheckResult:
    ev = _restore_evidence(d)
    restored = sum(t.restored for t in d.tables)
    cleanup = f"schema {d.schema_name} {'dropped' if d.dropped else 'NOT confirmed dropped'}"
    if d.stale_dropped:
        cleanup += f"; {len(d.stale_dropped)} stale scratch schema(s) swept"
    if rejected := [r | {"table": t.table} for t in d.tables for r in t.rejected]:
        n = sum(t.rejected_count for t in d.tables)
        first = rejected[0]
        msg = f"{n:,} sampled row(s) rejected by COPY FROM STDIN, first {first['table']} line "
        msg += f"{first['line']:,}: {first['error']} ({cleanup})"
        return _check("l5_restore", Status.FAIL, ev, msg, Severity.CRITICAL)
    if pk := [t for t in d.tables if t.pk_error]:
        msg = f"PRIMARY KEY of {pk[0].table} cannot be created on the restored sample: "
        msg += f"{pk[0].pk_error} ({cleanup})"
        return _check("l5_restore", Status.FAIL, ev, msg, Severity.CRITICAL)
    if bad := [t for t in d.tables if t.status in DDL_PROBLEMS]:
        msg = f"{bad[0].table}: table could not be created in isolation ({bad[0].status}: "
        msg += f"{bad[0].detail}); its sample was not restored ({cleanup})"
        return _check("l5_restore", Status.WARN, ev, msg, Severity.MAJOR)
    if not d.dropped:
        msg = f"{restored:,} sampled rows restored, but {cleanup}"
        return _check("l5_restore", Status.WARN, ev, msg, Severity.MAJOR)
    msg = f"{restored:,} sampled rows restored with COPY FROM STDIN into {d.schema_name} "
    msg += f"(scratch space used {size(d.scratch_bytes)}, {d.seconds:.2f} s); {cleanup}"
    return _check("l5_restore", Status.PASS, ev, msg, Severity.CRITICAL)


def check_round_trip(d: DrillResult, p: float, confidence: float) -> CheckResult:
    tables = [t for t in d.tables if t.status == "ok"]
    ev: dict[str, Any] = {
        "comparison": "row hash of each restored row, copied back out in load order, vs its "
        "dump line (pg_dump writes canonical text)",
        "tables": [
            t.model_dump(include={"table", "restored", "round_tripped", "mismatched_count"})
            | {"mismatched": t.mismatched, "detail": t.detail}
            for t in tables
        ],
    }
    if bad := [t for t in tables if t.mismatched_count]:
        n = sum(t.mismatched_count for t in bad)
        msg = f"{n:,} restored row(s) differ from their dump line"
        if ex := next((m for t in bad for m in t.mismatched), None):
            cols = ", ".join(
                f"{c['column']} {c['dump']!r} -> {c['restored']!r}" for c in ex["columns"]
            )
            msg += f", first line {ex['line']:,}: {cols}"
        elif bad[0].detail:
            msg += f": {bad[0].detail}"
        return _check("l5_round_trip", Status.FAIL, ev, msg, Severity.CRITICAL)
    if not tables:
        return _skip("l5_round_trip", "no sampled table was restored: nothing to round-trip")
    if len(tables) < len(d.tables):
        missing = ", ".join(t.table for t in d.tables if t.status != "ok" and t.status != "empty")
        if missing:
            msg = f"round trip clean for the restored tables, but not run for: {missing}"
            return _check("l5_round_trip", Status.WARN, ev, msg, Severity.MAJOR)
    n = sum(t.round_tripped for t in tables)
    if any(t.rejected_count or t.pk_error for t in d.tables):  # restore failed: claim nothing more
        msg = f"the {n:,} rows that did restore came back identical to their dump lines"
        return _check("l5_round_trip", Status.PASS, ev, msg, Severity.CRITICAL)
    statements = [confidence_statement(p, confidence, t.table, t.sampled, t.seen) for t in tables]
    ev["confidence_statements"] = statements
    msg = f"all {n:,} restored rows came back byte-identical to their dump lines. " + " ".join(
        statements
    )
    return _check("l5_round_trip", Status.PASS, ev, msg, Severity.CRITICAL)


def check_source(tables: list[SourceTable]) -> CheckResult:
    ev = {
        "classification": "differences vs the live table are DRIFT (changed or deleted since the "
        "export), never corruption; corruption is the round trip's job",
        "tables": [t.model_dump() for t in tables],
    }
    compared = sum(t.compared for t in tables)
    changed = sum(t.drift_changed for t in tables)
    deleted = sum(t.drift_deleted for t in tables)
    excluded = sum(t.excluded for t in tables)
    note = f"; {excluded:,} excluded (failed restore/round trip)" if excluded else ""
    if changed or deleted:
        msg = f"DRIFT, not corruption: of {compared:,} sampled rows compared by PK with the live "
        msg += f"table, {changed:,} changed and {deleted:,} deleted since the export{note}"
        return _check("l5_source", Status.WARN, ev, msg, Severity.INFO)
    if off := [t for t in tables if t.status not in ("ok",)]:
        msg = f"{off[0].table}: not compared with the source ({off[0].status}: {off[0].detail})"
        return _check("l5_source", Status.WARN, ev, msg, Severity.INFO)
    msg = f"{compared:,} sampled rows identical to the live table by primary key{note}"
    return _check("l5_source", Status.PASS, ev, msg, Severity.INFO)


def l5_checks(
    sampler: ReservoirSampler,
    policy: dict[str, Any],
    scratch_dsn: str | None,
    source_dsn: str | None,
) -> list[CheckResult]:
    p, confidence = policy["l5"]["detect_fraction"], policy["l5"]["confidence"]
    checks = [check_sample(sampler, p, confidence)]
    if not sampler.samples:
        return checks
    skipped = [] if not source_dsn else [_skip("l5_source", "needs the restore drill")]
    if not scratch_dsn:
        why = "no scratch database (SCRATCH_DSN / --scratch-dsn): the sample was not restored"
        return checks + [_skip("l5_restore", why), _skip("l5_round_trip", why), *skipped]
    try:
        drill = run_drill(sampler.samples, scratch_dsn, policy)
    except psycopg.Error as exc:
        why = f"scratch database unusable: {first_line(exc)}"
        return checks + [_skip("l5_restore", why), _skip("l5_round_trip", why), *skipped]
    checks += [check_restore(drill), check_round_trip(drill, p, confidence)]
    if source_dsn:
        try:
            checks.append(check_source(compare_source(sampler.samples, drill, source_dsn, policy)))
        except psycopg.Error as exc:
            checks.append(_skip("l5_source", f"source database unusable: {first_line(exc)}"))
    return checks
