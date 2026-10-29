"""L2 structural integrity: turn what the dump state machine saw (DumpStructure) into checks."""

from typing import Any

from eguard.models import CheckResult, CopyBlock, DumpStructure, Severity, Status, StreamEnd
from eguard.parsers.pg_plain import COMPLETE, COPY_ROWS

LAYER = 2
SHOWN = 10  # list items kept as evidence; counts are always complete


def _check(
    name: str, status: Status, evidence: dict[str, Any], message: str, *, critical: bool = True
) -> CheckResult:
    return CheckResult(
        layer=LAYER,
        name=name,
        status=status,
        severity=Severity.CRITICAL if critical else Severity.MAJOR,
        evidence=evidence,
        message=message,
    )


def _block(b: CopyBlock) -> dict[str, Any]:
    return b.model_dump(exclude={"columns"}) | {"column_count": len(b.columns)}


def check_header(s: DumpStructure) -> CheckResult:
    evidence = {
        "header_line": s.header_line,
        "dumped_from": s.dumped_from,
        "dumped_by": s.dumped_by,
        "restrict_key_present": s.restrict_key is not None,
    }
    if s.header_line is None:
        return _check(
            "l2_header",
            Status.FAIL,
            evidence,
            "no '-- PostgreSQL database dump' header: not a pg_dump plain-format file",
        )
    return _check(
        "l2_header", Status.PASS, evidence, f"pg_dump plain format, dumped by {s.dumped_by}"
    )


def check_copy_blocks(s: DumpStructure) -> CheckResult:
    problems: list[str] = []
    unclosed = [b for b in s.copies if not b.closed]
    no_ddl = [b for b in s.copies if b.table != "?" and b.table not in s.tables]
    unknown_cols = {
        b.table: missing
        for b in s.copies
        if b.table in s.tables
        and (missing := sorted(set(b.columns) - {c.name for c in s.tables[b.table].columns}))
    }
    if unclosed:
        problems.append(f"{len(unclosed)} COPY block(s) never closed by '\\.'")
    if s.bad_copy_headers:
        problems.append(f"{len(s.bad_copy_headers)} unparseable COPY header(s)")
    if no_ddl:
        problems.append(f"COPY without CREATE TABLE for {', '.join(b.table for b in no_ddl)}")
    if unknown_cols:
        problems.append(f"COPY columns missing from the DDL: {unknown_cols}")
    if s.stray_terminators:
        problems.append(f"'\\.' outside any COPY block at line(s) {s.stray_terminators[:SHOWN]}")
    evidence = {
        "copy_blocks": len(s.copies),
        "closed": len(s.copies) - len(unclosed),
        "unclosed": [_block(b) for b in unclosed[:SHOWN]],
        "bad_headers": s.bad_copy_headers[:SHOWN],
        "without_ddl": [b.table for b in no_ddl[:SHOWN]],
        "unknown_columns": unknown_cols,
        "stray_terminators": s.stray_terminators[:SHOWN],
    }
    if problems:
        return _check("l2_copy_blocks", Status.FAIL, evidence, "; ".join(problems))
    return _check(
        "l2_copy_blocks",
        Status.PASS,
        evidence,
        f"{len(s.copies)} COPY block(s), each with a header, DDL and '\\.' terminator",
    )


def check_tables(s: DumpStructure) -> CheckResult:
    blocks: dict[str, list[CopyBlock]] = {}
    for b in s.copies:
        blocks.setdefault(b.table, []).append(b)
    expected = [t for t in s.tables.values() if t.has_data]
    missing = [t.name for t in expected if t.name not in blocks]
    repeated = {name: len(bs) for name, bs in blocks.items() if len(bs) > 1}
    evidence = {
        "tables_declared": len(s.tables),
        "tables_with_data": len(expected),
        "missing_copy": missing[:SHOWN],
        "repeated_copy": repeated,
        "per_table": {
            name: {
                "rows": sum(b.rows for b in bs),
                "bytes": sum(b.bytes for b in bs),
                "first_row_line": bs[0].first_row_line,
                "last_row_line": bs[-1].last_row_line,
                "blocks": len(bs),
            }
            for name, bs in list(blocks.items())[:SHOWN]
        },
    }
    problems = []
    if missing:
        problems.append(f"no COPY data block for {len(missing)} table(s): {', '.join(missing)}")
    if repeated:
        problems.append(f"table(s) with more than one COPY block: {repeated}")
    if problems:
        return _check("l2_tables", Status.FAIL, evidence, "; ".join(problems))
    total = sum(b.rows for b in s.copies)
    return _check(
        "l2_tables",
        Status.PASS,
        evidence,
        f"{len(expected)} table(s), each with exactly one COPY block ({total:,} rows)",
    )


def _ended_where(s: DumpStructure) -> str:
    if s.state == COPY_ROWS:
        b = s.copies[-1]
        where = (
            f"stream ended inside COPY {b.table} after row {b.rows:,} "
            f"(decompressed line {b.last_row_line or b.header_line:,})"
        )
        if s.partial_line_bytes:
            where += f", then a partial row of {s.partial_line_bytes:,} bytes"
        return where + ": the exporter stopped mid-table"
    if s.open_statement:
        return f"stream ended inside a SQL statement at line {s.lines:,}"
    return f"stream ended in state {s.state} at line {s.lines:,}"


def check_complete(s: DumpStructure, end: StreamEnd) -> CheckResult:
    keys_match = s.restrict_key == s.unrestrict_key
    evidence: dict[str, Any] = {
        "state_at_end": s.state,
        "complete_marker_line": s.complete_line,
        "lines": s.lines,
        "last_line": s.last_line,
        "partial_line_bytes": s.partial_line_bytes,
        "open_copy": _block(s.copies[-1]) if s.state == COPY_ROWS else None,
        "open_statement": s.open_statement,
        "after_complete": s.after_complete,
        "after_complete_count": s.after_complete_count,
        "restrict_keys_match": keys_match,
        "container_clean": end.clean,
    }
    cause = "" if end.clean else " (decoder stopped early: see L1)"
    if s.state != COMPLETE:
        return _check(
            "l2_complete",
            Status.FAIL,
            evidence,
            f"{_ended_where(s)}; completion marker missing{cause}",
        )
    problems = []
    if s.after_complete_count:
        problems.append(
            f"{s.after_complete_count:,} statement line(s) after the completion marker "
            f"(first at line {s.after_complete[0]['line']:,})"
        )
    if not keys_match:
        problems.append(f"\\unrestrict key {s.unrestrict_key!r} != \\restrict key")
    if s.partial_line_bytes:
        problems.append(f"final line has no newline ({s.partial_line_bytes} bytes)")
    if problems:
        return _check("l2_complete", Status.FAIL, evidence, "; ".join(problems) + cause)
    return _check(
        "l2_complete",
        Status.PASS,
        evidence,
        f"completion marker at line {s.complete_line:,}; nothing but trailer after it",
    )


def check_structure(s: DumpStructure, end: StreamEnd) -> list[CheckResult]:
    return [check_header(s), check_copy_blocks(s), check_tables(s), check_complete(s, end)]
