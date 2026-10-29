"""L5 source check (`verify --dsn`): sampled dump rows vs the live source table, by primary key.

The export snapshot is gone once the export transaction ends, so the live table can only be newer
than the dump. A difference is therefore DRIFT (row changed or deleted since the export), never
corruption. Corruption is what the round trip proves: a row restored but differing from its dump
line. Rows that failed restore or the round trip are excluded here, so they are never counted
twice or relabelled as drift.

Read-only. Table, primary key and column types come from the live catalog (pg_index,
format_type), never from the dump's text.
"""

from typing import Any

import psycopg
from psycopg import sql

from eguard.fingerprint import row_hash
from eguard.models import DrillResult, DrillTable, SourceTable
from eguard.parsers.pg_plain import split_idents, unquote
from eguard.restore_drill import apply_session, column_diff, connect, first_line
from eguard.rows import NULL, unescape
from eguard.sampler import TableSample

PK_SQL = """
SELECT a.attname, format_type(a.atttypid, a.atttypmod)
FROM pg_index i
JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
WHERE i.indrelid = %s AND i.indisprimary
ORDER BY array_position(i.indkey::int2[], a.attnum)
"""


def _parts(dump_name: str) -> list[str]:
    parts = [unquote(p) for p in split_idents(dump_name)]
    return parts if len(parts) == 2 else ["public", *parts][-2:]


def _live_oid(conn: psycopg.Connection, parts: list[str]) -> int | None:
    row = conn.execute(
        "SELECT to_regclass(format('%%I.%%I', %s::text, %s::text))::oid", parts
    ).fetchone()
    return None if row is None or row[0] is None else int(row[0])


def _key(line: bytes, positions: list[int]) -> tuple[bytes, ...]:
    fields = line.split(b"\t")
    return tuple(fields[p] for p in positions)


def _fetch_live(
    conn: psycopg.Connection,
    parts: list[str],
    columns: list[str],
    pk: list[tuple[str, str]],
    keys: list[tuple[bytes, ...]],
) -> dict[tuple[bytes, ...], bytes]:
    positions = [columns.index(name) for name, _ in pk]
    arrays = sql.SQL(", ").join(
        sql.SQL("{}::text[]::{}[]").format(
            sql.Literal([unescape(k[j].decode()) for k in keys]),
            sql.SQL(typ),  # type: ignore[arg-type]
        )
        for j, (_, typ) in enumerate(pk)
    )
    stmt = sql.SQL("COPY (SELECT {} FROM {} WHERE ({}) IN (SELECT * FROM unnest({}))) TO STDOUT")
    stmt = stmt.format(
        sql.SQL(", ").join(map(sql.Identifier, columns)),
        sql.Identifier(*parts),
        sql.SQL(", ").join(sql.Identifier(name) for name, _ in pk),
        arrays,
    )
    with conn.cursor() as cur, cur.copy(stmt) as cp:
        data = b"".join(bytes(chunk) for chunk in cp)
    lines = data.split(b"\n")[:-1] if data else []
    return {_key(line, positions): line for line in lines}


def _compare(
    s: TableSample,
    d: DrillTable,
    live: dict[tuple[bytes, ...], bytes],
    positions: list[int],
    out: SourceTable,
    max_examples: int,
) -> None:
    clean = set(d.clean_lines)
    for lineno, line in s.rows:
        if lineno not in clean:
            continue
        key = _key(line, positions)
        got = live.get(key)
        shown = [k.decode("utf-8", "replace") for k in key]
        if got is not None and row_hash(got) == row_hash(line):
            out.matched += 1
            continue
        example: dict[str, Any] = {"line": lineno, "key": shown}
        if got is None:
            out.drift_deleted += 1
            example["drift"] = "deleted since export"
        else:
            out.drift_changed += 1
            example["drift"] = "changed since export"
            example["columns"] = column_diff(s.block.columns, line, got)
        if len(out.examples) < max_examples:
            out.examples.append(example)
    out.compared = out.matched + out.drift_changed + out.drift_deleted


def _source_table(
    conn: psycopg.Connection, s: TableSample, d: DrillTable, max_examples: int
) -> SourceTable:
    out = SourceTable(table=s.block.table, excluded=d.sampled - len(d.clean_lines))
    parts = _parts(s.block.table)
    oid = _live_oid(conn, parts)
    if oid is None:
        out.status, out.detail = "no_table", "table does not exist in the source database"
        return out
    pk = [(str(n), str(t)) for n, t in conn.execute(PK_SQL, [oid]).fetchall()]
    out.primary_key = [n for n, _ in pk]
    if not pk or any(n not in s.block.columns for n, _ in pk):
        out.status, out.detail = "no_pk", "live table has no primary key among the dumped columns"
        return out
    positions = [s.block.columns.index(n) for n, _ in pk]
    clean = set(d.clean_lines)
    keys = [_key(line, positions) for lineno, line in s.rows if lineno in clean]
    if any(NULL.encode() in k for k in keys):
        out.status, out.detail = "error", "NULL in a primary-key field of a sampled row"
        return out
    try:
        with conn.transaction():
            live = _fetch_live(conn, parts, s.block.columns, pk, keys) if keys else {}
    except psycopg.Error as exc:
        out.status, out.detail = "error", first_line(exc)
        return out
    _compare(s, d, live, positions, out, max_examples)
    return out


def compare_source(
    samples: list[TableSample], drill: DrillResult, dsn: str, policy: dict[str, Any]
) -> list[SourceTable]:
    l5 = policy["l5"]
    with connect(dsn) as conn:
        conn.read_only = True
        with conn.transaction():
            apply_session(conn, l5)
            return [
                _source_table(conn, s, d, l5["max_examples"])
                if d.status in ("ok", "empty")
                else SourceTable(
                    table=s.block.table, status="skipped", detail=f"not restored ({d.status})"
                )
                for s, d in zip(samples, drill.tables, strict=True)
            ]
