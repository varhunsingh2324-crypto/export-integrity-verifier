"""L5 restore drill (IMPLEMENTATION_PLAN §4): restore the sample into a throwaway scratch schema.

Per sampled COPY block, inside one transaction on SCRATCH_DSN:
  1. CREATE SCHEMA eguard_l5_<epoch>_<hex>; the dump's own CREATE TABLE, renamed into it
  2. COPY ... FROM STDIN with the sampled raw lines (the path a real restore takes); on error each
     row is retried in its own savepoint to name every rejected line; then the dump's PRIMARY KEY
  3. round trip: COPY the table back out in insertion order (ORDER BY ctid on a fresh heap) and
     compare each row hash with its dump line. pg_dump writes canonical text, so a byte difference
     means PostgreSQL stored something other than what the dump line says
The transaction is rolled back and the schema dropped in `finally` (confirmed via pg_namespace),
so nothing survives even a kill. Leftover eguard_l5_* schemas older than policy
l5.stale_scratch_seconds are dropped first.

Session settings follow pg_dump's (DateStyle ISO, IntervalStyle postgres, extra_float_digits 3,
search_path ''), plus TimeZone from policy l5.timezone: timestamptz text depends on it, so a dump
taken in another zone shows up as round-trip differences (a documented limitation).
"""

import re
import secrets
import time
from collections.abc import Callable, Iterable
from typing import Any

import psycopg
from psycopg import sql

from eguard.fingerprint import row_hash
from eguard.models import DrillResult, DrillTable, TableDef
from eguard.parsers.pg_plain import CREATE_RE
from eguard.sampler import TableSample

SCRATCH_PREFIX = "eguard_l5_"
SCRATCH_RE = re.compile(r"eguard_l5_([0-9]+)_[0-9a-f]{8}")
VALUE_SHOWN = 80
DOLLAR_QUOTE_RE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$")


def scratch_name(now: float) -> str:
    return f"{SCRATCH_PREFIX}{int(now)}_{secrets.token_hex(4)}"


def sweep_stale(conn: psycopg.Connection, now: float, max_age: float) -> list[str]:
    """Drop eguard scratch schemas whose name says they are older than max_age seconds."""
    rows = conn.execute(
        "SELECT nspname FROM pg_namespace WHERE nspname LIKE %s", ["eguard\\_l5\\_%"]
    ).fetchall()
    stale = sorted(
        name
        for (name,) in rows
        if (m := SCRATCH_RE.fullmatch(name)) and now - int(m.group(1)) > max_age
    )
    for name in stale:
        conn.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(name)))
    return stale


def _skip_quoted(text: str, i: int, quote: str, backslash: bool) -> int:
    """Index just past the closing quote of a literal/identifier opened at text[i]."""
    j = i + 1
    while j < len(text):
        c = text[j]
        if backslash and c == "\\":
            j += 2
            continue
        if c == quote:
            if text[j + 1 : j + 2] == quote:  # doubled quote inside
                j += 2
                continue
            return j + 1
        j += 1
    return j


def single_statement(text: str) -> bool:
    """True if `text` is one SQL statement: no `;` outside quotes/comments except a final one,
    and no dollar quoting (whose body this scanner does not tokenise)."""
    i, end_seen = 0, False
    while i < len(text):
        c = text[i]
        if c.isspace():
            i += 1
            continue
        if text.startswith("--", i):
            nl = text.find("\n", i)
            i = len(text) if nl < 0 else nl + 1
            continue
        if text.startswith("/*", i):
            close = text.find("*/", i + 2)
            i = len(text) if close < 0 else close + 2
            continue
        if end_seen:
            return False  # something after the terminating `;`
        if c == ";":
            end_seen = True
            i += 1
        elif c in "'\"":
            escape = c == "'" and i > 0 and text[i - 1] in "Ee"
            i = _skip_quoted(text, i, c, escape)
        elif c == "$" and DOLLAR_QUOTE_RE.match(text, i) and not text[i - 1 : i].isalnum():
            return False
        else:
            i += 1
    return True


def scratch_ddl(table: TableDef, schema: str, name: str) -> str | None:
    """The dump's CREATE TABLE with only the table name replaced by schema.name, or None if the
    statement is missing, unparseable or not a single plain statement (then it is not executed)."""
    if table.ddl is None or not single_statement(table.ddl):
        return None
    m = CREATE_RE.match(table.ddl)
    if m is None:
        return None
    target = f'"{schema}"."{name}"'  # both generated: [a-z0-9_] only
    return table.ddl[: m.start(1)] + target + table.ddl[m.end(1) :]


def apply_session(conn: psycopg.Connection, l5: dict[str, Any]) -> None:
    """pg_dump's output settings, transaction-local."""
    settings = {
        "DateStyle": "ISO",
        "IntervalStyle": "postgres",
        "extra_float_digits": "3",
        "search_path": "",
        "TimeZone": str(l5["timezone"]),
        "statement_timeout": str(int(l5["statement_timeout_ms"])),
    }
    for name, value in settings.items():
        conn.execute("SELECT set_config(%s, %s, true)", [name, value])


def first_line(exc: Exception) -> str:
    return (str(exc).strip().splitlines() or [type(exc).__name__])[0]


def _copy_in(conn: psycopg.Connection, stmt: sql.Composed, lines: Iterable[bytes]) -> None:
    with conn.cursor() as cur, cur.copy(stmt) as cp:
        for line in lines:
            cp.write(line + b"\n")


def _load(
    conn: psycopg.Connection,
    target: sql.Composed,
    cols: sql.Composed,
    rows: list[tuple[int, bytes]],
    t: DrillTable,
    max_examples: int,
) -> list[tuple[int, bytes]]:
    """COPY the sampled lines in; returns the rows that loaded, in load order."""
    stmt = sql.SQL("COPY {} ({}) FROM STDIN").format(target, cols)
    try:
        with conn.transaction():
            _copy_in(conn, stmt, (line for _, line in rows))
        return rows
    except psycopg.Error:
        pass  # find every rejected line, one savepoint per row
    loaded: list[tuple[int, bytes]] = []
    for lineno, line in rows:
        try:
            with conn.transaction():
                _copy_in(conn, stmt, [line])
            loaded.append((lineno, line))
        except psycopg.Error as exc:
            t.rejected_count += 1
            if len(t.rejected) < max_examples:
                t.rejected.append({"line": lineno, "error": first_line(exc), "value": _short(line)})
    return loaded


def _short(data: bytes) -> str:
    return data[:VALUE_SHOWN].decode("utf-8", "replace")


def _add_pk(conn: psycopg.Connection, target: sql.Composed, pk: list[str]) -> str | None:
    stmt = sql.SQL("ALTER TABLE {} ADD PRIMARY KEY ({})").format(
        target, sql.SQL(", ").join(map(sql.Identifier, pk))
    )
    try:
        with conn.transaction():
            conn.execute(stmt)
    except psycopg.Error as exc:
        return first_line(exc)
    return None


def _copy_out(conn: psycopg.Connection, target: sql.Composed, cols: sql.Composed) -> list[bytes]:
    stmt = sql.SQL("COPY (SELECT {} FROM {} ORDER BY ctid) TO STDOUT").format(cols, target)
    with conn.cursor() as cur, cur.copy(stmt) as cp:
        data = b"".join(bytes(chunk) for chunk in cp)
    return data.split(b"\n")[:-1] if data else []


def column_diff(columns: list[str], a: bytes, b: bytes) -> list[dict[str, str]]:
    fa, fb = a.split(b"\t"), b.split(b"\t")
    if len(fa) != len(fb):
        return [{"column": "*", "dump": _short(a), "restored": _short(b)}]
    return [
        {"column": name, "dump": _short(x), "restored": _short(y)}
        for name, x, y in zip(columns, fa, fb, strict=True)
        if x != y
    ]


def _round_trip(
    conn: psycopg.Connection,
    target: sql.Composed,
    cols: sql.Composed,
    loaded: list[tuple[int, bytes]],
    t: DrillTable,
    columns: list[str],
    max_examples: int,
) -> None:
    out = _copy_out(conn, target, cols)
    t.round_tripped = len(out)
    if len(out) != len(loaded):  # cannot pair rows: every loaded row is unproven
        t.mismatched_count = len(loaded)
        t.detail = f"{len(loaded)} rows loaded but {len(out)} came back"
        return
    for (lineno, line), back in zip(loaded, out, strict=True):
        if row_hash(line) == row_hash(back):
            t.clean_lines.append(lineno)
            continue
        t.mismatched_count += 1
        if len(t.mismatched) < max_examples:
            t.mismatched.append({"line": lineno, "columns": column_diff(columns, line, back)})


def _scratch_bytes(conn: psycopg.Connection, schema: str, name: str) -> int:
    row = conn.execute(
        "SELECT pg_total_relation_size(c.oid) FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = %s AND c.relname = %s",
        [schema, name],
    ).fetchone()
    return int(row[0]) if row else 0


def _drill_table(
    conn: psycopg.Connection, s: TableSample, schema: str, name: str, max_examples: int
) -> DrillTable:
    rows = s.rows
    t = DrillTable(
        table=s.block.table, scratch_table=f"{schema}.{name}", seen=s.seen, sampled=len(rows)
    )
    if not rows:
        t.status = "empty"
        return t
    if s.table is None or s.table.ddl is None:
        t.status, t.detail = "no_ddl", "no complete CREATE TABLE for this COPY block in the dump"
        return t
    ddl = scratch_ddl(s.table, schema, name)
    if ddl is None:
        t.status, t.detail = "ddl_refused", "CREATE TABLE is not a single plain statement"
        return t
    try:
        with conn.transaction():
            conn.execute(ddl.encode())
    except psycopg.Error as exc:
        t.status, t.detail = "ddl_error", first_line(exc)
        return t
    target = sql.Identifier(schema, name)
    cols = sql.SQL(", ").join(map(sql.Identifier, s.block.columns))
    loaded = _load(conn, target, cols, rows, t, max_examples)
    t.restored = len(loaded)
    if s.table.primary_key:
        t.pk_error = _add_pk(conn, target, s.table.primary_key)
    _round_trip(conn, target, cols, loaded, t, s.block.columns, max_examples)
    t.scratch_bytes = _scratch_bytes(conn, schema, name)
    return t


def _drop(dsn: str, conn: psycopg.Connection, schema: str) -> bool:
    """DROP the scratch schema and confirm it is gone (reconnect if the session broke)."""
    c = conn if not (conn.closed or conn.broken) else psycopg.connect(dsn, autocommit=True)
    try:
        c.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema)))
        gone = c.execute("SELECT 1 FROM pg_namespace WHERE nspname = %s", [schema]).fetchone()
        return gone is None
    finally:
        if c is not conn:
            c.close()


def connect(dsn: str) -> psycopg.Connection:
    return psycopg.connect(dsn, connect_timeout=10, autocommit=True, client_encoding="utf8")


def run_drill(
    samples: list[TableSample],
    dsn: str,
    policy: dict[str, Any],
    now: Callable[[], float] = time.time,
) -> DrillResult:
    l5 = policy["l5"]
    started = time.monotonic()
    with connect(dsn) as conn:
        stale = sweep_stale(conn, now(), l5["stale_scratch_seconds"])
        result = DrillResult(schema_name=scratch_name(now()), stale_dropped=stale)
        schema = result.schema_name
        try:
            with conn.transaction() as tx:
                apply_session(conn, l5)
                conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
                for i, s in enumerate(samples, 1):
                    result.tables.append(_drill_table(conn, s, schema, f"t{i}", l5["max_examples"]))
                result.scratch_bytes = sum(t.scratch_bytes for t in result.tables)
                raise psycopg.Rollback(tx)  # nothing of the drill is ever committed
        finally:
            result.dropped = _drop(dsn, conn, schema)
    result.seconds = round(time.monotonic() - started, 3)
    return result
