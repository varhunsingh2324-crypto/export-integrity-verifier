"""L3 row validity (IMPLEMENTATION_PLAN §4): every row, not a sample.

Per row: strict UTF-8, field count vs the COPY header, COPY text escapes, NOT NULL, and a type parse
per column from the CREATE TABLE in the same dump. Primary-key uniqueness uses candidate tracking:
pg_dump declares the PRIMARY KEY after the data, so every NOT NULL column is tracked
(sketches.KeyTracker) until the declaration resolves which one is the key.
"""

import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable
from datetime import date, datetime
from typing import Any

from eguard.models import (
    CheckResult,
    CopyBlock,
    DumpStructure,
    Severity,
    Status,
    TableDef,
)
from eguard.parsers.pg_plain import COMPLETE
from eguard.sketches import KeyTracker

LAYER = 3
NULL = "\\N"
VALUE_SHOWN = 80
Validator = Callable[[str], str | None]  # raw COPY field -> error reason, or None if valid

SIMPLE_ESCAPES = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\"}
ESCAPE_RE = re.compile(r"\\([bfnrtv\\]|[0-7]{1,3}|x[0-9A-Fa-f]{1,2}|.|$)", re.S)
INT_RE = re.compile(r"-?[0-9]+")
NUMERIC_RE = re.compile(r"-?([0-9]*)(?:\.([0-9]*))?")
DATE_RE = re.compile(r"([0-9]{4,})-[0-9]{2}-[0-9]{2}( BC)?")
TS_RE = re.compile(
    r"([0-9]{4,})-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?"
    r"([+-][0-9]{2}(?::?[0-9]{2}){0,2})?( BC)?"
)
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
BYTEA_RE = re.compile(r"\\x(?:[0-9a-f]{2})*")
INFINITIES = {"infinity", "-infinity"}
INT_RANGES = {
    "smallint": 16,
    "int2": 16,
    "integer": 32,
    "int": 32,
    "int4": 32,
    "bigint": 64,
    "int8": 64,
}


def escape_error(field: str) -> str | None:
    """COPY text-format escapes. pg_dump writes only the simple ones; octal/hex are legal input."""
    for m in ESCAPE_RE.finditer(field):
        g = m.group(1)
        if g == "":
            return "trailing backslash"
        if g in SIMPLE_ESCAPES or g[0] in "01234567" or (g[0] == "x" and len(g) > 1):
            continue
        return f"invalid escape '\\{g}'"
    return None


def unescape(field: str) -> str:
    """Decode COPY escapes; octal/hex bytes must form valid UTF-8 (ValueError otherwise)."""
    if "\\" not in field:
        return field
    out = bytearray()
    pos = 0
    for m in ESCAPE_RE.finditer(field):
        out += field[pos : m.start()].encode()
        g = m.group(1)
        if g in SIMPLE_ESCAPES:
            out += SIMPLE_ESCAPES[g].encode()
        elif g and g[0] == "x" and len(g) > 1:
            out.append(int(g[1:], 16))
        elif g and g[0] in "01234567":
            out.append(int(g, 8) & 0xFF)
        else:
            raise ValueError(f"invalid escape '\\{g}'")
        pos = m.end()
    out += field[pos:].encode()
    text = out.decode()  # UnicodeDecodeError is a ValueError
    if "\0" in text:
        raise ValueError("NUL byte in value")
    return text


def _int(bits: int) -> Validator:
    lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1

    def check(f: str) -> str | None:
        if not INT_RE.fullmatch(f):
            return "not an integer"
        return None if lo <= int(f) <= hi else f"out of range for {bits}-bit integer"

    return check


def _numeric(precision: int | None, scale: int | None) -> Validator:
    def check(f: str) -> str | None:
        if f in ("NaN", "Infinity", "-Infinity"):
            return None
        m = NUMERIC_RE.fullmatch(f)
        if not m or not (m.group(1) or m.group(2)):
            return "not a numeric"
        whole, frac = m.group(1).lstrip("0"), m.group(2) or ""
        if scale is not None and len(frac) > scale:
            return f"more than {scale} decimal places"
        if precision is not None and len(whole) > precision - (scale or 0):
            return f"exceeds numeric({precision},{scale or 0})"
        return None

    return check


def _float(f: str) -> str | None:
    try:
        float(f)
    except ValueError:
        return "not a float"
    return None


def _bool(f: str) -> str | None:
    return None if f in ("t", "f") else "not a boolean (t/f)"


def _date(f: str) -> str | None:
    if f in INFINITIES:
        return None
    m = DATE_RE.fullmatch(f)
    if not m:
        return "not a date"
    if len(m.group(1)) == 4:
        try:
            date.fromisoformat(f[:10])
        except ValueError:
            return "invalid calendar date"
    return None


def _timestamp(f: str) -> str | None:
    if f in INFINITIES:
        return None
    m = TS_RE.fullmatch(f)
    if not m:
        return "not a timestamp"
    if len(m.group(1)) == 4:
        core = f[: m.end(2) if m.group(2) else (m.start(3) if m.group(3) else len(f))]
        try:
            datetime.fromisoformat(core)
        except ValueError:
            return "invalid timestamp"
    return None


def _chars(limit: int | None) -> Validator:
    def check(f: str) -> str | None:
        if limit is not None and len(unescape(f)) > limit:
            return f"longer than {limit} characters"
        return None

    return check


def _reject_constant(name: str) -> None:
    raise ValueError(f"{name} is not valid JSON")


def _json(f: str) -> str | None:
    try:
        json.loads(unescape(f), parse_constant=_reject_constant)
    except ValueError:
        return "invalid JSON"
    return None


def _uuid(f: str) -> str | None:
    return None if UUID_RE.fullmatch(f.lower()) else "not a uuid"


def _bytea(f: str) -> str | None:
    return None if BYTEA_RE.fullmatch(unescape(f)) else "not hex bytea"


def _text(f: str) -> str | None:
    return None


def validator_for(type_text: str) -> Validator | None:
    """Validator for a DDL type as pg_dump prints it; None = not validated beyond escapes/UTF-8."""
    t = re.sub(r"\s+", " ", type_text.strip().lower())
    m = re.fullmatch(r"([a-z ]+?)(?: ?\(([0-9]+)(?:, ?([0-9]+))?\))?", t)
    if not m:
        return None  # arrays, user types, ...
    base = m.group(1).strip()
    p = int(m.group(2)) if m.group(2) else None
    s = int(m.group(3)) if m.group(3) else None
    if base in INT_RANGES:
        return _int(INT_RANGES[base])
    if base in ("numeric", "decimal"):
        return _numeric(p, s if p is not None else None)
    if base in ("real", "double precision", "float4", "float8"):
        return _float
    if base in ("boolean", "bool"):
        return _bool
    if base == "date":
        return _date
    if base.startswith("timestamp"):
        return _timestamp
    if base in ("character", "char", "character varying", "varchar"):
        return _chars(p)
    if base == "text":
        return _text
    if base in ("json", "jsonb"):
        return _json
    if base == "uuid":
        return _uuid
    if base == "bytea":
        return _bytea
    return None


class _Block:
    """Per COPY block: column plan built once, used for every row."""

    def __init__(self, block: CopyBlock, table: TableDef | None) -> None:
        self.block = block
        self.ncols = len(block.columns)
        defs = {c.name: c for c in table.columns} if table else {}
        self.not_null = [bool(defs.get(n) and defs[n].not_null) for n in block.columns]
        self.validators = [
            validator_for(defs[n].type) if n in defs else None for n in block.columns
        ]
        self.unvalidated = [
            f"{n} ({defs[n].type if n in defs else 'no DDL'})"
            for n, v in zip(block.columns, self.validators, strict=True)
            if v is None
        ]
        self.keys: list[tuple[int, KeyTracker]] = []


class RowValidator:
    """Parser listener (parsers.pg_plain.DumpListener) doing L3 for every row."""

    def __init__(self, policy: dict[str, Any]) -> None:
        l3 = policy["l3"]
        self.max_error_rate = l3["max_error_rate"]
        self.max_examples = l3["max_error_examples"]
        self._tracker_args = (
            l3["pk_set_limit"],
            l3["pk_bloom_bytes"],
            l3["pk_bloom_hashes"],
            l3["pk_candidate_prune_dups"],
            self.max_examples,
        )
        self.rows = 0
        self.invalid = 0
        self.by_reason: Counter[str] = Counter()
        self.by_table: Counter[str] = Counter()
        self.examples: list[dict[str, Any]] = []
        self.unvalidated: dict[str, list[str]] = {}
        self.trackers: dict[tuple[str, str], KeyTracker] = {}
        self.structure: DumpStructure | None = None
        self._cur: _Block | None = None

    def on_copy_start(self, block: CopyBlock, table: TableDef | None) -> None:
        cur = _Block(block, table)
        if cur.unvalidated:
            self.unvalidated[block.table] = cur.unvalidated
        for i, name in enumerate(block.columns):
            if cur.not_null[i]:
                key = (block.table, name)
                if key not in self.trackers:
                    self.trackers[key] = KeyTracker(*self._tracker_args)
                cur.keys.append((i, self.trackers[key]))
        self._cur = cur

    def on_copy_end(self, block: CopyBlock) -> None:
        self._cur = None

    def _error(self, lineno: int, column: str | None, reason: str, value: str) -> None:
        self.invalid += 1
        self.by_reason[reason.split(":")[0]] += 1
        assert self._cur is not None
        self.by_table[self._cur.block.table] += 1
        if len(self.examples) < self.max_examples:
            self.examples.append(
                {
                    "line": lineno,
                    "table": self._cur.block.table,
                    "column": column,
                    "reason": reason,
                    "value": value[:VALUE_SHOWN],
                }
            )

    def on_row(self, block: CopyBlock, line: bytes, lineno: int) -> None:
        self.rows += 1
        cur = self._cur
        assert cur is not None
        try:
            text = line.decode()
        except UnicodeDecodeError as exc:
            self._error(lineno, None, f"utf8: invalid UTF-8 at byte {exc.start}", repr(line))
            return
        fields = text.split("\t")
        if len(fields) != cur.ncols:
            self._error(
                lineno, None, f"field_count: {len(fields)} fields, expected {cur.ncols}", text
            )
            return
        if "\r" in text or "\0" in text:
            self._error(lineno, None, "control_char: raw CR or NUL in row", text)
            return
        if self._fields_error(cur, fields, lineno):
            return
        for i, tracker in cur.keys:
            if not tracker.pruned:
                f = fields[i]
                h = hashlib.blake2b(f.encode(), digest_size=8).digest()
                tracker.add(int.from_bytes(h, "little"), lineno, f[:VALUE_SHOWN])

    def _fields_error(self, cur: _Block, fields: list[str], lineno: int) -> bool:
        cols = cur.block.columns
        for i, f in enumerate(fields):
            if f == NULL:
                if cur.not_null[i]:
                    self._error(lineno, cols[i], "not_null: NULL in NOT NULL column", f)
                    return True
                continue
            if "\\" in f and (err := escape_error(f)):
                self._error(lineno, cols[i], f"escape: {err}", f)
                return True
            v = cur.validators[i]
            try:
                err = v(f) if v else None
            except ValueError as exc:  # unescape() of octal/hex that is not UTF-8, NUL
                err = str(exc)
            if err:
                self._error(lineno, cols[i], f"type: {err}", f)
                return True
        return False

    def on_finish(self, structure: DumpStructure) -> None:
        self.structure = structure


def check_row_validity(v: RowValidator) -> CheckResult:
    s = v.structure
    rate = v.invalid / v.rows if v.rows else 0.0
    evidence: dict[str, Any] = {
        "rows_checked": v.rows,
        "invalid_rows": v.invalid,
        "error_rate": rate,
        "max_error_rate": v.max_error_rate,
        "by_reason": dict(v.by_reason),
        "by_table": dict(v.by_table),
        "examples": v.examples,
        "unvalidated_columns": v.unvalidated,
        "partial_row_bytes_not_checked": s.partial_line_bytes if s and s.state != COMPLETE else 0,
    }

    def result(status: Status, message: str) -> CheckResult:
        return CheckResult(
            layer=LAYER,
            name="l3_row_validity",
            status=status,
            severity=Severity.CRITICAL,
            evidence=evidence,
            message=message,
        )

    if not v.rows:
        return result(Status.SKIP, "no COPY rows to validate")
    if v.invalid and rate > v.max_error_rate:
        first = v.examples[0]
        return result(
            Status.FAIL,
            f"{v.invalid:,} of {v.rows:,} rows invalid ({dict(v.by_reason)}); first at line "
            f"{first['line']:,} in {first['table']}"
            + (f".{first['column']}" if first["column"] else "")
            + f": {first['reason']}",
        )
    if v.unvalidated:
        return result(
            Status.WARN,
            f"{v.rows:,} rows valid, but column type(s) not validated: {v.unvalidated}",
        )
    return result(
        Status.PASS,
        f"all {v.rows:,} rows valid: field count, UTF-8, COPY escapes, NOT NULL, types",
    )


def _pk_table(v: RowValidator, table: TableDef, complete: bool) -> dict[str, Any]:
    pk = table.primary_key
    if pk is None:
        why = "no PRIMARY KEY declared" if complete else "PRIMARY KEY declaration not reached"
        return {"status": "SKIP", "reason": why}
    if len(pk) > 1:
        return {"status": "SKIP", "pk": pk, "reason": "composite key not tracked"}
    tracker = v.trackers.get((table.name, pk[0]))
    if tracker is None:
        return {"status": "SKIP", "pk": pk, "reason": "key column not NOT NULL in COPY data"}
    stats = tracker.result()
    return {"status": "FAIL" if stats["duplicates"] else "PASS", "pk": pk} | stats


def check_pk_unique(v: RowValidator) -> CheckResult:
    s = v.structure
    complete = s is not None and s.state == COMPLETE
    copied = {b.table for b in s.copies} if s else set()
    tables = {
        name: _pk_table(v, t, complete)
        for name, t in (s.tables.items() if s else [])
        if name in copied
    }
    for tracker in v.trackers.values():
        tracker.close()
    fails = {n: r for n, r in tables.items() if r["status"] == "FAIL"}
    skips = {n: r for n, r in tables.items() if r["status"] == "SKIP"}
    evidence: dict[str, Any] = {"tables": tables}
    if fails:
        name, r = next(iter(fails.items()))
        ex = r["examples"][0] if r["examples"] else {}
        scope = (
            f"≥{r['duplicates']:,} duplicate {r['pk'][0]} value(s) (counting stops at "
            f"l3.pk_candidate_prune_dups: the key is declared only after the data)"
            if r["lower_bound"]
            else f"{r['duplicates']:,} duplicate {r['pk'][0]} value(s) among {r['keys']:,} rows"
        )
        status, message = (
            Status.FAIL,
            f"{name}: {scope}; first duplicate at line {ex.get('line', 0):,} "
            f"({r['pk'][0]} = {ex.get('value')})",
        )
    elif skips or not tables:
        status = Status.SKIP
        reasons = {n: r["reason"] for n, r in skips.items()}
        message = f"PK uniqueness not established: {reasons or 'no tables with data'}"
    else:
        status = Status.PASS
        message = "; ".join(
            f"{n}: {r['keys']:,} unique {', '.join(r['pk'])} ({r['mode']})"
            for n, r in tables.items()
        )
    return CheckResult(
        layer=LAYER,
        name="l3_pk_unique",
        status=status,
        severity=Severity.CRITICAL,
        evidence=evidence,
        message=message,
    )


def check_rows(v: RowValidator) -> list[CheckResult]:
    return [check_row_validity(v), check_pk_unique(v)]
