"""PostgreSQL plain-format dump grammar (IMPLEMENTATION_PLAN §4 L2) as a streaming state machine.

    PREAMBLE -> BODY <-> COPY_ROWS -> COMPLETE

PREAMBLE ends at `-- PostgreSQL database dump`. In BODY, lines are gathered into SQL statements up
to a line ending in `;`; only CREATE TABLE, ALTER TABLE ... PRIMARY KEY and COPY ... FROM stdin are
interpreted. In COPY_ROWS every line is a row until `\\.`. COMPLETE starts at
`-- PostgreSQL database dump complete`. psql meta-commands (`\\restrict`/`\\unrestrict`, written by
pg_dump >= 16.10, and `\\connect`) are single lines.

The parser holds one line of lookahead so it knows whether the final line had a newline: an
unterminated final line inside COPY is a partial row (an exporter killed mid-write) and is
recorded, not handed to row listeners.

Limitation: dollar-quoted bodies (functions) are not tokenised; a body line ending in `;` ends the
gathered statement early. That cannot hide a COPY block or the markers, which are matched per line.
"""

import re
from typing import Protocol

from eguard.models import ColumnDef, CopyBlock, DumpStructure, StreamEnd, TableDef
from eguard.stream import Consumer

DUMP_HEADER = b"-- PostgreSQL database dump"
DUMP_COMPLETE = b"-- PostgreSQL database dump complete"
COPY_END = b"\\."
MAX_STATEMENT_CHARS = 1 << 20  # statement text kept for parsing; longer bodies are cut (bounded)
MAX_EVIDENCE_CHARS = 200
AFTER_COMPLETE_KEPT = 5

PREAMBLE, BODY, COPY_ROWS, COMPLETE = "PREAMBLE", "BODY", "COPY_ROWS", "COMPLETE"

_IDENT = r'(?:"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)'
_QUALIFIED = rf"{_IDENT}(?:\.{_IDENT})*"
COPY_RE = re.compile(rf"^COPY\s+({_QUALIFIED})\s*(?:\((.*)\))?\s+FROM\s+stdin;$", re.S)
CREATE_RE = re.compile(rf"^CREATE\s+(?:UNLOGGED\s+)?TABLE\s+({_QUALIFIED})\s*\((.*)$", re.S)
PK_RE = re.compile(
    rf"^ALTER\s+TABLE\s+(?:ONLY\s+)?({_QUALIFIED})\s+ADD\s+CONSTRAINT\s+{_IDENT}\s+"
    r"PRIMARY\s+KEY\s*\((.*?)\)",
    re.S,
)
COLUMN_RE = re.compile(rf"^\s*({_IDENT})\s+(.+?)\s*,?\s*$")
TYPE_END_RE = re.compile(r"\s+(?:NOT\s+NULL|NULL|DEFAULT|COLLATE|GENERATED|CONSTRAINT|CHECK)\b")
NOT_CONSTRAINT = ("CONSTRAINT ", "CHECK ", "UNIQUE ", "PRIMARY KEY", "EXCLUDE ", "FOREIGN KEY")


class DumpListener(Protocol):
    """Row-level subscriber (L3). Called per row on the hot path: keep it cheap."""

    def on_copy_start(self, block: CopyBlock, table: TableDef | None) -> None: ...

    def on_row(self, block: CopyBlock, line: bytes, lineno: int) -> None: ...

    def on_copy_end(self, block: CopyBlock) -> None: ...

    def on_finish(self, structure: DumpStructure) -> None: ...


def split_idents(text: str) -> list[str]:
    """Split a comma-separated identifier list, honouring "quoted, names"."""
    return [m.group(0) for m in re.finditer(_IDENT, text)]


def unquote(ident: str) -> str:
    return ident[1:-1].replace('""', '"') if ident.startswith('"') else ident


def parse_columns(body: str) -> list[ColumnDef]:
    """Column lines between `CREATE TABLE x (` and the closing `)` (one column per line)."""
    cols: list[ColumnDef] = []
    for raw in body.split("\n"):
        line = raw.strip()
        if not line or line.startswith(")") or line.upper().startswith(NOT_CONSTRAINT):
            continue
        m = COLUMN_RE.match(line)
        if not m:
            continue
        rest = m.group(2)
        end = TYPE_END_RE.search(" " + rest)
        type_text = (rest if end is None else (" " + rest)[: end.start()]).strip()
        cols.append(
            ColumnDef(
                name=unquote(m.group(1)),
                type=type_text,
                not_null=bool(re.search(r"\bNOT\s+NULL\b", rest)),
            )
        )
    return cols


def _short(text: str) -> str:
    return text if len(text) <= MAX_EVIDENCE_CHARS else text[:MAX_EVIDENCE_CHARS] + "..."


class PgPlainParser(Consumer):
    def __init__(self) -> None:
        self.s = DumpStructure(state=PREAMBLE)
        self.listeners: list[DumpListener] = []
        self.block: CopyBlock | None = None
        self._held: tuple[bytes, int] | None = None
        self._stmt: list[str] = []
        self._stmt_len = 0
        self._stmt_line = 0

    def add_listener(self, listener: DumpListener) -> None:
        self.listeners.append(listener)

    # -- Consumer -------------------------------------------------------------------------
    def on_line(self, line: bytes, lineno: int) -> None:
        if self._held is not None:
            self._process(*self._held)
        self._held = (line, lineno)

    def on_end(self, end: StreamEnd) -> None:
        if self._held is not None:
            line, lineno = self._held
            if end.unterminated_tail:
                self._partial(line, lineno)
            else:
                self._process(line, lineno)
        self.s.lines = end.lines
        if self._stmt:
            self.s.open_statement = _short("\n".join(self._stmt))
        for listener in self.listeners:
            listener.on_finish(self.s)

    # -- state machine --------------------------------------------------------------------
    def _partial(self, line: bytes, lineno: int) -> None:
        self.s.partial_line_bytes = len(line)
        self.s.last_line = _short(line.decode("utf-8", "replace"))
        if self.s.state != COPY_ROWS:
            self._process(line, lineno)  # outside COPY a cut line is still grammar to check

    def _process(self, line: bytes, lineno: int) -> None:
        if self.s.state == COPY_ROWS:
            self._copy_line(line, lineno)
            return
        self.s.last_line = _short(line.decode("utf-8", "replace"))
        if self.s.state == COMPLETE:
            self._after_complete(line, lineno)
        elif self.s.state == PREAMBLE:
            self._preamble(line, lineno)
        else:
            self._body(line, lineno)

    def _copy_line(self, line: bytes, lineno: int) -> None:
        block = self.block
        assert block is not None
        if line == COPY_END:
            block.closed, block.end_line = True, lineno
            self.s.state = BODY
            self.block = None
            for listener in self.listeners:
                listener.on_copy_end(block)
            return
        block.rows += 1
        block.bytes += len(line) + 1
        if block.first_row_line is None:
            block.first_row_line = lineno
        block.last_row_line = lineno
        for listener in self.listeners:
            listener.on_row(block, line, lineno)

    def _preamble(self, line: bytes, lineno: int) -> None:
        if line == DUMP_HEADER:
            self.s.header_line = lineno
            self.s.state = BODY
        elif line.strip() and not line.startswith(b"--"):
            self.s.state = BODY  # no header: keep parsing so later layers still see the data
            self._body(line, lineno)

    def _meta(self, text: str, lineno: int) -> bool:
        """psql meta-command lines (single line, never part of a SQL statement)."""
        if not text.startswith("\\"):
            return False
        word, _, arg = text.partition(" ")
        if word == "\\restrict":
            self.s.restrict_key = arg.strip()
        elif word == "\\unrestrict":
            self.s.unrestrict_key = arg.strip()
        elif word == "\\.":
            self.s.stray_terminators.append(lineno)
        return True

    def _body(self, line: bytes, lineno: int) -> None:
        if line == DUMP_COMPLETE:
            self.s.complete_line = lineno
            self.s.state = COMPLETE
            return
        text = line.decode("utf-8", "replace")
        if not self._stmt:
            if not text.strip() or text.startswith("--"):
                self._comment(text)
                return
            if self._meta(text, lineno):
                return
            self._stmt_line = lineno
        if self._stmt_len < MAX_STATEMENT_CHARS:
            self._stmt.append(text)
            self._stmt_len += len(text) + 1
        if text.rstrip().endswith(";"):
            stmt = "\n".join(self._stmt)
            self._stmt, self._stmt_len = [], 0
            self._statement(stmt, self._stmt_line)

    def _comment(self, text: str) -> None:
        for prefix, attr in (("-- Dumped from ", "dumped_from"), ("-- Dumped by ", "dumped_by")):
            if text.startswith(prefix):
                setattr(self.s, attr, text[len(prefix) :].strip())

    def _statement(self, stmt: str, lineno: int) -> None:
        head = stmt.lstrip()[:32].upper()
        if head.startswith("COPY "):
            self._copy_header(stmt.strip(), lineno)
        elif head.startswith(("CREATE TABLE ", "CREATE UNLOGGED TABLE ")):
            self._create_table(stmt, lineno)
        elif head.startswith("ALTER TABLE ") and "PRIMARY KEY" in stmt:
            m = PK_RE.match(stmt.strip())
            if m and (table := self.s.tables.get(m.group(1))) is not None:
                table.primary_key = [unquote(c) for c in split_idents(m.group(2))]

    def _create_table(self, stmt: str, lineno: int) -> None:
        m = CREATE_RE.match(stmt.strip())
        if not m:
            return
        name, rest = m.group(1), m.group(2)
        close = rest.rfind("\n)")
        body = rest if close < 0 else rest[:close]
        self.s.tables[name] = TableDef(
            name=name,
            columns=parse_columns(body),
            line=lineno,
            has_data="PARTITION BY" not in rest[close:].upper(),
        )

    def _copy_header(self, stmt: str, lineno: int) -> None:
        m = COPY_RE.match(stmt)
        if not m:
            if stmt.upper().endswith("FROM STDIN;"):
                # Data follows even though we could not read the header: still a COPY block.
                self.s.bad_copy_headers.append({"line": lineno, "text": _short(stmt)})
                self._open_block(CopyBlock(table="?", columns=[], header_line=lineno))
            return
        cols = [unquote(c) for c in split_idents(m.group(2))] if m.group(2) else []
        table = self.s.tables.get(m.group(1))
        if not cols and table is not None:
            cols = [c.name for c in table.columns]
        self._open_block(CopyBlock(table=m.group(1), columns=cols, header_line=lineno))

    def _open_block(self, block: CopyBlock) -> None:
        self.block = block
        self.s.copies.append(block)
        self.s.state = COPY_ROWS
        table = self.s.tables.get(block.table)
        for listener in self.listeners:
            listener.on_copy_start(block, table)

    def _after_complete(self, line: bytes, lineno: int) -> None:
        text = line.decode("utf-8", "replace")
        if not text.strip() or text.startswith("--"):
            return
        if text.startswith("\\unrestrict "):
            self.s.unrestrict_key = text.partition(" ")[2].strip()
            return
        self.s.after_complete_count += 1
        if len(self.s.after_complete) < AFTER_COMPLETE_KEPT:
            self.s.after_complete.append({"line": lineno, "text": _short(text)})
