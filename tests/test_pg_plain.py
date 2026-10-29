"""PgPlainParser (dump grammar state machine) and the L2 checks built from it."""

from typing import Any

import pytest

from eguard.models import CopyBlock, DumpStructure, Status, StreamEnd, TableDef
from eguard.parsers.pg_plain import (
    BODY,
    COMPLETE,
    COPY_ROWS,
    PgPlainParser,
    parse_columns,
    split_idents,
    unquote,
)
from eguard.stream import FanOut
from eguard.structure import check_structure
from tests import pgdump


class Recorder:
    def __init__(self) -> None:
        self.events: list[tuple[Any, ...]] = []

    def on_copy_start(self, block: CopyBlock, table: TableDef | None) -> None:
        self.events.append(("start", block.table, table is not None))

    def on_row(self, block: CopyBlock, line: bytes, lineno: int) -> None:
        self.events.append(("row", lineno, line))

    def on_copy_end(self, block: CopyBlock) -> None:
        self.events.append(("end", block.rows))

    def on_finish(self, structure: DumpStructure) -> None:
        self.events.append(("finish", structure.state))


def parse(data: bytes, chunk: int = 97) -> tuple[DumpStructure, StreamEnd, Recorder]:
    parser, rec = PgPlainParser(), Recorder()
    parser.add_listener(rec)
    fan = FanOut(1 << 20)
    fan.subscribe(parser)
    end = fan.run(data[i : i + chunk] for i in range(0, len(data), chunk))
    return parser.s, end, rec


def l2(data: bytes) -> dict[str, Any]:
    s, end, _ = parse(data)
    return {c.name: c for c in check_structure(s, end)}


def test_healthy_dump() -> None:
    s, end, rec = parse(pgdump.dump_bytes(50))
    assert s.state == COMPLETE
    assert s.dumped_by and s.dumped_by.startswith("pg_dump version 16")
    assert s.restrict_key == s.unrestrict_key == pgdump.KEY
    table = s.tables[pgdump.TABLE]
    assert [c.name for c in table.columns] == list(pgdump.COLUMNS)
    assert table.primary_key == ["id"]
    (block,) = s.copies
    assert block.closed and block.rows == 50
    assert block.first_row_line == pgdump.header_lines() + 1
    assert block.last_row_line == pgdump.header_lines() + 50
    rows = [e for e in rec.events if e[0] == "row"]
    assert len(rows) == 50 and rows[0][2].startswith(b"1\t")
    assert rec.events[0] == ("start", pgdump.TABLE, True)
    assert rec.events[-2:] == [("end", 50), ("finish", COMPLETE)]
    assert all(c.status == Status.PASS for c in l2(pgdump.dump_bytes(50)).values())


def test_ddl_types_and_not_null() -> None:
    s, _, _ = parse(pgdump.dump_bytes(1))
    cols = {c.name: (c.type, c.not_null) for c in s.tables[pgdump.TABLE].columns}
    assert cols["id"] == ("bigint", True)
    assert cols["txn_ts"] == ("timestamp with time zone", True)
    assert cols["amount"] == ("numeric(12,2)", True)
    assert cols["currency"] == ("character(3)", True)
    assert cols["remarks"] == ("text", False)
    assert cols["meta"] == ("jsonb", False)


def test_parse_columns_skips_constraints_and_reads_defaults() -> None:
    body = (
        "\n    \"Odd Name\" character varying(20) DEFAULT 'x'::text NOT NULL,\n"
        "    n integer,\n    CONSTRAINT pos CHECK ((n > 0))\n"
    )
    cols = parse_columns(body)
    assert [(c.name, c.type, c.not_null) for c in cols] == [
        ("Odd Name", "character varying(20)", True),
        ("n", "integer", False),
    ]


def test_quoted_identifiers() -> None:
    assert split_idents('id, "a, b", "q""x"') == ["id", '"a, b"', '"q""x"']
    assert unquote('"q""x"') == 'q"x'


def test_quoted_copy_header_matches_ddl() -> None:
    text = pgdump.dump_text(2).replace("public.transactions", 'public."Txn Table"')
    s, end, _ = parse(text.encode())
    assert s.copies[0].table == 'public."Txn Table"'
    assert s.tables['public."Txn Table"'].primary_key == ["id"]
    assert all(c.status == Status.PASS for c in check_structure(s, end))


def test_killed_mid_copy_reports_table_row_and_partial() -> None:
    data = pgdump.killed_at(100, 42, partial="43\t1234\t2023-0")
    s, end, rec = parse(data)
    assert s.state == COPY_ROWS
    assert s.partial_line_bytes == len("43\t1234\t2023-0")
    assert [e for e in rec.events if e[0] == "row"][-1][2].startswith(b"42\t")
    assert len([e for e in rec.events if e[0] == "row"]) == 42  # partial row not delivered
    checks = l2(data)
    c = checks["l2_complete"]
    assert c.status == Status.FAIL
    assert "inside COPY public.transactions after row 42" in c.message
    assert f"line {pgdump.header_lines() + 42:,}" in c.message
    assert "partial row of 14 bytes" in c.message
    assert c.evidence["open_copy"]["rows"] == 42
    assert checks["l2_copy_blocks"].status == Status.FAIL


def test_killed_exactly_at_a_row_boundary() -> None:
    s, end, _ = parse(pgdump.killed_at(100, 42, partial=""))
    assert s.state == COPY_ROWS and s.partial_line_bytes == 0
    c = check_structure(s, end)[3]
    assert c.status == Status.FAIL and "after row 42" in c.message
    assert "partial" not in c.message


def test_killed_before_data() -> None:
    data = (pgdump.PREAMBLE + pgdump.DDL).encode()
    checks = l2(data)
    assert checks["l2_complete"].status == Status.FAIL
    assert checks["l2_tables"].status == Status.FAIL
    assert "no COPY data block" in checks["l2_tables"].message


def test_missing_marker_only() -> None:
    text = pgdump.dump_text(5).replace("-- PostgreSQL database dump complete\n", "")
    c = l2(text.encode())["l2_complete"]
    assert c.status == Status.FAIL and "completion marker missing" in c.message


def test_no_header() -> None:
    text = pgdump.dump_text(5).replace("-- PostgreSQL database dump\n", "", 1)
    assert l2(text.encode())["l2_header"].status == Status.FAIL


def test_stray_terminator() -> None:
    text = pgdump.dump_text(3).replace(
        "SET row_security = off;\n", "SET row_security = off;\n\\.\n"
    )
    c = l2(text.encode())["l2_copy_blocks"]
    assert c.status == Status.FAIL and c.evidence["stray_terminators"]


def test_copy_without_ddl() -> None:
    text = pgdump.dump_text(3).replace("CREATE TABLE public.transactions", "CREATE TABLE public.x")
    checks = l2(text.encode())
    assert checks["l2_copy_blocks"].status == Status.FAIL
    assert "without CREATE TABLE" in checks["l2_copy_blocks"].message
    assert checks["l2_tables"].status == Status.FAIL  # public.x has no data block


def test_duplicate_copy_block() -> None:
    block = pgdump.COPY_HEADER + "".join(r + "\n" for r in pgdump.rows(3)) + "\\.\n"
    text = pgdump.dump_text(3).replace(
        "\n\n--\n-- Name: transactions transactions_pkey",
        block + "\n\n--\n-- Name: transactions transactions_pkey",
    )
    c = l2(text.encode())["l2_tables"]
    assert c.status == Status.FAIL and c.evidence["repeated_copy"] == {pgdump.TABLE: 2}


def test_data_after_completion_marker() -> None:
    data = pgdump.dump_bytes(3) + pgdump.dump_bytes(3)  # two dumps concatenated
    c = l2(data)["l2_complete"]
    assert c.status == Status.FAIL and "after the completion marker" in c.message


def test_restrict_key_mismatch() -> None:
    text = pgdump.dump_text(3)
    i = text.rindex(pgdump.KEY)
    c = l2((text[:i] + "other" + text[i + len(pgdump.KEY) :]).encode())["l2_complete"]
    assert c.status == Status.FAIL and "unrestrict" in c.message


def test_dump_without_restrict_lines_is_fine() -> None:
    """pg_dump < 16.10 writes no \\restrict/\\unrestrict."""
    text = pgdump.dump_text(3).replace(f"\\restrict {pgdump.KEY}\n", "")
    text = text.replace(f"\\unrestrict {pgdump.KEY}\n", "")
    assert all(c.status == Status.PASS for c in l2(text.encode()).values())


def test_unterminated_final_line_on_complete_dump() -> None:
    data = pgdump.dump_bytes(3).rstrip(b"\n")
    c = l2(data)["l2_complete"]
    assert c.status == Status.FAIL and "no newline" in c.message


@pytest.mark.parametrize("chunk", [1, 7, 4096])
def test_chunking_does_not_matter(chunk: int) -> None:
    s1, _, _ = parse(pgdump.dump_bytes(30), chunk=chunk)
    s2, _, _ = parse(pgdump.dump_bytes(30), chunk=1 << 16)
    assert s1 == s2
    assert s1.state == COMPLETE != BODY
