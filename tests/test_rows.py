"""L3: validators, COPY escapes, RowValidator and the PK key tracker (set -> Bloom + spill)."""

import copy
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from eguard.config import load_policy
from eguard.models import Status
from eguard.parsers.pg_plain import PgPlainParser
from eguard.rows import RowValidator, check_rows, escape_error, unescape, validator_for
from eguard.sketches import BloomFilter, KeyTracker
from eguard.stream import FanOut
from tests import pgdump

POLICY = load_policy()


def run(data: bytes, policy: dict[str, Any] = POLICY) -> dict[str, Any]:
    parser, rows = PgPlainParser(), RowValidator(policy)
    parser.add_listener(rows)
    fan = FanOut(1 << 20)
    fan.subscribe(parser)
    fan.run([data])
    return {c.name: c for c in check_rows(rows)}


def with_rows(body: list[str]) -> bytes:
    return pgdump.dump_bytes(body=body)


GOOD = pgdump.rows(1)[0].split("\t")


def mutate(col: str, value: str) -> bytes:
    fields = list(GOOD)
    fields[pgdump.COLUMNS.index(col)] = value
    return with_rows(pgdump.rows(5, start=2) + ["\t".join(fields)])


@pytest.mark.parametrize(
    ("type_text", "good", "bad"),
    [
        ("bigint", ["0", "-9223372036854775808", "42"], ["9223372036854775808", "1.0", "x", ""]),
        ("integer", ["2147483647", "-1"], ["2147483648", "1e3"]),
        ("smallint", ["32767"], ["32768"]),
        (
            "numeric(12,2)",
            ["4683.02", "-0.50", "9999999999.99", "NaN"],
            ["1.234", "10000000000.00", "abc", "-"],
        ),
        ("numeric", ["1.23456789", "Infinity"], ["1,5"]),
        ("double precision", ["1.5e-10", "NaN", "-Infinity"], ["one"]),
        ("boolean", ["t", "f"], ["true", "1"]),
        ("date", ["2024-02-29", "infinity", "0044-03-15 BC"], ["2023-02-29", "2023/01/01"]),
        (
            "timestamp with time zone",
            ["2023-02-02 06:25:41.97989+00", "2023-02-02 06:25:41+05:30", "infinity"],
            ["2023-02-30 06:25:41+00", "2023-02-02T06:25:41+00", "2023-02-02 25:00:00+00"],
        ),
        ("timestamp without time zone", ["2023-02-02 06:25:41.123456"], ["yesterday"]),
        ("character(3)", ["USD", "a\\tb"], ["USDX"]),
        ("character varying(4)", ["abcd"], ["abcde"]),
        ("jsonb", ['{"v": 1}', '{"q": "a\\\\"b"}', "[]"], ['{"v": 1', '{"v": NaN}', "{'a': 1}"]),
        ("uuid", ["123e4567-e89b-12d3-a456-426614174000"], ["123e4567"]),
        ("bytea", ["\\\\x00ff"], ["\\\\xabc", "plain"]),
    ],
)
def test_validators(type_text: str, good: list[str], bad: list[str]) -> None:
    v = validator_for(type_text)
    assert v is not None
    for value in good:
        assert v(value) is None, value
    for value in bad:
        assert v(value) is not None, value


@pytest.mark.parametrize("type_text", ["integer[]", "mood", "interval", "point"])
def test_unknown_types_are_not_validated(type_text: str) -> None:
    assert validator_for(type_text) is None


def test_escapes() -> None:
    assert escape_error("a\\tb\\nc\\\\d\\b\\f\\r\\v") is None
    assert escape_error("\\101\\x41") is None  # legal input, pg_dump never writes it
    assert escape_error("abc\\") == "trailing backslash"
    assert escape_error("a\\qb") == "invalid escape '\\q'"
    assert escape_error("a\\Nb") == "invalid escape '\\N'"
    assert unescape("a\\tb\\\\c\\101\\x42") == "a\tb\\cAB"
    with pytest.raises(ValueError):
        unescape("\\377")  # lone 0xff byte is not UTF-8
    with pytest.raises(ValueError):
        unescape("a\\000")


def test_healthy_rows_pass() -> None:
    checks = run(pgdump.dump_bytes(300))
    assert checks["l3_row_validity"].status == Status.PASS
    assert checks["l3_row_validity"].evidence["rows_checked"] == 300
    pk = checks["l3_pk_unique"]
    assert pk.status == Status.PASS
    assert pk.evidence["tables"][pgdump.TABLE]["keys"] == 300


@pytest.mark.parametrize(
    ("col", "value", "reason"),
    [
        ("amount", "12.345", "type"),
        ("txn_ts", "2023-13-01 00:00:00+00", "type"),
        ("meta", '{"v": 1', "type"),
        ("currency", "\\N", "not_null"),
        ("remarks", "bad\\qescape", "escape"),
        ("account_id", "99999999999", "type"),
    ],
)
def test_invalid_field_is_corrupt(col: str, value: str, reason: str) -> None:
    c = run(mutate(col, value))["l3_row_validity"]
    assert c.status == Status.FAIL
    assert c.evidence["invalid_rows"] == 1
    assert c.evidence["by_reason"] == {reason: 1}
    ex = c.evidence["examples"][0]
    assert ex["line"] == pgdump.header_lines() + 6
    assert ex["column"] == col and ex["table"] == pgdump.TABLE


def test_field_count_utf8_and_control_chars() -> None:
    body = pgdump.rows(4)
    body[1] = body[1].rsplit("\t", 1)[0]  # one field short
    body[2] = body[2].replace("\t", "\r", 1)  # raw CR
    data = with_rows(body).replace(body[3].encode(), body[3].encode() + b"\xff\xfe")
    c = run(data)["l3_row_validity"]
    assert c.status == Status.FAIL
    assert c.evidence["by_reason"] == {"field_count": 2, "utf8": 1}  # CR merges two fields


def test_nullable_null_is_fine() -> None:
    assert run(mutate("remarks", "\\N"))["l3_row_validity"].status == Status.PASS


def test_unknown_type_warns() -> None:
    text = pgdump.dump_text(3).replace("    meta jsonb\n", "    meta public.mytype\n")
    c = run(text.encode())["l3_row_validity"]
    assert c.status == Status.WARN
    assert c.evidence["unvalidated_columns"] == {pgdump.TABLE: ["meta (public.mytype)"]}


def test_duplicate_pk_set_mode() -> None:
    body = pgdump.rows(50)
    body += body[10:13]  # rows 11-13 sent again
    c = run(with_rows(body))["l3_pk_unique"]
    assert c.status == Status.FAIL
    t = c.evidence["tables"][pgdump.TABLE]
    assert (t["mode"], t["duplicates"], t["lower_bound"]) == ("set", 3, False)
    assert t["examples"][0] == {"line": pgdump.header_lines() + 51, "value": "11"}
    assert "3 duplicate id" in c.message


def small_policy(**l3: int) -> dict[str, Any]:
    p = copy.deepcopy(POLICY)  # config/policy.yaml itself is never edited (rule 4)
    p["l3"].update(l3)
    return p


def test_duplicate_pk_after_switch_to_bloom() -> None:
    body = pgdump.rows(400)
    body += body[350:370] + body[5:7]  # duplicates both of set-era and bloom-era keys
    c = run(with_rows(body), small_policy(pk_set_limit=100, pk_bloom_bytes=4096))["l3_pk_unique"]
    t = c.evidence["tables"][pgdump.TABLE]
    assert c.status == Status.FAIL
    assert (t["mode"], t["duplicates"], t["keys"]) == ("bloom", 22, 422)


def test_bloom_false_positives_are_not_findings() -> None:
    # A 16-byte Bloom over 400 keys is saturated: nearly every insert is a suspect.
    p = small_policy(pk_set_limit=10, pk_bloom_bytes=16, pk_candidate_prune_dups=10_000)
    c = run(pgdump.dump_bytes(400), p)["l3_pk_unique"]
    t = c.evidence["tables"][pgdump.TABLE]
    assert t["bloom_suspects"] > 300
    assert t["duplicates"] == 0 and c.status == Status.PASS


def test_pruned_pk_is_a_lower_bound() -> None:
    body = pgdump.rows(30)
    body += body * 2
    c = run(with_rows(body), small_policy(pk_candidate_prune_dups=5))["l3_pk_unique"]
    t = c.evidence["tables"][pgdump.TABLE]
    assert c.status == Status.FAIL
    assert t["lower_bound"] and t["duplicates"] == 6
    assert "≥6 duplicate id" in c.message


def test_non_unique_candidates_are_pruned() -> None:
    parser, rows = PgPlainParser(), RowValidator(small_policy(pk_candidate_prune_dups=5))
    parser.add_listener(rows)
    fan = FanOut(1 << 20)
    fan.subscribe(parser)
    fan.run([pgdump.dump_bytes(300)])
    pruned = {col for (_, col), t in rows.trackers.items() if t.pruned}
    assert {"currency", "status", "channel"} <= pruned
    assert not rows.trackers[(pgdump.TABLE, "id")].pruned


def test_composite_pk_and_unreached_pk_skip() -> None:
    text = pgdump.dump_text(5).replace("PRIMARY KEY (id)", "PRIMARY KEY (id, account_id)")
    c = run(text.encode())["l3_pk_unique"]
    assert c.status == Status.SKIP and "composite" in c.message
    c = run(pgdump.killed_at(50, 20))["l3_pk_unique"]
    assert c.status == Status.SKIP and "not reached" in c.message


def test_partial_final_row_is_not_an_l3_error() -> None:
    c = run(pgdump.killed_at(50, 20, partial="21\t99\t2023"))["l3_row_validity"]
    assert c.status == Status.PASS
    assert c.evidence["partial_row_bytes_not_checked"] == len("21\t99\t2023")


@settings(max_examples=50, deadline=None)
@given(st.sets(st.integers(min_value=0, max_value=(1 << 64) - 1), min_size=1, max_size=300))
def test_bloom_has_no_false_negatives(keys: set[int]) -> None:
    bloom = BloomFilter(64, 3)
    for k in keys:
        bloom.add(k)
    assert all(bloom.add(k) for k in keys)


def test_key_tracker_set_to_bloom_counts_exactly() -> None:
    t = KeyTracker(set_limit=50, bloom_bytes=1024, bloom_hashes=5, prune_dups=10_000, examples=5)
    keys = [(i * 0x9E3779B97F4A7C15) & ((1 << 64) - 1) for i in range(500)]
    for i, k in enumerate(keys + keys[:7] + keys[300:303]):
        t.add(k, i, str(i))
    r = t.result()
    assert r["mode"] == "bloom" and r["duplicates"] == 10 and r["keys"] == 510
    assert len(r["examples"]) == 5
