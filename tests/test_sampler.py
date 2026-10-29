import math
import random
from collections import Counter

import pytest

from eguard.config import load_policy
from eguard.models import Status, TableDef
from eguard.parsers.pg_plain import PgPlainParser
from eguard.restore_drill import SCRATCH_RE, scratch_ddl, scratch_name, single_statement
from eguard.sampler import (
    Reservoir,
    ReservoirSampler,
    check_sample,
    confidence_statement,
    detection_probability,
    sample_size,
)
from eguard.stream import FanOut
from tests import pgdump

POLICY = load_policy()


def test_sample_size_formula_defaults_to_2995() -> None:
    l5 = POLICY["l5"]
    assert sample_size(l5["detect_fraction"], l5["confidence"]) == 2995
    assert sample_size(0.001, 0.95) == math.ceil(math.log(0.05) / math.log(1 - 0.001)) == 2995
    assert sample_size(0.01, 0.99) == 459


def test_2995_is_the_smallest_sample_reaching_95_percent() -> None:
    assert detection_probability(0.001, 2995) >= 0.95 > detection_probability(0.001, 2994)


@pytest.mark.parametrize(("p", "c"), [(0, 0.95), (1, 0.95), (0.001, 0), (0.001, 1), (-1, 0.5)])
def test_sample_size_rejects_bad_parameters(p: float, c: float) -> None:
    with pytest.raises(ValueError):
        sample_size(p, c)


def _fill(k: int, n: int, seed: int) -> list[int]:
    r = Reservoir(k, random.Random(seed))
    for i in range(1, n + 1):
        r.add(i, b"")
    assert r.seen == n
    return sorted(lineno for lineno, _ in r.items)


def test_reservoir_keeps_everything_when_stream_is_short() -> None:
    assert _fill(10, 7, 1) == list(range(1, 8))
    assert _fill(10, 10, 1) == list(range(1, 11))


def test_reservoir_is_reproducible_with_a_seed() -> None:
    a, b, c = _fill(50, 10_000, 3), _fill(50, 10_000, 3), _fill(50, 10_000, 4)
    assert a == b and a != c
    assert len(a) == len(set(a)) == 50 and all(1 <= x <= 10_000 for x in a)


def test_reservoir_is_roughly_uniform() -> None:
    """N=100, k=10: each item expected in 10 % of runs (500 of 5000; sd ~21)."""
    counts: Counter[int] = Counter()
    rng = random.Random(11)
    for _ in range(5000):
        r = Reservoir(10, rng)
        for i in range(100):
            r.add(i, b"")
        counts.update(lineno for lineno, _ in r.items)
    assert set(counts) == set(range(100))
    assert all(390 <= counts[i] <= 610 for i in range(100)), counts.most_common(3)
    early, late = sum(counts[i] for i in range(50)), sum(counts[i] for i in range(50, 100))
    assert abs(early - late) < 600


def _sampled(data: bytes, n: int, seed: int) -> ReservoirSampler:
    parser, sampler = PgPlainParser(), ReservoirSampler(n, seed)
    parser.add_listener(sampler)
    fan = FanOut(1 << 20)
    fan.subscribe(parser)
    fan.run([data])
    return sampler


def test_sampler_maps_line_numbers_to_their_lines() -> None:
    rows = pgdump.rows(500)
    sampler = _sampled(pgdump.dump_bytes(500), 40, 9)
    (s,) = sampler.samples
    assert s.seen == 500 and len(s.rows) == 40
    assert s.table is not None and s.table.primary_key == ["id"]  # resolved post-data
    for lineno, line in s.rows:
        assert line == rows[lineno - pgdump.header_lines() - 1].encode()
    assert [x for x, _ in s.rows] == sorted(x for x, _ in s.rows)


def test_check_sample_records_formula_and_seed() -> None:
    sampler = _sampled(pgdump.dump_bytes(300), 2995, 1234)
    c = check_sample(sampler, 0.001, 0.95)
    assert c.status == Status.PASS and c.evidence["seed"] == 1234 and c.evidence["n"] == 2995
    assert c.evidence["tables"] == [
        {"table": pgdump.TABLE, "seen": 300, "sampled": 300, "exhaustive": True}
    ]


def test_confidence_statement_text() -> None:
    s = confidence_statement(0.001, 0.95, "public.t", 2995, 390_000)
    assert s.startswith(
        "If ≥0.1% of rows were unrestorable, this drill would have caught it with 95% probability"
    )
    assert "2,995 of 390,000 rows of public.t" in s
    assert "exhaustive" in confidence_statement(0.001, 0.95, "public.t", 300, 300)


@pytest.mark.parametrize(
    ("text", "ok"),
    [
        ("CREATE TABLE a (x text DEFAULT ';');", True),
        ('CREATE TABLE a ("x;y" int);', True),
        ("CREATE TABLE a (x text DEFAULT E'\\';');", True),
        ("CREATE TABLE a (x int) -- trailing ; comment\n;", True),
        ("CREATE TABLE a (x int); DROP TABLE b;", False),
        ("CREATE TABLE a (x int);\nSELECT 1;", False),
        ("CREATE TABLE a (x text DEFAULT $$;$$);", False),
        ("CREATE TABLE a (x$y int);", True),
    ],
)
def test_single_statement(text: str, ok: bool) -> None:
    assert single_statement(text) is ok


def test_scratch_ddl_renames_only_the_table() -> None:
    parser = PgPlainParser()
    fan = FanOut(1 << 20)
    fan.subscribe(parser)
    fan.run([pgdump.dump_bytes(3)])
    table = parser.s.tables[pgdump.TABLE]
    ddl = scratch_ddl(table, "eguard_l5_1_abcdef01", "t1")
    assert ddl is not None
    assert ddl.startswith('CREATE TABLE "eguard_l5_1_abcdef01"."t1" (\n    id bigint NOT NULL,')
    assert ddl.endswith("WITH (autovacuum_enabled='false');")
    evil = TableDef(name="public.a", columns=[], line=1, ddl="CREATE TABLE public.a (x int); DROP")
    assert scratch_ddl(evil, "s", "t1") is None
    assert scratch_ddl(TableDef(name="public.a", columns=[], line=1), "s", "t1") is None


def test_scratch_name_encodes_age() -> None:
    m = SCRATCH_RE.fullmatch(scratch_name(1_700_000_000.7))
    assert m is not None and m.group(1) == "1700000000"
    assert scratch_name(1.0) != scratch_name(1.0)
