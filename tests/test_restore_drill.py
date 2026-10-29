"""L5 restore drill against the real PostgreSQL container (SCRATCH_DSN, PG_DSN)."""

import copy
import os
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from eguard import restore_drill
from eguard.config import load_policy
from eguard.l5 import l5_checks
from eguard.manifest import build_from_chunks, compressed_info, save, seal
from eguard.models import CheckResult, SnapshotInfo, Status, Verdict
from eguard.parsers.pg_plain import PgPlainParser
from eguard.sampler import ReservoirSampler
from eguard.stream import FanOut
from eguard.verify import verify_file
from tests import pgdump
from tests.gzutil import member

pytestmark = pytest.mark.db

POLICY = load_policy()
SCRATCH = os.environ.get("SCRATCH_DSN")
SOURCE = os.environ.get("PG_DSN")
LIVE = "eguard_test_l5"  # live source table for the drift test, in its own schema

MINI_DDL = """CREATE TABLE {table} (
    id bigint NOT NULL,
    amount numeric(12,2) NOT NULL,
    code character(3) NOT NULL,
    note text
);"""


def mini_dump(table: str, lines: list[str], ddl: str = MINI_DDL) -> bytes:
    """A small plain dump with pg_dump's layout: DDL, COPY, `\\.`, PK after the data."""
    text = "--\n-- PostgreSQL database dump\n--\n\n"
    text += "SELECT pg_catalog.set_config('search_path', '', false);\n\n"
    text += ddl.format(table=table) + "\n\n"
    text += f"COPY {table} (id, amount, code, note) FROM stdin;\n"
    text += "".join(line + "\n" for line in lines) + "\\.\n\n"
    text += f"ALTER TABLE ONLY {table}\n    ADD CONSTRAINT x_pkey PRIMARY KEY (id);\n\n"
    text += "--\n-- PostgreSQL database dump complete\n--\n\n"
    return text.encode()


def sampled(data: bytes, n: int = 2995, seed: int = 1) -> ReservoirSampler:
    parser, sampler = PgPlainParser(), ReservoirSampler(n, seed)
    parser.add_listener(sampler)
    fan = FanOut(1 << 20)
    fan.subscribe(parser)
    fan.run([data])
    return sampler


def by_name(checks: list[CheckResult]) -> dict[str, CheckResult]:
    return {c.name: c for c in checks}


@pytest.fixture
def scratch() -> Iterator[str]:
    if not SCRATCH:
        pytest.skip("SCRATCH_DSN not set (copy .env.example to .env and run `make up`)")
    with restore_drill.connect(SCRATCH) as conn:  # deliberately not caught: set but down = FAIL
        conn.execute("SELECT 1")
    yield SCRATCH


def scratch_schemas(dsn: str) -> set[str]:
    with restore_drill.connect(dsn) as conn:
        rows = conn.execute(
            "SELECT nspname FROM pg_namespace WHERE nspname LIKE 'eguard\\_l5\\_%'"
        ).fetchall()
    return {r[0] for r in rows}


def test_healthy_sample_restores_and_round_trips(scratch: str) -> None:
    before = scratch_schemas(scratch)
    checks = by_name(l5_checks(sampled(pgdump.dump_bytes(400)), POLICY, scratch, None))
    restore, trip = checks["l5_restore"], checks["l5_round_trip"]
    assert restore.status == Status.PASS, restore.message
    assert trip.status == Status.PASS, trip.message
    assert restore.evidence["dropped"] is True and restore.evidence["scratch_bytes"] > 0
    assert "scratch space used" in restore.message
    (stmt,) = trip.evidence["confidence_statements"]
    assert "All 400 rows of public.transactions" in stmt  # 400 < n: exhaustive
    assert "l5_source" not in checks
    assert scratch_schemas(scratch) == before


def test_schema_dropped_even_when_an_insert_fails(scratch: str) -> None:
    before = scratch_schemas(scratch)
    lines = ["1\t10.00\tUSD\ta", "2\t20.00", "3\t30.00\tGBP\tc"]  # line 2: missing columns
    checks = by_name(l5_checks(sampled(mini_dump("public.items", lines)), POLICY, scratch, None))
    restore = checks["l5_restore"]
    assert restore.status == Status.FAIL and restore.severity == "CRITICAL"
    (t,) = restore.evidence["tables"]
    assert t["rejected_count"] == 1 and t["restored"] == 2
    assert t["rejected"][0]["value"] == "2\t20.00"
    assert "missing data for column" in t["rejected"][0]["error"]
    assert restore.evidence["dropped"] is True
    assert checks["l5_round_trip"].status == Status.PASS  # the other two rows came back intact
    assert scratch_schemas(scratch) == before


def test_round_trip_catches_a_malformed_sampled_line(scratch: str) -> None:
    """COPY accepts these lines but stores something else: 3 decimals rounded into
    numeric(12,2), 2 chars padded into character(3)."""
    lines = ["1\t10.00\tUSD\ta", "2\t40.005\tEUR\tb", "3\t30.00\tUS\tc"]
    checks = by_name(l5_checks(sampled(mini_dump("public.items", lines)), POLICY, scratch, None))
    assert checks["l5_restore"].status == Status.PASS
    trip = checks["l5_round_trip"]
    assert trip.status == Status.FAIL and trip.severity == "CRITICAL"
    (t,) = trip.evidence["tables"]
    assert t["mismatched_count"] == 2
    diffs = {m["line"]: m["columns"] for m in t["mismatched"]}
    assert [c["column"] for c in diffs[min(diffs)]] == ["amount"]
    assert diffs[min(diffs)][0]["restored"] == "40.01"
    assert diffs[max(diffs)] == [{"column": "code", "dump": "US", "restored": "US "}]
    assert "confidence_statements" not in trip.evidence


def test_schema_dropped_when_the_drill_raises(
    scratch: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = scratch_schemas(scratch)
    created: list[str] = []
    real_name = restore_drill.scratch_name

    def spy(now: float) -> str:
        created.append(real_name(now))
        return created[-1]

    def boom(*args: object) -> None:
        raise RuntimeError("injected mid-drill")

    monkeypatch.setattr(restore_drill, "scratch_name", spy)
    monkeypatch.setattr(restore_drill, "_round_trip", boom)
    with pytest.raises(RuntimeError, match="injected"):
        l5_checks(sampled(pgdump.dump_bytes(50)), POLICY, scratch, None)
    assert created and created[0] not in scratch_schemas(scratch)
    assert scratch_schemas(scratch) == before


def test_stale_scratch_schemas_swept_at_startup(scratch: str) -> None:
    now = time.time()
    old, fresh = f"eguard_l5_{int(now) - 7200}_deadbeef", f"eguard_l5_{int(now) - 60}_cafef00d"
    with restore_drill.connect(scratch) as conn:
        for name in (old, fresh):
            conn.execute(f'CREATE SCHEMA "{name}"')
    try:
        checks = by_name(l5_checks(sampled(pgdump.dump_bytes(20)), POLICY, scratch, None))
        assert checks["l5_restore"].evidence["stale_dropped"] == [old]
        remaining = scratch_schemas(scratch)
        assert old not in remaining and fresh in remaining
    finally:
        with restore_drill.connect(scratch) as conn:
            for name in (old, fresh):
                conn.execute(f'DROP SCHEMA IF EXISTS "{name}" CASCADE')


def test_multi_statement_ddl_is_refused_not_run(scratch: str) -> None:
    ddl = "CREATE TABLE {table} (id bigint, amount numeric, code text, note text); " + (
        "CREATE SCHEMA eguard_test_injected;"
    )
    data = mini_dump("public.items", ["1\t1\tUSD\ta"], ddl=ddl)
    checks = by_name(l5_checks(sampled(data), POLICY, scratch, None))
    restore = checks["l5_restore"]
    assert restore.status == Status.WARN and "ddl_refused" in restore.message
    with restore_drill.connect(scratch) as conn:
        assert (
            conn.execute(
                "SELECT 1 FROM pg_namespace WHERE nspname = 'eguard_test_injected'"
            ).fetchone()
            is None
        )


@pytest.fixture
def live_table(scratch: str) -> Iterator[str]:
    if not SOURCE:
        pytest.skip("PG_DSN not set")
    table = f"{LIVE}.items"
    with restore_drill.connect(SOURCE) as conn:
        conn.execute(f"DROP SCHEMA IF EXISTS {LIVE} CASCADE")
        conn.execute(f"CREATE SCHEMA {LIVE}")
        conn.execute(MINI_DDL.format(table=table))
        conn.execute(f"ALTER TABLE {table} ADD PRIMARY KEY (id)")
        conn.execute(
            f"INSERT INTO {table} VALUES (1, 10, 'USD', 'a'), (2, 20, 'EUR', 'b'), "
            "(3, 30, 'GBP', 'c'), (4, 40, 'USD', 'd')"
        )
    try:
        yield table
    finally:
        with restore_drill.connect(SOURCE) as conn:
            conn.execute(f"DROP SCHEMA IF EXISTS {LIVE} CASCADE")


def test_drift_vs_corrupt_classification(scratch: str, live_table: str) -> None:
    """Dumped: 4 rows as exported. Since then row 2 was updated and row 3 deleted (drift). Row 4's
    dump line does not round-trip (corrupt) and must not also count as drift."""
    lines = ["1\t10.00\tUSD\ta", "2\t20.00\tEUR\tb", "3\t30.00\tGBP\tc", "4\t40.005\tUSD\td"]
    assert SOURCE
    with restore_drill.connect(SOURCE) as conn:
        conn.execute(f"UPDATE {live_table} SET note = 'b2' WHERE id = 2")
        conn.execute(f"DELETE FROM {live_table} WHERE id = 3")
    checks = by_name(l5_checks(sampled(mini_dump(live_table, lines)), POLICY, scratch, SOURCE))
    assert checks["l5_round_trip"].status == Status.FAIL  # row 4: CORRUPT
    src = checks["l5_source"]
    assert src.status == Status.WARN and src.severity == "INFO"  # drift is never a FAIL
    (t,) = src.evidence["tables"]
    assert (t["matched"], t["drift_changed"], t["drift_deleted"], t["excluded"]) == (1, 1, 1, 1)
    assert t["primary_key"] == ["id"]
    kinds = {e["key"][0]: e for e in t["examples"]}
    assert kinds["2"]["drift"] == "changed since export"
    assert kinds["2"]["columns"] == [{"column": "note", "dump": "b", "restored": "b2"}]
    assert kinds["3"]["drift"] == "deleted since export"
    assert "4" not in kinds
    assert "DRIFT, not corruption" in src.message


def test_no_drift_passes_source_check(scratch: str, live_table: str) -> None:
    lines = ["1\t10.00\tUSD\ta", "2\t20.00\tEUR\tb"]
    checks = by_name(l5_checks(sampled(mini_dump(live_table, lines)), POLICY, scratch, SOURCE))
    assert checks["l5_source"].status == Status.PASS, checks["l5_source"].message


def test_unreachable_scratch_is_skip_not_corrupt() -> None:
    bad = "postgresql://eguard:wrong@127.0.0.1:1/none?connect_timeout=1"
    checks = by_name(l5_checks(sampled(pgdump.dump_bytes(10)), POLICY, bad, None))
    assert checks["l5_restore"].status == Status.SKIP
    assert "scratch database unusable" in checks["l5_restore"].message


def test_verify_with_manifest_and_drill_is_verified_ral_5(scratch: str, tmp_path: Path) -> None:
    policy = copy.deepcopy(POLICY)
    data = pgdump.dump_bytes(300)
    key = b"drill-key"
    gz = tmp_path / "export.sql.gz"
    gz.write_bytes(member(data))
    snap = SnapshotInfo(
        id="00000003-0000ABCD-1",
        isolation="repeatable read",
        taken_at="2026-10-29 10:00:00+00",
        counts={pgdump.TABLE: 300},
    )
    m = seal(build_from_chunks([data], policy, key), key, snap, compressed_info(gz, "t", 4096))
    save(m, tmp_path / "m.json")
    report = verify_file(gz, policy, tmp_path / "m.json", key, scratch_dsn=scratch, seed=1)
    assert report.verdict == Verdict.VERIFIED and report.ral == 5, report.reasons
    assert report.reasons == []
    legacy = verify_file(gz, policy, scratch_dsn=scratch, seed=1)
    assert legacy.verdict == Verdict.SUSPECT and legacy.ral == 4
    assert len(legacy.reasons) == 1 and legacy.reasons[0].startswith("L4 l4_manifest SKIP")
