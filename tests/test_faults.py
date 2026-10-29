import gzip
import os
import secrets
import shutil
import subprocess
from pathlib import Path

import pytest

from eguard.config import load_policy
from eguard.models import Status, Verdict, VerifyReport
from eguard.verify import verify_file
from sim.faults import (
    F1Config,
    F6Config,
    dump_outcome,
    load_faults_config,
    make_f1,
    make_f2,
    make_f3,
    make_f6,
)
from tests import pgdump
from tests.gzutil import member

POLICY = load_policy()
CFG = load_faults_config()
V2_ROWS = 20_500  # enough for the configured F6 (rows 10001-20000)


def gzip_cli(data: bytes, dst: Path) -> Path:
    """Compress like the legacy pipe does: the `gzip` binary reading a pipe that just ends."""
    dst.write_bytes(subprocess.run(["gzip", "-c"], input=data, capture_output=True).stdout)
    return dst


def gzip_t(path: Path) -> int:
    return subprocess.run(["gzip", "-t", str(path)], capture_output=True).returncode


@pytest.fixture(scope="module")
def gallery(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    src = tmp_path_factory.mktemp("src") / "v2.sql.gz"
    src.write_bytes(member(pgdump.dump_bytes(V2_ROWS)))
    out = tmp_path_factory.mktemp("exports")
    killed = pgdump.killed_at(V2_ROWS, 12_345, partial="12346\t77\t2023-0")
    make_f2(src, out / "F2_truncated.sql.gz", CFG.f2)
    make_f3(src, out / "F3_byteflip.sql.gz", CFG.f3)
    make_f6(src, out / "F6_dupchunk.sql.gz", CFG.f6)
    return {
        "F0": src,
        "F1": gzip_cli(killed, out / "F1_killed.sql.gz"),
        "F2": out / "F2_truncated.sql.gz",
        "F3": out / "F3_byteflip.sql.gz",
        "F6": out / "F6_dupchunk.sql.gz",
    }


@pytest.fixture(scope="module")
def reports(gallery: dict[str, Path]) -> dict[str, VerifyReport]:
    return {fid: verify_file(p, POLICY) for fid, p in gallery.items()}


def test_faults_config() -> None:
    assert CFG.f2.truncate_fraction == 0.70
    assert CFG.f3.offset_fraction == 0.5
    assert CFG.f6.rows == 10_000
    assert CFG.f1.timeout_seconds > 0


def test_f2_keeps_exact_prefix(gallery: dict[str, Path]) -> None:
    src, f2 = gallery["F0"].read_bytes(), gallery["F2"].read_bytes()
    assert len(f2) == int(len(src) * CFG.f2.truncate_fraction)
    assert src.startswith(f2)


def test_f3_flips_exactly_one_byte(gallery: dict[str, Path]) -> None:
    src, f3 = gallery["F0"].read_bytes(), gallery["F3"].read_bytes()
    assert len(src) == len(f3)
    diff = [i for i, (a, b) in enumerate(zip(src, f3, strict=True)) if a != b]
    assert diff == [int(len(src) * CFG.f3.offset_fraction)]
    assert src[diff[0]] ^ f3[diff[0]] == CFG.f3.xor_mask


def _fails(report: VerifyReport) -> set[str]:
    return {c.name for c in report.checks if c.status == Status.FAIL}


def _failing_layers(report: VerifyReport) -> set[int]:
    return {c.layer for c in report.checks if c.status == Status.FAIL}


def test_f0_has_no_l1_l3_findings(reports: dict[str, VerifyReport]) -> None:
    f0 = reports["F0"]
    assert f0.verdict == Verdict.SUSPECT and f0.ral == 3  # L4/L5 not built yet
    assert all(c.status == Status.PASS for c in f0.checks if c.layer <= 3)


def test_f2_f3_corrupt_at_l1(reports: dict[str, VerifyReport]) -> None:
    assert reports["F2"].verdict == Verdict.CORRUPT
    assert "l1_stream_end" in _fails(reports["F2"])
    assert reports["F3"].verdict == Verdict.CORRUPT
    assert _fails(reports["F3"]) & {"l1_stream_end", "l1_integrity"}
    # The decoded prefix really is an incomplete dump, so L2 agrees (defence in depth).
    for fid in ("F2", "F3"):
        assert 1 in _failing_layers(reports[fid])
        assert _failing_layers(reports[fid]) <= {1, 2, 3}


def test_f1_passes_gzip_t_but_l2_is_corrupt(
    gallery: dict[str, Path], reports: dict[str, VerifyReport]
) -> None:
    assert gzip_t(gallery["F1"]) == 0
    f1 = reports["F1"]
    assert f1.verdict == Verdict.CORRUPT
    assert all(c.status == Status.PASS for c in f1.checks if c.layer == 1)
    assert _failing_layers(f1) == {2}
    (c,) = [c for c in f1.checks if c.name == "l2_complete"]
    assert "inside COPY public.transactions after row 12,345" in c.message
    assert "partial row" in c.message


def test_f6_duplicates_exactly_the_configured_rows(gallery: dict[str, Path]) -> None:
    with gzip.open(gallery["F0"], "rb") as a, gzip.open(gallery["F6"], "rb") as b:
        src, f6 = a.read().split(b"\n"), b.read().split(b"\n")
    first = pgdump.header_lines()  # 0-based index of row 1 in the split list
    lo, hi = first + CFG.f6.start_row - 1, first + CFG.f6.start_row - 1 + CFG.f6.rows
    assert len(f6) == len(src) + CFG.f6.rows
    assert f6[:hi] == src[:hi]
    assert f6[hi : hi + CFG.f6.rows] == src[lo:hi]
    assert f6[hi + CFG.f6.rows :] == src[hi:]


def test_f6_corrupt_at_l3_pk_only(reports: dict[str, VerifyReport]) -> None:
    f6 = reports["F6"]
    assert f6.verdict == Verdict.CORRUPT
    assert _fails(f6) == {"l3_pk_unique"}
    (c,) = [c for c in f6.checks if c.name == "l3_pk_unique"]
    t = c.evidence["tables"]["public.transactions"]
    prune = POLICY["l3"]["pk_candidate_prune_dups"]
    assert t["duplicates"] == min(CFG.f6.rows, prune + 1)
    assert t["lower_bound"] == (CFG.f6.rows > prune)
    assert t["examples"][0]["value"] == str(CFG.f6.start_row)


def test_f6_rejects_short_table(tmp_path: Path) -> None:
    src = tmp_path / "small.sql.gz"
    src.write_bytes(member(pgdump.dump_bytes(50)))
    with pytest.raises(ValueError, match="need >= 60"):
        make_f6(src, tmp_path / "f6.gz", F6Config(start_row=11, rows=50))


def test_dump_outcome_oracle(tmp_path: Path) -> None:
    cases = {
        "completed": pgdump.dump_bytes(20),
        "mid_copy": pgdump.killed_at(20, 5),
        "before_data": (pgdump.PREAMBLE + pgdump.DDL).encode(),
    }
    for kind, data in cases.items():
        assert dump_outcome(gzip_cli(data, tmp_path / f"{kind}.gz"))["outcome"] == kind


def _signature(report: VerifyReport) -> tuple:
    return report.verdict, report.ral, [(c.name, c.status, c.evidence) for c in report.checks]


def test_verdicts_ignore_file_names(
    tmp_path: Path, gallery: dict[str, Path], reports: dict[str, VerifyReport]
) -> None:
    """Rule 9: renaming every file to random names/dirs/extensions changes nothing."""
    for fid, path in gallery.items():
        decoy = tmp_path / secrets.token_hex(4) / f"{secrets.token_hex(6)}.{secrets.token_hex(2)}"
        decoy.parent.mkdir()
        shutil.copyfile(path, decoy)
        assert _signature(verify_file(decoy, POLICY)) == _signature(reports[fid]), fid


@pytest.mark.db
def test_f1_real_timeout_in_legacy_pipe(tmp_path: Path) -> None:
    """F1 for real: `timeout` kills pg_dump inside `pg_dump | gzip`; gzip -t still passes."""
    if not os.environ.get("PG_DSN"):
        pytest.skip("PG_DSN not set (copy .env.example to .env and run `make up`)")
    from sim.incident import drop_schema, load_sim_config, scaled_rows, seed

    cfg, schema = load_sim_config(), "eguard_test_f1"
    try:
        seed(cfg, scaled_rows(cfg, 0.02), schema)
        rec = make_f1(
            f"{schema}.{cfg.table}",
            tmp_path / "f1.gz",
            F1Config(timeout_seconds=0.2, max_attempts=12),
        )
    finally:
        drop_schema(schema)
    assert rec["script_exit"] == 0 and rec["gzip_t_exit"] == 0
    report = verify_file(tmp_path / "f1.gz", POLICY)
    assert report.verdict == Verdict.CORRUPT
    assert _failing_layers(report) == {2}
    (c,) = [c for c in report.checks if c.name == "l2_complete"]
    assert (
        f"inside COPY {schema}.{cfg.table} after row {rec['complete_rows_written']:,}" in c.message
    )
