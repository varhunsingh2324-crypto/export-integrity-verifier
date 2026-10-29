import gzip
import os
import secrets
import shutil
import subprocess
from decimal import Decimal
from pathlib import Path

import pytest

from eguard.config import load_policy
from eguard.manifest import build_from_chunks, save
from eguard.models import Status, Verdict, VerifyReport
from eguard.verify import verify_file
from sim.faults import (
    FROM_SOURCE,
    F1Config,
    F5Config,
    F6Config,
    copy_columns,
    dump_outcome,
    load_faults_config,
    make_f1,
    make_f2,
    make_f3,
    make_f4,
    make_f5,
    make_f6,
)
from tests import pgdump
from tests.gzutil import member

POLICY = load_policy()
CFG = load_faults_config()
V2_ROWS = 20_500  # enough for the configured F6 (rows 10001-20000)
KEY = b"fault-gallery-key"
# The configured F5 row (33,333) is beyond this small synthetic dump; same column and delta.
F5 = F5Config(row=13_579, column=CFG.f5.column, delta=CFG.f5.delta)
HAVE_COMPRESS = shutil.which("compress") is not None


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
    make_f5(src, out / "F5_amount.sql.gz", F5)
    files = {
        "F0": src,
        "F1": gzip_cli(killed, out / "F1_killed.sql.gz"),
        "F2": out / "F2_truncated.sql.gz",
        "F3": out / "F3_byteflip.sql.gz",
        "F5": out / "F5_amount.sql.gz",
        "F6": out / "F6_dupchunk.sql.gz",
    }
    if HAVE_COMPRESS:
        make_f4(src, out / "F4_bitflip.sql.Z", CFG.f4)
        files["F4"] = out / "F4_bitflip.sql.Z"
    return files


@pytest.fixture(scope="module")
def source_manifest(gallery: dict[str, Path], tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Built from the source stream, as the hardened pipeline would at export time."""
    path = tmp_path_factory.mktemp("manifests") / "source.manifest.json"
    with gzip.open(gallery["F0"], "rb") as fh:
        save(build_from_chunks(iter(lambda: fh.read(1 << 16), b""), POLICY, KEY), path)
    return path


def _manifest_for(fid: str, manifest: Path) -> tuple[Path | None, bytes | None]:
    """Same pairing as sim/faults.py: the source and everything derived from it use its manifest."""
    return (manifest, KEY) if fid == "F0" or fid in FROM_SOURCE else (None, None)


@pytest.fixture(scope="module")
def reports(gallery: dict[str, Path], source_manifest: Path) -> dict[str, VerifyReport]:
    return {
        fid: verify_file(p, POLICY, *_manifest_for(fid, source_manifest))
        for fid, p in gallery.items()
    }


def test_faults_config() -> None:
    assert CFG.f2.truncate_fraction == 0.70
    assert CFG.f3.offset_fraction == 0.5
    assert CFG.f6.rows == 10_000
    assert CFG.f1.timeout_seconds > 0
    assert CFG.f4.offset_fraction == 0.5
    assert (CFG.f5.row, CFG.f5.column, str(CFG.f5.delta)) == (33_333, "amount", "1.00")


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


def test_f0_has_no_l1_l4_findings(reports: dict[str, VerifyReport]) -> None:
    f0 = reports["F0"]
    assert f0.verdict == Verdict.SUSPECT and f0.ral == 4  # L5 not built yet
    assert all(c.status == Status.PASS for c in f0.checks if c.layer <= 4)


def test_f2_f3_corrupt_at_l1(reports: dict[str, VerifyReport]) -> None:
    assert reports["F2"].verdict == Verdict.CORRUPT
    assert "l1_stream_end" in _fails(reports["F2"])
    assert reports["F3"].verdict == Verdict.CORRUPT
    assert _fails(reports["F3"]) & {"l1_stream_end", "l1_integrity"}
    # The decoded prefix really is an incomplete dump, so L2 agrees (defence in depth).
    for fid in ("F2", "F3"):
        assert 1 in _failing_layers(reports[fid])
        assert _failing_layers(reports[fid]) <= {1, 2, 3, 4}


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


def test_f6_corrupt_at_l3_pk_and_l4_counts(reports: dict[str, VerifyReport]) -> None:
    f6 = reports["F6"]
    assert f6.verdict == Verdict.CORRUPT
    assert _fails(f6) == {"l3_pk_unique", "l4_row_counts", "l4_fingerprint", "l4_stream_digest"}
    (counts,) = [c for c in f6.checks if c.name == "l4_row_counts"]
    assert counts.evidence["tables"]["public.transactions"]["delta"] == CFG.f6.rows
    (c,) = [c for c in f6.checks if c.name == "l3_pk_unique"]
    t = c.evidence["tables"]["public.transactions"]
    prune = POLICY["l3"]["pk_candidate_prune_dups"]
    assert t["duplicates"] == min(CFG.f6.rows, prune + 1)
    assert t["lower_bound"] == (CFG.f6.rows > prune)
    assert t["examples"][0]["value"] == str(CFG.f6.start_row)


def _rows(path: Path) -> list[bytes]:
    with gzip.open(path, "rb") as fh:
        return fh.read().split(b"\n")


def test_f5_changes_exactly_one_value(gallery: dict[str, Path]) -> None:
    src, f5 = _rows(gallery["F0"]), _rows(gallery["F5"])
    i = pgdump.header_lines() + F5.row - 1  # 0-based index of that row
    diff = [k for k, (a, b) in enumerate(zip(src, f5, strict=True)) if a != b]
    assert diff == [i]
    col = copy_columns(src[pgdump.header_lines() - 1] + b"\n").index(F5.column)
    old, new = src[i].split(b"\t"), f5[i].split(b"\t")
    assert [k for k, (a, b) in enumerate(zip(old, new, strict=True)) if a != b] == [col]
    assert Decimal(new[col].decode()) - Decimal(old[col].decode()) == F5.delta


def test_f5_passes_l1_l3_and_l4_names_the_chunk(reports: dict[str, VerifyReport]) -> None:
    f5 = reports["F5"]
    assert f5.verdict == Verdict.CORRUPT
    assert all(c.status == Status.PASS for c in f5.checks if c.layer <= 3)
    assert _fails(f5) == {"l4_fingerprint", "l4_stream_digest"}
    (fp,) = [c for c in f5.checks if c.name == "l4_fingerprint"]
    first = fp.evidence["first_damaged"]
    assert fp.evidence["damaged_count"] == 1
    lo, hi = first["rows"]
    assert lo <= F5.row <= hi and hi - lo + 1 == POLICY["l4"]["chunk_rows"]
    assert first["lines"][0] <= pgdump.header_lines() + F5.row <= first["lines"][1]


@pytest.mark.skipif(not HAVE_COMPRESS, reason="`compress` (ncompress) not installed")
def test_f4_l1_cannot_see_it_but_l4_does(
    gallery: dict[str, Path], reports: dict[str, VerifyReport]
) -> None:
    assert gallery["F4"].read_bytes()[:2] == b"\x1f\x9d"
    f4 = reports["F4"]
    assert f4.verdict == Verdict.CORRUPT
    assert 1 not in _failing_layers(f4)  # .Z has no checksum
    assert {"l4_fingerprint", "l4_stream_digest"} <= _fails(f4)
    (fp,) = [c for c in f4.checks if c.name == "l4_fingerprint"]
    assert fp.evidence["first_damaged"]["rows"][0] >= 1


def test_f5_rejects_short_table_and_missing_column(tmp_path: Path) -> None:
    src = tmp_path / "small.sql.gz"
    src.write_bytes(member(pgdump.dump_bytes(50)))
    with pytest.raises(ValueError, match="need >= 60"):
        make_f5(src, tmp_path / "f5.gz", F5Config(row=60, column="amount", delta=Decimal("1")))
    with pytest.raises(ValueError):
        make_f5(src, tmp_path / "f5.gz", F5Config(row=5, column="nope", delta=Decimal("1")))


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


def _decoy(tmp_path: Path, path: Path) -> Path:
    decoy = tmp_path / secrets.token_hex(4) / f"{secrets.token_hex(6)}.{secrets.token_hex(2)}"
    decoy.parent.mkdir()
    shutil.copyfile(path, decoy)
    return decoy


def test_verdicts_ignore_file_names(
    tmp_path: Path,
    gallery: dict[str, Path],
    source_manifest: Path,
    reports: dict[str, VerifyReport],
) -> None:
    """Rule 9: renaming every file (and the manifest) to random names/dirs/extensions
    changes nothing."""
    for fid, path in gallery.items():
        manifest, key = _manifest_for(fid, _decoy(tmp_path, source_manifest))
        report = verify_file(_decoy(tmp_path, path), POLICY, manifest, key)
        assert _signature(report) == _signature(reports[fid]), fid


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
