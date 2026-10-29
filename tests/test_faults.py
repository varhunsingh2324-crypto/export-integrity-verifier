import secrets
import shutil
from pathlib import Path

import pytest

from eguard.config import load_policy
from eguard.models import Status, Verdict, VerifyReport
from eguard.verify import verify_file
from sim.faults import load_faults_config, make_f2, make_f3
from tests.gzutil import dump_like, member

POLICY = load_policy()
CFG = load_faults_config()


@pytest.fixture
def v2(tmp_path: Path) -> Path:
    path = tmp_path / "src" / "v2.sql.gz"
    path.parent.mkdir()
    path.write_bytes(member(dump_like(5000)))
    return path


@pytest.fixture
def gallery(tmp_path: Path, v2: Path) -> dict[str, Path]:
    out = tmp_path / "exports"
    make_f2(v2, out / "F2_truncated.sql.gz", CFG.f2)
    make_f3(v2, out / "F3_byteflip.sql.gz", CFG.f3)
    return {"F0": v2, "F2": out / "F2_truncated.sql.gz", "F3": out / "F3_byteflip.sql.gz"}


def test_faults_config() -> None:
    assert CFG.f2.truncate_fraction == 0.70
    assert CFG.f3.offset_fraction == 0.5


def test_f2_keeps_exact_prefix(v2: Path, gallery: dict[str, Path]) -> None:
    src, f2 = v2.read_bytes(), gallery["F2"].read_bytes()
    assert len(f2) == int(len(src) * CFG.f2.truncate_fraction)
    assert src.startswith(f2)


def test_f3_flips_exactly_one_byte(v2: Path, gallery: dict[str, Path]) -> None:
    src, f3 = v2.read_bytes(), gallery["F3"].read_bytes()
    assert len(src) == len(f3)
    diff = [i for i, (a, b) in enumerate(zip(src, f3, strict=True)) if a != b]
    assert diff == [int(len(src) * CFG.f3.offset_fraction)]
    assert src[diff[0]] ^ f3[diff[0]] == CFG.f3.xor_mask


def _fails(report: VerifyReport) -> set[str]:
    return {c.name for c in report.checks if c.status == Status.FAIL}


def test_f2_f3_corrupt_at_l1_and_f0_passes_l1(gallery: dict[str, Path]) -> None:
    reports = {fid: verify_file(p, POLICY) for fid, p in gallery.items()}
    assert reports["F0"].verdict == Verdict.SUSPECT  # L2-L5 not built yet
    assert all(c.status == Status.PASS for c in reports["F0"].checks if c.layer == 1)
    assert reports["F2"].verdict == Verdict.CORRUPT
    assert _fails(reports["F2"]) == {"l1_stream_end"}
    assert reports["F3"].verdict == Verdict.CORRUPT
    assert _fails(reports["F3"]) <= {"l1_stream_end", "l1_integrity"}
    for fid in ("F2", "F3"):
        assert {c.layer for c in reports[fid].checks if c.status == Status.FAIL} == {1}


def _signature(report: VerifyReport) -> tuple:
    return report.verdict, report.ral, [(c.name, c.status, c.evidence) for c in report.checks]


def test_verdicts_ignore_file_names(tmp_path: Path, gallery: dict[str, Path]) -> None:
    """Rule 9: renaming every file to random names/dirs/extensions changes nothing."""
    for fid, path in gallery.items():
        decoy = tmp_path / secrets.token_hex(4) / f"{secrets.token_hex(6)}.{secrets.token_hex(2)}"
        decoy.parent.mkdir()
        shutil.copyfile(path, decoy)
        assert _signature(verify_file(decoy, POLICY)) == _signature(verify_file(path, POLICY)), fid
