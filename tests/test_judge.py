import os
import subprocess
import sys
from pathlib import Path

import pytest

from sim.judge import corrupt_copy, parse_offset
from tests import pgdump
from tests.gzutil import member

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def export(tmp_path: Path) -> Path:
    path = tmp_path / "src" / "e.sql.gz"
    path.parent.mkdir()
    path.write_bytes(member(pgdump.dump_bytes(600)))
    return path


def test_flip_changes_exactly_one_byte_of_a_copy(export: Path, tmp_path: Path) -> None:
    before = export.read_bytes()
    rec = corrupt_copy(export, tmp_path / "out", 100, "flip", 0x01)
    after = Path(rec["path"]).read_bytes()
    assert export.read_bytes() == before  # never the source
    assert len(after) == len(before)
    assert [i for i in range(len(before)) if before[i] != after[i]] == [100]
    assert (
        rec["old_byte"] == f"0x{before[100]:02x}" and rec["new_byte"] == f"0x{before[100] ^ 1:02x}"
    )


def test_truncate_keeps_exactly_offset_bytes(export: Path, tmp_path: Path) -> None:
    rec = corrupt_copy(export, tmp_path / "out", 777, "truncate", 1)
    assert Path(rec["path"]).read_bytes() == export.read_bytes()[:777]
    assert rec["kept"] == 777 and Path(rec["path"]).name == "judge_truncate_777_e.sql.gz"


def test_offset_bytes_percent_and_range() -> None:
    assert parse_offset("10", 100) == 10 and parse_offset("50%", 1000) == 500
    for bad in ("100", "-1", "100%"):
        with pytest.raises(ValueError, match="outside the file"):
            parse_offset(bad, 100)


def test_bad_mode_is_rejected(export: Path, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="mode"):
        corrupt_copy(export, tmp_path, 1, "shred", 1)


def _judge(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sim.judge", *args], cwd=ROOT, capture_output=True, text=True
    )


def test_judge_cli_errors_are_tool_errors(export: Path, tmp_path: Path) -> None:
    out = ["--out-dir", str(tmp_path)]
    assert _judge(str(export), "--offset", "99999999", *out).returncode == 3
    assert _judge(str(tmp_path / "missing.gz"), "--offset", "1", *out).returncode == 3
    assert _judge(str(export), "--offset", "1", "--mode", "x", *out).returncode == 3
    assert _judge(str(export), *out).returncode == 3  # usage error: not 2 (= CORRUPT)


def test_make_judge_test_end_to_end(export: Path, tmp_path: Path) -> None:
    env = os.environ | {"SCRATCH_DSN": ""}
    for mode, verdict in (("flip", "CORRUPT"), ("truncate", "CORRUPT")):
        args = [f"FILE={export}", "OFFSET=50%", f"MODE={mode}", f"JUDGE_DIR={tmp_path / 'j'}"]
        cmd = ["make", "-s", "--no-print-directory", "judge-test", *args]
        result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env)
        assert result.returncode == 0, result.stderr
        assert verdict in result.stdout and "eguard exit 2" in result.stdout
    assert sorted(p.suffix for p in (tmp_path / "j").iterdir()) == [
        ".gz", ".gz", ".html", ".html", ".json", ".json"
    ]  # fmt: skip
    usage = subprocess.run(["make", "-s", "judge-test"], cwd=ROOT, capture_output=True, text=True)
    assert usage.returncode != 0 and "usage" in usage.stderr
