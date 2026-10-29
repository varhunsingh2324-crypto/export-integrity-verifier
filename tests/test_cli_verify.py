import json
from pathlib import Path

from typer.testing import CliRunner

from eguard.cli import app
from eguard.models import VerifyReport
from tests.gzutil import dump_like, member

runner = CliRunner()
DATA = dump_like(500)


def _file(tmp_path: Path, blob: bytes) -> Path:
    path = tmp_path / "export.gz"
    path.write_bytes(blob)
    return path


def test_verify_healthy_is_suspect_until_l2_l5(tmp_path: Path) -> None:
    result = runner.invoke(app, ["verify", str(_file(tmp_path, member(DATA)))])
    assert result.exit_code == 1, result.stdout
    assert "SUSPECT" in result.stdout and "l1_integrity" in result.stdout


def test_verify_truncated_is_corrupt(tmp_path: Path) -> None:
    blob = member(DATA)
    result = runner.invoke(app, ["verify", "--json", str(_file(tmp_path, blob[:-20]))])
    assert result.exit_code == 2
    report = VerifyReport.model_validate_json(result.stdout)
    assert report.verdict == "CORRUPT"


def test_verify_missing_file_is_tool_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["verify", "--json", str(tmp_path / "nope.gz")])
    assert result.exit_code == 3
    assert json.loads(result.stdout)["verdict"] == "TOOL_ERROR"
