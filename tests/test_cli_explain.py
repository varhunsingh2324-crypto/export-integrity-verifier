import re
from pathlib import Path

from markupsafe import escape
from typer.testing import CliRunner

from eguard.cli import app
from eguard.config import load_policy
from eguard.models import ExplainReport
from eguard.report.html import write_reports
from eguard.verify import verify_file
from tests import pgdump
from tests.gzutil import member

runner = CliRunner(env={"SCRATCH_DSN": ""})  # hermetic, as tests/test_cli_verify.py


def _pair(tmp_path: Path) -> tuple[Path, Path]:
    old, new = tmp_path / "old.sql.gz", tmp_path / "new.sql.gz"
    old.write_bytes(member(pgdump.dump_bytes(600), level=6))
    new.write_bytes(member(pgdump.dump_bytes(780), level=1, xfl=4))
    return old, new


def test_explain_json_round_trips(tmp_path: Path) -> None:
    old, new = _pair(tmp_path)
    args = ["explain", "--json", "--reports", str(tmp_path / "none"), str(old), str(new)]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    x = ExplainReport.model_validate_json(result.stdout)
    assert x.old.rows == 600 and x.new.rows == 780
    assert x.new.xfl == 4 and x.new.level_hint == "fastest (-1)"
    assert x.integrity_new.status == "none" and len(x.narrative) == 6


def test_explain_console_output(tmp_path: Path) -> None:
    old, new = _pair(tmp_path)
    result = runner.invoke(app, ["explain", "--reports", str(tmp_path), str(old), str(new)])
    assert result.exit_code == 0, result.output
    for text in ("S = R × W ÷ C", "probe:", "hypothesis:", "narrative:", "Rows +30.0 %"):
        assert text in result.stdout


def test_explain_missing_file_is_a_tool_error(tmp_path: Path) -> None:
    old, _ = _pair(tmp_path)
    result = runner.invoke(app, ["explain", "--json", str(old), str(tmp_path / "nope.gz")])
    assert result.exit_code == 3
    assert '"verdict": "TOOL_ERROR"' in result.stdout


def test_explain_without_rows_is_a_tool_error(tmp_path: Path) -> None:
    old, new = _pair(tmp_path)
    old.write_bytes(member(pgdump.dump_bytes(body=[])))
    result = runner.invoke(app, ["explain", "--json", str(old), str(new)])
    assert result.exit_code == 3 and "no COPY rows" in result.stdout


def test_explain_report_dir_writes_self_contained_html(tmp_path: Path) -> None:
    old, new = _pair(tmp_path)
    reports = tmp_path / "reports"
    write_reports(verify_file(new, load_policy(), seed=1), reports, "verify_new")
    args = ["explain", "--reports", str(reports), "--report-dir", str(reports), str(old), str(new)]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    x = ExplainReport.model_validate_json((reports / "explain_old__new.json").read_text())
    html = (reports / "explain_old__new.html").read_text()
    assert not re.search(r"https?://|<script|<link|@import|src=|url\(", html, re.I)
    assert 'class="banner SUSPECT"' in html  # the new export's own verify verdict
    assert "Decomposition S = R × W ÷ C" in html and "Re-compress probe" in html
    for sentence in x.narrative:
        assert str(escape(sentence)) in html
    assert (reports / "verify_new.json").exists()  # verify reports are left alone
