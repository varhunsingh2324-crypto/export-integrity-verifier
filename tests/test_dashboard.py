import io
import re
from pathlib import Path

import numpy as np
import pytest
from streamlit.testing.v1 import AppTest
from typer.testing import CliRunner

from dashboard import data as D
from eguard.cli import app
from eguard.config import load_policy
from eguard.models import Status, Verdict
from tests import pgdump
from tests.gzutil import member
from tests.rename import signature

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "dashboard" / "app.py"
runner = CliRunner(env={"SCRATCH_DSN": ""})  # hermetic, as tests/test_cli_verify.py


def _flipped(blob: bytes) -> bytes:
    mid = len(blob) // 2
    return blob[:mid] + bytes([blob[mid] ^ 1]) + blob[mid + 1 :]


@pytest.fixture(scope="module")
def reports(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A small, real data/reports: verify-all over three exports + one explain pair."""
    base = tmp_path_factory.mktemp("dash")
    exports, out = base / "exports", base / "reports"
    exports.mkdir()
    healthy = member(pgdump.dump_bytes(600))
    (exports / "v1.sql.gz").write_bytes(healthy)
    (exports / "v2.sql.gz").write_bytes(member(pgdump.dump_bytes(780), level=1, xfl=4))
    (exports / "bitrot.sql.gz").write_bytes(_flipped(healthy))
    (exports / "cut.sql.gz").write_bytes(healthy[: len(healthy) // 2])
    (exports / "sub").mkdir()  # same name in a subdirectory, as data/exports/fault_source/
    (exports / "sub" / "v1.sql.gz").write_bytes(healthy)
    args = ["verify-all", str(exports), "--out", str(out / "verify_all.json")]
    result = runner.invoke(app, [*args, "--report-dir", str(out)])
    assert result.exit_code == 2, result.output
    pair = [str(exports / "v1.sql.gz"), str(exports / "v2.sql.gz")]
    result = runner.invoke(app, ["explain", "--report-dir", str(out), "--reports", str(out), *pair])
    assert result.exit_code == 0, result.output
    return out


# --- colours ----------------------------------------------------------------------------------


def _lin(hexcode: str) -> np.ndarray:
    c = np.array([int(hexcode[i : i + 2], 16) for i in (1, 3, 5)], float) / 255
    return np.where(c <= 0.04045, c / 12.92, ((c + 0.055) / 1.055) ** 2.4)


def _contrast(a: str, b: str) -> float:
    lum = sorted(float(np.dot([0.2126, 0.7152, 0.0722], _lin(h))) for h in (a, b))
    return (lum[1] + 0.05) / (lum[0] + 0.05)


CVD = {  # Machado et al. 2009, severity 1.0, on linear RGB
    "none": np.eye(3),
    "deutan": np.array([[0.367, 0.861, -0.228], [0.280, 0.673, 0.047], [-0.012, 0.043, 0.969]]),
    "protan": np.array([[0.152, 1.053, -0.205], [0.115, 0.786, 0.099], [-0.004, -0.048, 1.052]]),
    "tritan": np.array([[1.256, -0.077, -0.179], [-0.078, 0.931, 0.148], [0.005, 0.691, 0.304]]),
}
_M1 = np.array([[0.4122, 0.5363, 0.0514], [0.2119, 0.6807, 0.1074], [0.0883, 0.2817, 0.6300]])
_M2 = np.array([[0.2105, 0.7936, -0.0041], [1.9780, -2.4286, 0.4506], [0.0259, 0.7828, -0.8087]])


def _oklab(rgb: np.ndarray) -> np.ndarray:
    return _M2 @ np.cbrt(_M1 @ np.clip(rgb, 0, 1))


def test_status_colours_are_colour_blind_safe_and_labelled() -> None:
    styles = [D.PASS_STYLE, D.WARN_STYLE, D.FAIL_STYLE, D.SKIP_STYLE]
    assert len({s.fill for s in styles}) == 4 and len({s.symbol for s in styles}) == 4
    for s in styles:
        assert _contrast(s.fill, s.text) >= 4.5, s
    for i, a in enumerate(styles):
        for b in styles[i + 1 :]:
            for name, m in CVD.items():
                de = 100 * np.linalg.norm(_oklab(m @ _lin(a.fill)) - _oklab(m @ _lin(b.fill)))
                assert de >= (15 if name == "none" else 8), (a.fill, b.fill, name, de)
    assert D.badge("FAIL") == "✗ FAIL" and D.badge("CORRUPT") == "✗ CORRUPT"
    assert D.style(Verdict.SUSPECT) == D.STATUS_STYLE[Status.WARN]


# --- matrix -----------------------------------------------------------------------------------


def test_matrix_frame_flags_where_gzip_t_disagrees(reports: Path) -> None:
    frame = {r["label"]: r for r in D.matrix(reports)}
    assert set(frame) == {"v1.sql.gz", "v2.sql.gz", "bitrot.sql.gz", "cut.sql.gz", "sub/v1.sql.gz"}
    healthy, cut = frame["v1.sql.gz"], frame["cut.sql.gz"]
    assert healthy["gzip"] == "OK" and healthy["verdict"] == "SUSPECT" and not healthy["disagrees"]
    assert healthy["versus"] == "OK / SUSPECT" and healthy["L4"] == "SKIP"
    assert cut["gzip"].startswith("FAIL") and cut["verdict"] == "CORRUPT"
    assert cut["versus"] == "FAIL / CORRUPT" and not cut["disagrees"]
    assert all(r[f"L{n}_reason"] for r in frame.values() for n in D.LAYERS)


def test_disagreement_and_missing_gzip() -> None:
    assert D.disagrees(0, "CORRUPT") and D.disagrees(1, "VERIFIED")
    assert not D.disagrees(0, "SUSPECT") and not D.disagrees(None, "CORRUPT")
    assert D.gzip_says(None) == "n/a" and D.gzip_says(1) == "FAIL (exit 1)"


def test_matrix_row_with_tool_error() -> None:
    from eguard.matrix import MatrixRow

    row = MatrixRow(path="x.gz", label="x.gz", manifest=None, gzip_t=None, error="boom")
    (rec,) = D.matrix_frame([row])
    assert rec["verdict"] == "TOOL_ERROR" and rec["L1"] == "ERROR" and rec["L1_reason"] == "boom"


def test_list_exports_labels_from_the_matrix(reports: Path) -> None:
    labels = {p.stem: label for label, p in D.list_exports(reports)}
    assert labels == {
        "verify_bitrot": "bitrot.sql.gz",
        "verify_cut": "cut.sql.gz",
        "verify_v1": "v1.sql.gz",
        "verify_v2": "v2.sql.gz",
        "verify_sub__v1": "sub/v1.sql.gz",  # labels stay unique across subdirectories
    }


# --- explain ----------------------------------------------------------------------------------


def test_waterfall_steps_add_up_to_the_new_size(reports: Path) -> None:
    x = D.load_explain(reports / "explain_v1__v2.json")
    old, steps, new = D.waterfall_steps(x)
    assert [s.name for s in steps] == list(D.STEP_ORDER)
    assert old == x.old.compressed_bytes and new == x.new.compressed_bytes
    assert steps[0].size_effect == pytest.approx(0.3)  # 600 -> 780 rows
    tolerance = load_policy()["explain"]["identity_tolerance"]
    assert abs((old + sum(s.delta_bytes for s in steps)) / new - 1) <= tolerance


def test_column_rows_largest_change_first(reports: Path) -> None:
    rows = D.column_rows(D.load_explain(reports / "explain_v1__v2.json"))
    deltas = [abs(r["Δ B/row"]) for r in rows]
    assert deltas == sorted(deltas, reverse=True)
    assert {"column", "old NULL %", "new distinct"} <= set(rows[0])


def test_list_explains_puts_the_incident_first(tmp_path: Path) -> None:
    for stem in ("explain_a__b", "explain_v1__v2", "explain_z__y"):
        (tmp_path / f"{stem}.json").write_text("{}")
    assert [p.stem for p in D.list_explains(tmp_path)][0] == "explain_v1__v2"


# --- upload -----------------------------------------------------------------------------------


def test_verify_upload_writes_reports_and_ignores_the_name(tmp_path: Path) -> None:
    blob = _flipped(member(pgdump.dump_bytes(600)))
    a = D.verify_upload("../../etc/x y.sql.gz", io.BytesIO(blob), out_root=tmp_path, seed=1)
    b = D.verify_upload("random.bin", io.BytesIO(blob), out_root=tmp_path, seed=1)
    assert Path(a.path).parent.parent == tmp_path and Path(a.path).name == "x_y.sql.gz"
    assert a.row.report is not None and b.row.report is not None
    assert a.row.report.verdict == Verdict.CORRUPT and a.row.gzip_t not in (0,)
    assert signature(a.row.report)[:2] == signature(b.row.report)[:2]
    assert [c.status for c in a.row.report.checks] == [c.status for c in b.row.report.checks]
    assert Path(a.html_path).read_text().startswith("<!doctype html>")  # type: ignore[arg-type]
    assert Path(a.json_path).exists()  # type: ignore[arg-type]


def test_verify_upload_bad_manifest_is_reported_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blob = member(pgdump.dump_bytes(200))
    monkeypatch.delenv("MANIFEST_HMAC_KEY", raising=False)
    r = D.verify_upload("a.gz", io.BytesIO(blob), io.BytesIO(b"{}"), out_root=tmp_path)
    assert r.row.report is None and "MANIFEST_HMAC_KEY" in (r.row.error or "")
    monkeypatch.setenv("MANIFEST_HMAC_KEY", "k")
    r = D.verify_upload("a.gz", io.BytesIO(blob), io.BytesIO(b"not json"), out_root=tmp_path)
    assert r.row.report is not None and r.row.report.verdict == Verdict.CORRUPT
    sig = next(c for c in r.row.report.checks if c.name == "l4_manifest_signature")
    assert sig.status == Status.FAIL


# --- the app itself ---------------------------------------------------------------------------


def _run(monkeypatch: pytest.MonkeyPatch, reports: Path) -> AppTest:
    monkeypatch.setenv("EGUARD_REPORTS_DIR", str(reports))
    at = AppTest.from_file(str(APP), default_timeout=60)
    at.run()
    assert not at.exception, at.exception
    return at


def test_app_renders_every_tab(reports: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    at = _run(monkeypatch, reports)
    assert at.selectbox[0].value.stem == "verify_v2"  # the incident export by default
    page = " ".join(m.value for m in at.markdown)
    assert "SUSPECT" in page and "RAL" in page and "Where in the stream" not in page
    assert "Size = rows × bytes per row ÷ compression ratio" in page
    assert "gzip -t" in page and "Rows +30.0 %" in page
    at.selectbox[0].select(reports / "verify_bitrot.json").run()
    assert not at.exception
    page = " ".join(m.value for m in at.markdown)
    assert "CORRUPT" in page and "Where in the stream" in page
    assert any("L1 container" in e.label and "FAIL" in e.label for e in at.expander)


def test_app_without_reports_says_what_to_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    at = _run(monkeypatch, tmp_path)
    infos = " ".join(i.value for i in at.info)
    assert "make verify-all" in infos and "make explain" in infos


def test_no_external_network() -> None:
    sources = [*sorted((ROOT / "dashboard").glob("*.py")), ROOT / ".streamlit" / "config.toml"]
    for path in sources:
        urls = re.findall(r"https?://[^\s'\"]+", path.read_text())
        assert all(u.startswith(("http://localhost", "http://127.0.0.1")) for u in urls), path
    config = (ROOT / ".streamlit" / "config.toml").read_text()
    assert re.search(r"^gatherUsageStats = false", config, re.M)
