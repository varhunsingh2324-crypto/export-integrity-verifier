"""Everything the dashboard shows, as pure functions over the saved JSON reports (no Streamlit
import, unit-tested). Page loads only read files; the upload view is the one place that runs the
engine, through the same `matrix.verify_one` as `eguard verify-all`."""

import json
import os
import re
import uuid
from pathlib import Path
from shutil import copyfileobj
from typing import Any, BinaryIO

from pydantic import BaseModel

from eguard.config import load_policy
from eguard.matrix import MatrixRow, report_stem, verify_one
from eguard.models import ExplainReport, Status, Verdict, VerifyReport
from eguard.report.html import write_reports

ROOT = Path(__file__).resolve().parent.parent
LAYERS = (1, 2, 3, 4, 5)


def reports_dir() -> Path:
    return Path(os.environ.get("EGUARD_REPORTS_DIR") or ROOT / "data" / "reports")


def uploads_dir() -> Path:
    return Path(os.environ.get("EGUARD_UPLOADS_DIR") or ROOT / "data" / "dev" / "uploads")


# --- status colours ---------------------------------------------------------------------------
# Okabe-Ito based, checked for colour-vision deficiency (tests/test_dashboard.py): every pair is
# >= 14 OKLab dE under deutan/protan/tritan simulation. Colour is never alone: symbol + word too.


class Style(BaseModel):
    fill: str
    text: str  # label colour on the fill, >= 4.5:1 contrast
    symbol: str


PASS_STYLE = Style(fill="#0072B2", text="#FFFFFF", symbol="✓")
WARN_STYLE = Style(fill="#E69F00", text="#0B0B0B", symbol="!")
FAIL_STYLE = Style(fill="#B03A00", text="#FFFFFF", symbol="✗")
SKIP_STYLE = Style(fill="#C8C8C8", text="#0B0B0B", symbol="–")
NEUTRAL_STYLE = Style(fill="#FFFFFF", text="#0B0B0B", symbol="")

STATUS_STYLE: dict[str, Style] = {
    Status.PASS: PASS_STYLE,
    Status.WARN: WARN_STYLE,
    Status.FAIL: FAIL_STYLE,
    Status.SKIP: SKIP_STYLE,
    Verdict.VERIFIED: PASS_STYLE,
    Verdict.SUSPECT: WARN_STYLE,
    Verdict.CORRUPT: FAIL_STYLE,
    Verdict.TOOL_ERROR: FAIL_STYLE,
    "OK": PASS_STYLE,  # gzip -t exit 0
    "ERROR": FAIL_STYLE,
    "n/a": SKIP_STYLE,
}


def style(status: str) -> Style:
    return STATUS_STYLE.get(status, NEUTRAL_STYLE)


def badge(status: str) -> str:
    """Symbol + word: readable without colour."""
    s = style(status).symbol
    return f"{s} {status}" if s else status


# --- loading ----------------------------------------------------------------------------------


def load_verify(path: Path) -> VerifyReport:
    return VerifyReport.model_validate_json(path.read_text())


def load_explain(path: Path) -> ExplainReport:
    return ExplainReport.model_validate_json(path.read_text())


def matrix(reports: Path) -> list[dict[str, Any]]:
    """The fault x layer matrix of verify_all.json, labelled for display."""
    if not (reports / "verify_all.json").exists():
        return []
    return matrix_frame(load_matrix(reports), Path(_matrix_root(reports)))


def load_matrix(reports: Path) -> list[MatrixRow]:
    path = reports / "verify_all.json"
    if not path.exists():
        return []
    return [MatrixRow.model_validate(r) for r in json.loads(path.read_text()).get("rows", [])]


def list_exports(reports: Path) -> list[tuple[str, Path]]:
    """(label, verify_*.json) for every saved verify report; matrix labels (fault IDs) first."""
    labels: dict[str, str] = {}
    if (reports / "verify_all.json").exists():
        root = Path(_matrix_root(reports))
        for row in load_matrix(reports):
            labels[report_stem(Path(row.path), root)] = display_label(row, root)
    found = sorted(p for p in reports.glob("verify_*.json") if p.name != "verify_all.json")
    return [(labels.get(p.stem, p.stem.removeprefix("verify_")), p) for p in found]


def display_label(row: MatrixRow, root: Path) -> str:
    """Fault ID (if any) and the path under the matrix root: `fault_source/v1.sql.gz` and
    `v1.sql.gz` must not collapse into one label."""
    path = Path(row.path)
    name = str(path.relative_to(root) if path.is_relative_to(root) else path.name)
    return name if row.label == path.name else f"{row.label} · {name}"


def _matrix_root(reports: Path) -> str:
    return json.loads((reports / "verify_all.json").read_text()).get("root", ".")


def list_explains(reports: Path) -> list[Path]:
    """explain_*.json, the incident pair (v1 -> v2) first."""
    found = sorted(reports.glob("explain_*.json"))
    return sorted(found, key=lambda p: p.stem != "explain_v1__v2")


# --- fault x layer matrix ---------------------------------------------------------------------


def gzip_says(code: int | None) -> str:
    if code is None:
        return "n/a"
    return "OK" if code == 0 else f"FAIL (exit {code})"


def disagrees(gzip_t: int | None, verdict: str) -> bool:
    """gzip -t and ExportGuard reach opposite conclusions about the file."""
    if gzip_t is None:
        return False
    return (gzip_t == 0 and verdict == Verdict.CORRUPT) or (
        gzip_t != 0 and verdict == Verdict.VERIFIED
    )


def matrix_frame(rows: list[MatrixRow], root: Path = Path(".")) -> list[dict[str, Any]]:
    """One dict per export: label, gzip, L1..L5 (status + reason), verdict, the gzip/eguard pair."""
    out = []
    for row in rows:
        r = row.report
        verdict = r.verdict.value if r else Verdict.TOOL_ERROR.value
        layers = {lr.layer: lr for lr in r.layers} if r else {}
        gz = gzip_says(row.gzip_t)
        rec: dict[str, Any] = {
            "label": display_label(row, root),
            "path": row.path,
            "gzip": gz,
            "verdict": verdict,
            "ral": r.ral if r else None,
            "versus": f"{gz.split(' ')[0]} / {verdict}",
            "disagrees": disagrees(row.gzip_t, verdict),
            "error": row.error,
        }
        for n in LAYERS:
            lr = layers.get(n)
            rec[f"L{n}"] = lr.status.value if lr else "ERROR"
            rec[f"L{n}_reason"] = lr.reason if lr else (row.error or "no report")
        out.append(rec)
    return out


# --- explain ----------------------------------------------------------------------------------

STEP_ORDER = ("rows", "width", "data", "compressor")


class Step(BaseModel):
    name: str
    label: str
    delta_bytes: float  # change in compressed bytes this step causes, applied in STEP_ORDER
    size_effect: float  # multiplicative effect, e.g. -0.2 for -20 %


def waterfall_steps(x: ExplainReport) -> tuple[int, list[Step], int]:
    """(old compressed bytes, steps, new compressed bytes). S = R x W / C is multiplicative, so
    each step multiplies the running size by (1 + size_effect); the byte deltas then add up to
    the new size within the decomposition's identity error (they depend on the step order)."""
    by_name = {f.name: f for f in x.decomposition.factors}
    size = float(x.old.compressed_bytes)
    steps = []
    for name in STEP_ORDER:
        f = by_name[name]
        effect = f.size_effect or 0.0
        steps.append(Step(name=name, label=f.label, delta_bytes=size * effect, size_effect=effect))
        size *= 1 + effect
    return x.old.compressed_bytes, steps, x.new.compressed_bytes


def column_rows(x: ExplainReport) -> list[dict[str, Any]]:
    """The width drill-down: one row per component, largest |delta width| first."""
    rows = sorted(x.columns, key=lambda c: c.rank_width)
    return [
        {
            "column": c.column if c.table is None else f"{c.table}.{c.column}",
            "old B/row": round(c.old_width, 1),
            "new B/row": round(c.new_width, 1),
            "Δ B/row": round(c.delta_width, 1),
            "old NULL %": _pct(c.old_null_fraction),
            "new NULL %": _pct(c.new_null_fraction),
            "old distinct": c.old_distinct,
            "new distinct": c.new_distinct,
            "Δ entropy bits": None if c.delta_entropy is None else round(c.delta_entropy, 3),
            "present": c.present,
        }
        for c in rows
    ]


def _pct(x: float | None) -> float | None:
    return None if x is None else round(100 * x, 1)


# --- upload -----------------------------------------------------------------------------------


class UploadResult(BaseModel):
    path: str
    row: MatrixRow
    json_path: str | None = None
    html_path: str | None = None


def safe_name(name: str) -> str:
    """The uploaded name, reduced to [A-Za-z0-9._-] (it becomes a path component)."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name).lstrip(".")
    return cleaned[:100] or "upload"


def verify_upload(
    name: str,
    data: BinaryIO,
    manifest: BinaryIO | None = None,
    *,
    out_root: Path | None = None,
    seed: int | None = None,
) -> UploadResult:
    """Copy the upload to data/dev/uploads/<uuid>/, verify it with the real engine (L5 when
    SCRATCH_DSN is set), and write its JSON + HTML report next to it."""
    folder = (out_root or uploads_dir()) / uuid.uuid4().hex
    folder.mkdir(parents=True)
    path = folder / safe_name(name)
    with path.open("wb") as fh:
        copyfileobj(data, fh, 1 << 20)
    manifest_path = None
    if manifest is not None:
        manifest_path = folder / "manifest.json"
        with manifest_path.open("wb") as fh:
            copyfileobj(manifest, fh, 1 << 20)
    row = verify_one(
        path,
        path.name,
        manifest_path,
        load_policy(),
        scratch_dsn=os.environ.get("SCRATCH_DSN") or None,
        seed=seed,
    )
    result = UploadResult(path=str(path), row=row)
    if row.report is not None:
        j, h = write_reports(row.report, folder, report_stem(path, folder), gzip_t=row.gzip_t)
        result.json_path, result.html_path = str(j), str(h)
    return result
