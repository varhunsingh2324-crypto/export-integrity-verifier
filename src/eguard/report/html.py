"""Render a VerifyReport, or an ExplainReport, as one self-contained HTML page (inline CSS, no
script, no external URL), and write it next to the report's JSON."""

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from eguard import forensics
from eguard.models import ExplainReport, IntegrityRef, VerifyReport
from eguard.report import view

MAX_LOCATIONS = 50  # rows of the "where" table; the JSON keeps every one

_env = Environment(
    loader=PackageLoader("eguard.report", "templates"),
    autoescape=select_autoescape(["j2", "html"], default_for_string=True),  # evidence is dump text
    trim_blocks=True,
    lstrip_blocks=True,
)


def _evidence(evidence: dict[str, Any]) -> str:
    return json.dumps(evidence, indent=2, ensure_ascii=False, default=str)


def render_html(r: VerifyReport, *, gzip_t: int | None = None) -> str:
    locs = view.locations(r)
    template = _env.get_template("report.html.j2")
    return template.render(
        r=r,
        summary=view.summary(r),
        layers=[(lr, [c for c in r.checks if c.layer == lr.layer]) for lr in r.layers],
        locations=[(loc, view.where(loc)) for loc in locs[:MAX_LOCATIONS]],
        locations_more=max(0, len(locs) - MAX_LOCATIONS),
        confidence=view.confidence(r),
        prov=view.provenance(r),
        gzip_t=gzip_t,
        evidence=_evidence,
    )


def write_reports(
    r: VerifyReport, out_dir: Path, stem: str, *, gzip_t: int | None = None
) -> tuple[Path, Path]:
    """`<out_dir>/<stem>.json` (the VerifyReport, as `verify --json`) and `<stem>.html`."""
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path, html_path = out_dir / f"{stem}.json", out_dir / f"{stem}.html"
    json_path.write_text(r.model_dump_json(indent=2) + "\n")
    html_path.write_text(render_html(r, gzip_t=gzip_t), encoding="utf-8")
    return json_path, html_path


HYPOTHESIS = {
    "H1": "H1: compressor or level changed (the ratio gap disappears at an equal level)",
    "H2/H3": "H2/H3: the data changed (the ratio gap persists at an equal level)",
    "mixed": "mixed: both the data and the compressor settings contribute",
    "none": "none: the compression ratio did not change enough to attribute",
}


def _value(name: str, v: float) -> str:
    if name == "rows":
        return forensics.fmt_count(v)
    if name == "width":
        return forensics.fmt_width(v)
    return forensics.fmt_ratio(v)


def load_verify_report(ref: IntegrityRef) -> VerifyReport | None:
    if ref.status != "found" or ref.report is None:
        return None
    try:
        return VerifyReport.model_validate_json(Path(ref.report).read_text())
    except (OSError, ValueError):
        return None


def render_explain_html(x: ExplainReport, new_report: VerifyReport | None, top: int) -> str:
    d = x.decomposition
    steps = [abs(f.effect_ln) for f in d.factors if f.effect_ln is not None]
    biggest = max(steps, default=0.0) or 1.0
    factors = [
        (f, None if f.effect_ln is None else round(100 * abs(f.effect_ln) / biggest, 1))
        for f in d.factors
    ]
    f = forensics
    return _env.get_template("explain.html.j2").render(
        x=x,
        d=d,
        factors=factors,
        new_report=new_report,
        new_summary=view.summary(new_report) if new_report else [],
        hypothesis_text=HYPOTHESIS[x.hypothesis],
        columns=x.columns[:top],
        columns_more=max(0, len(x.columns) - top),
        value=_value,
        fmt_change=f.fmt_change,
        fmt_bytes=f.fmt_bytes,
        fmt_count=f.fmt_count,
        fmt_fraction=f.fmt_fraction,
        fmt_mib=f.fmt_mib,
        fmt_ratio=f.fmt_ratio,
    )


def write_explain_reports(
    x: ExplainReport, out_dir: Path, stem: str, top: int
) -> tuple[Path, Path]:
    """`<out_dir>/<stem>.json` (= `explain --json`) and `<stem>.html`; verify reports untouched."""
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path, html_path = out_dir / f"{stem}.json", out_dir / f"{stem}.html"
    json_path.write_text(x.model_dump_json(indent=2) + "\n")
    html = render_explain_html(x, load_verify_report(x.integrity_new), top)
    html_path.write_text(html, encoding="utf-8")
    return json_path, html_path
