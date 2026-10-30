"""Render a VerifyReport as one self-contained HTML page (inline CSS, no script, no external URL),
and write it next to the report's JSON."""

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from eguard.models import VerifyReport
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
