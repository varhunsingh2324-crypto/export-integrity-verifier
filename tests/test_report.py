import re
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from eguard.cli import app
from eguard.config import load_policy
from eguard.matrix import report_stem
from eguard.models import CheckResult, Severity, Status, Verdict, VerifyReport
from eguard.report import view
from eguard.report.html import render_html, write_reports
from eguard.verdict import build_report
from tests import pgdump
from tests.gzutil import member

POLICY = load_policy()
runner = CliRunner(env={"SCRATCH_DSN": ""})  # hermetic, as tests/test_cli_verify.py
TABLE = "public.transactions"
STATEMENT = "If ≥0.1% of rows were unrestorable, this drill would have caught it (95% probability)"


def c(
    layer: int, name: str, status: Status = Status.PASS, message: str = "ok", **ev: Any
) -> CheckResult:
    return CheckResult(
        layer=layer,
        name=name,
        status=status,
        severity=Severity.CRITICAL,
        evidence=ev,
        message=message,
    )


def healthy() -> list[CheckResult]:
    return [
        c(1, "l1_format", compressor="gzip", level_hint="default/unspecified"),
        c(2, "l2_header", dumped_by="pg_dump version 16.15", dumped_from="database version 16.15"),
        c(2, "l2_tables", per_table={TABLE: {"rows": 1000}}),
        c(3, "l3_row_validity", examples=[]),
        c(4, "l4_manifest_signature", created_at="2026-10-29T17:49:54+00:00", signed=True),
        c(4, "l4_snapshot_counts", snapshot_id="00000003-0000164B-1", taken_at="2026-10-29 17:49"),
        c(4, "l4_compressed_sha256", manifest={"compressor": "pigz -6"}),
        c(5, "l5_sample", seed=5),
        c(
            5,
            "l5_round_trip",
            tables=[{"table": TABLE, "round_tripped": 1000, "mismatched": []}],
            confidence_statements=[STATEMENT],
        ),
    ]


def report(checks: list[CheckResult], manifest: str | None = "m.json") -> VerifyReport:
    return build_report("export.sql.gz", checks, POLICY, manifest)


def replace(checks: list[CheckResult], new: CheckResult) -> list[CheckResult]:
    return [new if old.name == new.name else old for old in checks]


def sentences(r: VerifyReport) -> int:
    return len(view.summary(r))


def damaged() -> VerifyReport:
    chunk = {"table": TABLE, "chunk": 3, "of": 7, "rows": [20001, 30000], "lines": [20051, 30050]}
    fp = c(4, "l4_fingerprint", Status.FAIL, "content differs", damaged_chunks=[chunk])
    open_copy = {"table": TABLE, "rows": 29485, "last_row_line": 29535, "header_line": 50}
    l2 = c(2, "l2_complete", Status.FAIL, "cut", open_copy=open_copy, lines=29536)
    l2.evidence["partial_line_bytes"] = 63
    return report([*healthy(), fp, l2])


def test_verified_banner_summary_confidence_provenance() -> None:
    r = report(healthy())
    assert r.verdict == Verdict.VERIFIED
    html = render_html(r)
    assert 'class="banner VERIFIED"' in html and "RAL 5/5" in html
    assert 2 <= sentences(r) <= 3
    assert "1,000 rows in 1 table were checked" in view.summary(r)[1]
    assert STATEMENT in html
    for text in ("pigz -6", "pg_dump version 16.15", "00000003-0000164B-1", "signature valid"):
        assert text in html
    assert "seed" in html and ">5<" in html


def test_corrupt_locates_chunk_rows_and_lines() -> None:
    r = damaged()
    assert r.verdict == Verdict.CORRUPT
    places = [view.where(loc) for loc in view.locations(r)]
    assert f"{TABLE}, row 29,485, dump line 29,535" in places
    assert f"{TABLE}, chunk 3 of 7, rows 20,001–30,000, dump lines 20,051–30,050" in places
    summary = view.summary(r)
    assert 2 <= len(summary) <= 3
    assert summary[0].startswith("Do not rely on this export")
    assert "row 29,485" in summary[1]  # the first location, in layer order
    html = render_html(r)
    assert "chunk 3 of 7" in html and "partial row of 63 bytes" in html
    assert "only covers rows that are in this file" in html  # a passing drill is no reassurance


def test_l1_member_crc_points_at_the_member_not_a_byte() -> None:
    bad = {"offset": 0, "crc32_actual": "0x1", "crc32_expected": "0x2"}
    r = report(healthy() + [c(1, "l1_integrity", Status.FAIL, "crc", detail=[bad])])
    (loc,) = view.locations(r)
    assert loc.byte_offset is None and "member starting at compressed byte 0" in loc.detail


def test_suspect_without_manifest_or_drill() -> None:
    checks = [x for x in healthy() if x.layer < 4 or x.name == "l5_sample"]
    checks.append(c(4, "l4_manifest", Status.SKIP, "no manifest: nothing records it; export"))
    checks.append(c(5, "l5_restore", Status.SKIP, "no scratch database (SCRATCH_DSN unset)"))
    r = report(checks, manifest=None)
    assert r.verdict == Verdict.SUSPECT
    summary = view.summary(r)
    assert 2 <= len(summary) <= 3
    assert "L4 reconciliation, L5 restore drill lack full evidence" in summary[0]
    assert "eguard export" in summary[2]
    assert view.provenance(r).manifest_status == "no manifest"
    assert view.provenance(r).snapshot_id is None
    (why,) = view.confidence(r)
    assert "l5_restore SKIP" in why and "SCRATCH_DSN" in why
    assert "not recorded" in render_html(r)


def test_bad_signature_is_shown_untrusted() -> None:
    sig = c(4, "l4_manifest_signature", Status.FAIL, "manifest signature invalid", signed=True)
    assert view.provenance(report(replace(healthy(), sig))).manifest_status.startswith("untrusted")


def test_self_contained_no_external_requests() -> None:
    for r in (report(healthy()), damaged()):
        html = render_html(r, gzip_t=1)
        assert not re.search(r"https?://|<script|<link|@import|src=|url\(", html, re.I)
        assert "<style>" in html


def test_dump_text_is_escaped() -> None:
    evil = "<script>alert(1)</script>"
    example = {"line": 9, "table": TABLE, "column": "c", "reason": "type", "value": evil}
    bad = c(3, "l3_row_validity", Status.FAIL, f"bad {evil}", examples=[example])
    html = render_html(report(replace(healthy(), bad)))
    assert "<script" not in html and "&lt;script&gt;" in html


def test_write_reports_round_trip_and_rerender(tmp_path: Path) -> None:
    r = damaged()
    json_path, html_path = write_reports(r, tmp_path, "verify_x", gzip_t=0)
    assert VerifyReport.model_validate_json(json_path.read_text()) == r
    assert "gzip -t" in html_path.read_text()
    out = tmp_path / "again.html"
    result = runner.invoke(app, ["report", str(json_path), "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert "chunk 3 of 7" in out.read_text()


def test_report_command_bad_json_is_tool_error(tmp_path: Path) -> None:
    bad = tmp_path / "x.json"
    bad.write_text("{}")
    assert runner.invoke(app, ["report", str(bad)]).exit_code == 3


def test_report_stem_keeps_subdirectories_apart(tmp_path: Path) -> None:
    a = report_stem(tmp_path / "fault_source" / "v2.sql.gz", tmp_path)
    b = report_stem(tmp_path / "v2.sql.gz", tmp_path)
    assert (a, b) == ("verify_fault_source__v2", "verify_v2")
    assert report_stem(tmp_path / "F4_bitflip.sql.Z", tmp_path) == "verify_F4_bitflip"


def test_cli_verify_writes_json_and_html(tmp_path: Path) -> None:
    export = tmp_path / "killed.sql.gz"
    export.write_bytes(member(pgdump.killed_at(500, 321)))
    out = tmp_path / "reports"
    result = runner.invoke(app, ["verify", str(export), "--report-dir", str(out)])
    assert result.exit_code == 2
    r = VerifyReport.model_validate_json((out / "verify_killed.json").read_text())
    assert r.verdict == Verdict.CORRUPT and r.generated_at
    html = (out / "verify_killed.html").read_text()
    assert "CORRUPT" in html and f"{TABLE}, row 321" in html
