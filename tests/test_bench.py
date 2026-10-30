"""bench/scale.py pure helpers and the `make demo` wiring (no database)."""

import importlib.util
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def scale():
    spec = importlib.util.spec_from_file_location("bench_scale", ROOT / "bench" / "scale.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ENV = {
    "cpu": "Test CPU · 4 CPUs",
    "memory": "8.0 GiB RAM",
    "os": "Linux 6.0",
    "python": "3.12.3",
    "postgres": "16.10",
    "pg_dump": "pg_dump (PostgreSQL) 16.10",
    "pigz": "pigz 2.8",
    "gzip": "gzip 1.12",
    "commit": "abc1234",
}


def _run(scale_x: int, reimport: bool = False) -> dict:
    run = {
        "scale": scale_x,
        "rows": 300_000 * scale_x,
        "table_bytes": 123_000_000 * scale_x,
        "compressed_bytes": 40_000_000 * scale_x,
        "uncompressed_bytes": 80_000_000 * scale_x,
        "export_s": 7.0 * scale_x,
        "wall_s": 8.0 * scale_x,
        "peak_rss_mib": 97.5,
        "l5_sample_n": 2995,
        "layers": {1: "PASS", 2: "PASS", 3: "PASS", 4: "PASS", 5: "PASS"},
        "verdict": "VERIFIED",
        "ral": 5,
        "exit": 0,
    }
    if reimport:
        run["reimport"] = {"wall_s": 32.0, "db_bytes": 150_000_000, "rows": 300_000}
    return run


def test_config_section(scale):
    cfg = scale.load_bench_config()
    assert cfg.scales == [1, 3, 5]
    assert cfg.reimport_scale in cfg.scales
    assert cfg.disk_budget_bytes == 1_500_000_000


@pytest.mark.parametrize(
    ("project", "estimate", "ok"),
    [(1_000, 499, True), (1_000, 500, True), (1_000, 501, False)],
)
def test_fits_budget_boundary(scale, project, estimate, ok):
    assert scale.fits(project, estimate, 1_500) is ok


def test_estimate_is_linear_with_margin(scale):
    assert scale.estimate_bytes(1, 1_000_000) == round(1_000_000 * scale.MARGIN)
    assert scale.estimate_bytes(5, 1_000_000) == 5 * scale.estimate_bytes(1, 1_000_000)


def test_markdown_table_and_reimport(scale):
    md = scale.to_markdown([_run(1, True), _run(3)], ENV, None, datetime(2026, 10, 30, tzinfo=UTC))
    assert "| 1× | 300,000 | 123.0 MB | 40.0 MB | 80.0 MB | 7.0 s | 8.0 s | 5.0 | 10.0 |" in md
    assert "| 3× | 900,000 |" in md
    assert "VERIFIED RAL 5 (exit 0)" in md
    assert "| 32.0 s | 150.0 MB | 300,000 | 8.0 s | 4.0× |" in md
    assert "PostgreSQL 16.10" in md and "Test CPU" in md and "make bench" in md
    assert "Stopped early" not in md


def test_markdown_stop_reason_and_no_reimport(scale):
    md = scale.to_markdown([_run(3)], ENV, "5× was skipped: over budget.", datetime.now(UTC))
    assert "**Stopped early:** 5× was skipped: over budget." in md
    assert "Full re-import: not run" in md


def test_markdown_numbers_come_from_input(scale):
    """Rule 5: every number in the table rows is derived from the run dicts or ENV."""
    md = scale.to_markdown([_run(1, True)], ENV, None, datetime(2026, 10, 30, tzinfo=UTC))
    rows = [ln for ln in md.splitlines() if ln.startswith("| 1×")]
    allowed = {"1", "300,000", "123.0", "40.0", "80.0", "7.0", "8.0", "5.0", "10.0", "97.5"}
    allowed |= {"2995", "2", "3", "4", "5", "0", "32.0", "150.0", "4.0"}
    for row in rows:
        assert set(re.findall(r"\d[\d,]*(?:\.\d+)?", row)) <= allowed


def test_demo_wired():
    demo = (ROOT / "scripts" / "demo.sh").read_text().splitlines()
    assert "set -euo pipefail" in demo
    make = (ROOT / "Makefile").read_text()
    target = make.split("\ndemo:", 1)[1].split("\n\n", 1)[0]
    assert "scripts/demo.sh" in target and "not implemented" not in target


def _fault(fault: str, psql_exit: int, rows: int | None, error: str | None) -> dict:
    return {
        "fault": fault,
        "file": f"data/exports/{fault}.sql.gz",
        "psql_exit": psql_exit,
        "rows": rows,
        "psql_error": error,
        "source_rows": 65_000,
        "eguard": {
            "verdict": "CORRUPT",
            "exit": 2,
            "fails": ["l4_fingerprint"],
            "first_message": "chunk 4 of 7",
        },
    }


def test_proves_section_from_measured_results(scale):
    run = _run(1, True) | {"l5_scratch_bytes": 1_277_952}
    faults = [
        _fault("F5", 0, 65_000, None),
        _fault("F1", 3, None, "ERROR:  bad"),
    ]
    md = scale.to_markdown([run], ENV, None, datetime.now(UTC), faults)
    assert "### What re-import proves vs what ExportGuard proves" in md
    assert "| F5 `data/exports/F5.sql.gz` | 0 | 65,000 / 65,000 | – | CORRUPT (exit 2) |" in md
    assert "| 3 | table not created / 65,000 | `ERROR:  bad` |" in md
    assert "**F5**: psql reported success and loaded 65,000 of 65,000 rows" in md
    assert "**F1**: psql failed (exit 3) and loaded 0 of 65,000 rows" in md
    assert "used 150.0 MB of database space" in md and "2,995-row sample into 1.2 MiB" in md


def test_no_proves_section_without_faults(scale):
    md = scale.to_markdown([_run(1, True)], ENV, None, datetime.now(UTC))
    assert "What re-import proves" not in md
