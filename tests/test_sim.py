import gzip
import hashlib
import os
import re
from pathlib import Path

import pytest

from sim.incident import (
    ROOT,
    IncidentResult,
    drop_schema,
    load_sim_config,
    pct_change,
    run_incident,
    scaled_rows,
)

LEGACY = ROOT / "scripts" / "legacy_export.sh"
TEST_SCALE = 0.02  # 20 000 rows: seconds, not minutes


def test_sim_config_loads() -> None:
    cfg = load_sim_config()
    assert cfg.base_rows == 1_000_000
    assert -1 <= cfg.seed <= 1
    assert cfg.growth.fraction == cfg.targets.rows_change.value


def test_sim_config_rejects_bad_seed(tmp_path: Path) -> None:
    text = (ROOT / "config" / "sim.yaml").read_text().replace("seed: 0.42", "seed: 3")
    bad = tmp_path / "sim.yaml"
    bad.write_text(text)
    with pytest.raises(ValueError):
        load_sim_config(bad)


@pytest.mark.parametrize(("scale", "rows"), [(1.0, 1_000_000), (0.02, 20_000), (2.5, 2_500_000)])
def test_scaled_rows(scale: float, rows: int) -> None:
    assert scaled_rows(load_sim_config(), scale) == rows


@pytest.mark.parametrize("scale", [0.0, -1.0])
def test_scaled_rows_rejects_nonpositive(scale: float) -> None:
    with pytest.raises(ValueError):
        scaled_rows(load_sim_config(), scale)


def test_pct_change() -> None:
    assert pct_change(100, 130) == pytest.approx(0.30)
    assert pct_change(100, 80) == pytest.approx(-0.20)


def test_legacy_export_is_deliberately_naive() -> None:
    text = LEGACY.read_text()
    code = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    assert not any("pipefail" in ln or "set -e" in ln or "PIPESTATUS" in ln for ln in code)
    assert "DELIBERATELY NAIVE" in text
    assert re.search(r"pg_dump .*\| gzip > ", text)
    assert os.access(LEGACY, os.X_OK)


@pytest.fixture(scope="module")
def incident_runs(tmp_path_factory: pytest.TempPathFactory) -> list[IncidentResult]:
    if not os.environ.get("PG_DSN"):
        pytest.skip("PG_DSN not set (copy .env.example to .env and run `make up`)")
    cfg = load_sim_config()
    schema = "eguard_test"
    try:
        return [
            run_incident(cfg, TEST_SCALE, schema, tmp_path_factory.mktemp(f"run{i}"))
            for i in range(2)
        ]
    finally:
        drop_schema(schema)


@pytest.mark.db
def test_incident_hits_targets(incident_runs: list[IncidentResult]) -> None:
    result = incident_runs[0]
    assert result.v1.rows == 20_000
    assert result.v2.rows == 26_000
    assert result.rows_ok, result.rows_change
    assert result.size_ok, result.size_change


def _content_digest(path: Path) -> str:
    """sha256 of the decompressed dump, streamed, minus pg_dump's per-run random lines.

    pg_dump >= 16.10 writes `\\restrict <random key>` / `\\unrestrict <random key>` into every
    plain dump (CVE-2025-8714), so gzip sizes differ by a few bytes between identical datasets.
    """
    digest = hashlib.sha256()
    with gzip.open(path, "rb") as fh:
        for line in fh:
            if not line.startswith((b"\\restrict ", b"\\unrestrict ")):
                digest.update(line)
    return digest.hexdigest()


@pytest.mark.db
def test_incident_is_reproducible(incident_runs: list[IncidentResult]) -> None:
    first, second = incident_runs
    for a, b in ((first.v1, second.v1), (first.v2, second.v2)):
        assert (a.rows, a.raw_bytes) == (b.rows, b.raw_bytes)
        assert _content_digest(a.path) == _content_digest(b.path)
