"""scripts/export_with_manifest.sh end to end against the real database (pytest -m db)."""

import os
import subprocess
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from eguard.config import load_policy
from eguard.manifest import file_sha256, load, signature_ok
from eguard.models import Manifest, Status
from eguard.verify import verify_file
from sim.incident import (
    LEGACY_EXPORT,
    ROOT,
    count_rows,
    drop_schema,
    load_sim_config,
    run_sql,
    scaled_rows,
    seed,
)
from tests.pgdump import COLUMNS

pytestmark = pytest.mark.db

SCRIPT = ROOT / "scripts" / "export_with_manifest.sh"
KEY = "export-script-test-key"
SCHEMA = "eguard_test_export"
POLICY = load_policy()


@pytest.fixture(scope="module")
def table() -> Iterator[str]:
    if not os.environ.get("PG_DSN"):
        pytest.skip("PG_DSN not set (copy .env.example to .env and run `make up`)")
    cfg = load_sim_config()
    try:
        seed(cfg, scaled_rows(cfg, 0.02), SCHEMA)
        yield f"{SCHEMA}.{cfg.table}"
    finally:
        drop_schema(SCHEMA)


def export(tmp_path: Path, table: str, **env: str) -> subprocess.CompletedProcess[str]:
    cmd = [str(SCRIPT), "-m", str(tmp_path / "e.manifest.json"), str(tmp_path / "e.sql.gz"), table]
    return subprocess.run(
        cmd,
        env=os.environ | {"MANIFEST_HMAC_KEY": KEY} | env,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


def scratch_dsn() -> str:
    dsn = os.environ.get("SCRATCH_DSN")
    if not dsn:
        pytest.skip("SCRATCH_DSN not set (copy .env.example to .env and run `make up`)")
    return dsn


def test_without_scratch_db_is_suspect_and_says_so(tmp_path: Path, table: str) -> None:
    proc = export(tmp_path, table, SCRATCH_DSN="")
    assert proc.returncode == 1, proc.stderr  # the script never claims more than verify proved
    assert "SUSPECT (exit 1)" in proc.stderr and "NOT reported as fully verified" in proc.stderr
    assert sorted(p.name for p in tmp_path.iterdir()) == ["e.manifest.json", "e.sql.gz"]


def _sealed(tmp_path: Path) -> Manifest:
    m = load(tmp_path / "e.manifest.json")
    assert isinstance(m, Manifest) and signature_ok(m, KEY.encode())
    return m


def test_normal_run_counts_match_and_verify_passes_l4(tmp_path: Path, table: str) -> None:
    rows = count_rows(*table.split("."))
    proc = export(tmp_path, table, SCRATCH_DSN=scratch_dsn())
    assert proc.returncode == 0, proc.stderr  # L1-L4 plus the L5 restore drill: VERIFIED
    assert "VERIFIED (exit 0)" in proc.stderr
    assert sorted(p.name for p in tmp_path.iterdir()) == ["e.manifest.json", "e.sql.gz"]
    m = _sealed(tmp_path)
    assert m.snapshot is not None and m.snapshot.counts == {table: rows}
    assert m.tables[0].table == table and m.tables[0].count == rows and m.dump_complete
    assert m.compressed is not None
    size, sha = file_sha256(tmp_path / "e.sql.gz", 1 << 16)
    assert (m.compressed.bytes, m.compressed.sha256, m.compressed.format) == (size, sha, "gzip")
    report = verify_file(tmp_path / "e.sql.gz", POLICY, tmp_path / "e.manifest.json", KEY.encode())
    assert all(c.status == Status.PASS for c in report.checks if c.layer <= 4)
    assert report.ral == 4


QUARANTINED = ["e.manifest.json.FAILED", "e.sql.gz.FAILED"]


def _failed(
    tmp_path: Path, proc: subprocess.CompletedProcess[str], files: list[str] = QUARANTINED
) -> None:
    """Exit 2, only .FAILED files left (never a published e.sql.gz or a .partial)."""
    assert proc.returncode == 2, proc.stderr
    assert sorted(p.name for p in tmp_path.iterdir()) == files
    assert "EXPORT FAILED (exit 2)" in proc.stderr


def test_killed_pg_dump_fails_loudly(tmp_path: Path, table: str) -> None:
    proc = export(tmp_path, table, EXPORT_DUMP_TIMEOUT="0.01")
    _failed(tmp_path, proc)
    assert "pg_dump                exit 124  <-- FAILED" in proc.stderr


def test_same_kill_legacy_exits_0_hardened_exits_2(tmp_path: Path, table: str) -> None:
    legacy = tmp_path.parent / f"{tmp_path.name}_legacy.sql.gz"
    proc = subprocess.run(
        [str(LEGACY_EXPORT), table, str(legacy)],
        env=os.environ | {"LEGACY_DUMP_TIMEOUT": "0.01"},
        capture_output=True,
        cwd=ROOT,
    )
    assert proc.returncode == 0  # the silent failure ExportGuard exists for
    assert subprocess.run(["gzip", "-t", str(legacy)]).returncode == 0
    legacy.unlink()
    _failed(tmp_path, export(tmp_path, table, EXPORT_DUMP_TIMEOUT="0.01"))


def test_failing_compressor_stage(tmp_path: Path, table: str) -> None:
    proc = export(tmp_path, table, EXPORT_COMPRESSOR="false")
    _failed(tmp_path, proc)
    assert "<-- FAILED" in proc.stderr


def test_failing_manifest_build_on_the_fifo_is_caught(tmp_path: Path, table: str) -> None:
    stub = tmp_path.parent / f"{tmp_path.name}_eguard"
    real = ROOT / ".venv" / "bin" / "eguard"
    stub.write_text(f'#!/usr/bin/env bash\n[ "$1" = manifest-build ] && exit 5\nexec {real} "$@"\n')
    stub.chmod(0o755)
    proc = export(tmp_path, table, EXPORT_EGUARD=str(stub))
    _failed(tmp_path, proc, ["e.sql.gz.FAILED"])  # the stub never wrote a manifest
    assert "manifest-build         exit 5  <-- FAILED" in proc.stderr


def test_config_errors_exit_3_and_touch_nothing(tmp_path: Path, table: str) -> None:
    assert export(tmp_path, table.split(".")[1]).returncode == 3  # not schema-qualified
    assert export(tmp_path, table, MANIFEST_HMAC_KEY="").returncode == 3
    assert list(tmp_path.iterdir()) == []


def _insert_for(table: str, seconds: float) -> None:
    """Commit one new row every ~20 ms for `seconds`, from another session."""
    cols = ", ".join(COLUMNS[1:])
    run_sql(
        f"""DO $$
        DECLARE t0 timestamptz := clock_timestamp();
        BEGIN
          WHILE clock_timestamp() - t0 < interval '{seconds} seconds' LOOP
            INSERT INTO {table} (id, {cols})
              SELECT (SELECT max(id) FROM {table}) + 1, {cols} FROM {table} ORDER BY id LIMIT 1;
            COMMIT;
            PERFORM pg_sleep(0.02);
          END LOOP;
        END $$;""",
        {},
    )


def test_concurrent_inserts_snapshot_counts_still_exact(tmp_path: Path, table: str) -> None:
    writer = threading.Thread(target=_insert_for, args=(table, 6))
    writer.start()
    time.sleep(0.5)
    proc = export(tmp_path, table, SCRATCH_DSN=scratch_dsn())
    writer.join()
    assert proc.returncode == 0, proc.stderr
    m = _sealed(tmp_path)
    assert m.snapshot is not None
    in_snapshot = m.snapshot.counts[table]
    assert m.tables[0].count == in_snapshot  # the dump saw exactly the snapshot...
    assert count_rows(*table.split(".")) > in_snapshot  # ...while the table kept growing
