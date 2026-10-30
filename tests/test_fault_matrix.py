"""End-to-end fault matrix (IMPLEMENTATION_PLAN §6, §9 phase 6): the demo's truth table.

Builds F0-F7 (+ F1h) with the real generators (`sim.faults.build_gallery`: incident at
`faults.source_rows` in its own schema, hardened and legacy exports, real `timeout` kills), then
verifies every file with its manifest and the L5 drill, and pins gzip -t, every layer's status,
the verdict, the RAL and the exit code. A row that disagrees means a layer is wrong, not the row.
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import psycopg
import pytest

from eguard.config import load_policy
from eguard.models import Status, Verdict, VerifyReport
from eguard.verify import verify_file
from sim.faults import build_gallery, load_faults_config
from sim.incident import load_sim_config
from tests.rename import decoy

pytestmark = pytest.mark.db

POLICY = load_policy()
CFG = load_faults_config()
SCHEMA = "eguard_matrix"  # not CFG.schema_, so `make faults` and this test never share a table
KEY = b"fault-matrix-key"
SEED = 5
P, W, F, S = Status.PASS, Status.WARN, Status.FAIL, Status.SKIP

# Where the F3/F4 flip lands depends on the build: pg_dump writes a random `\restrict` key at the
# top, so every gallery has different compressed bytes and the byte at 50 % hits different data
# (measured: F3 garbled 24,786 rows in one build, 1 row in another). Rows only invalid by chance
# are not a guarantee of the fault, so those layers may PASS or FAIL (DEPENDS) and
# test_flip_dependent_layers_agree checks they agree with each other and with L4 instead.
DEPENDS = frozenset({P, F})
Layer = Status | frozenset[Status]

# fault: (gzip -t passes, (L1, L2, L3, L4, L5), verdict). §6 names the catching layer; the other
# FAILs are true cascades of the same damage. L3 WARN on F1/F1h/F2: the dump was cut before
# `ALTER TABLE ... PRIMARY KEY`, so l3_pk_unique is SKIP next to a PASSing l3_row_validity.
EXPECTED: dict[str, tuple[bool, tuple[Layer, ...], Verdict]] = {
    "F0": (True, (P, P, P, P, P), Verdict.VERIFIED),  # hardened source, pigz -6
    "F1": (True, (P, F, W, S, P), Verdict.CORRUPT),  # legacy kill: no manifest, L4 has no reference
    "F1h": (True, (P, F, W, F, P), Verdict.CORRUPT),  # same kill, hardened: manifest: incomplete
    "F2": (False, (F, F, W, F, P), Verdict.CORRUPT),  # truncated at rest: stream also ends mid-COPY
    "F3": (False, (F, P, DEPENDS, F, DEPENDS), Verdict.CORRUPT),  # byte flip: CRC + fingerprints
    "F4": (True, (W, P, DEPENDS, F, DEPENDS), Verdict.CORRUPT),  # .Z: no checksum, L4 catches it
    "F5": (True, (P, P, P, F, P), Verdict.CORRUPT),  # valid value changed: only L4 sees it
    "F6": (True, (P, P, F, F, F), Verdict.CORRUPT),  # dup chunk: PK, +10,000 rows, sample has dups
    "F7": (True, (P, P, P, P, P), Verdict.VERIFIED),  # compressor change only, own manifest
}
FLIPS = ("F3", "F4")


def _allows(expected: Layer, got: Status) -> bool:
    return got in expected if isinstance(expected, frozenset) else got == expected


def gzip_t(path: Path) -> int:
    return subprocess.run(["gzip", "-t", str(path)], capture_output=True).returncode


def _verify(path: Path, manifest: Path | None) -> VerifyReport:
    key = KEY if manifest is not None else None
    scratch = os.environ["SCRATCH_DSN"]
    return verify_file(path, POLICY, manifest, key, scratch_dsn=scratch, seed=SEED)


def _manifest(record: dict[str, Any]) -> Path | None:
    return Path(record["manifest"]) if record["manifest"] else None


@pytest.fixture(scope="module")
def gallery(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, Any]]:
    if not (os.environ.get("PG_DSN") and os.environ.get("SCRATCH_DSN")):
        pytest.skip("PG_DSN/SCRATCH_DSN not set (copy .env.example to .env and run `make up`)")
    if shutil.which("compress") is None:
        pytest.skip("`compress` (ncompress) not installed: F4 cannot be built")
    root = tmp_path_factory.mktemp("matrix")
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("MANIFEST_HMAC_KEY", KEY.decode())  # the export scripts sign with it
        _, _, records = build_gallery(
            CFG, load_sim_config(), root / "exports", root / "manifests", SCHEMA
        )
    return {r["fault"]: r for r in records}


@pytest.fixture(scope="module")
def results(gallery: dict[str, dict[str, Any]]) -> dict[str, tuple[int, VerifyReport]]:
    return {
        fid: (gzip_t(Path(r["path"])), _verify(Path(r["path"]), _manifest(r)))
        for fid, r in gallery.items()
    }


def _fails(report: VerifyReport) -> set[str]:
    return {c.name for c in report.checks if c.status == Status.FAIL}


def test_gallery_has_every_fault(gallery: dict[str, dict[str, Any]]) -> None:
    assert set(gallery) == set(EXPECTED)
    assert gallery["F1"]["manifest"] is None and gallery["F1"]["script_exit"] == 0
    assert gallery["F1h"]["script_exit"] == 2  # the hardened script refused to publish it


@pytest.mark.parametrize("fid", list(EXPECTED))
def test_truth_table(fid: str, results: dict[str, tuple[int, VerifyReport]]) -> None:
    gz_ok, layers, verdict = EXPECTED[fid]
    code, report = results[fid]
    got = tuple(lr.status for lr in report.layers)
    assert code == 0 if gz_ok else code != 0
    assert all(_allows(e, g) for e, g in zip(layers, got, strict=True)), (got, report.reasons)
    assert report.verdict == verdict, report.reasons
    assert report.ral == got.count(Status.PASS)
    assert report.exit_code == verdict.exit_code


@pytest.mark.parametrize("fid", FLIPS)
def test_flip_dependent_layers_agree(
    fid: str, results: dict[str, tuple[int, VerifyReport]]
) -> None:
    """L3 and L5 of a flip may PASS or FAIL, but never on their own: an L3-invalid row lies at
    or after the first chunk L4 found damaged, and the drill rejects only rows L3 also rejected."""
    report = results[fid][1]
    l3, l5 = report.layers[2].status, report.layers[4].status
    fp = next(c for c in report.checks if c.name == "l4_fingerprint")
    first_damaged_line = fp.evidence["first_damaged"]["lines"][0]
    rows = next(c for c in report.checks if c.name == "l3_row_validity")
    if rows.status == Status.FAIL:
        assert rows.evidence["examples"][0]["line"] >= first_damaged_line
    if l5 == Status.FAIL:
        assert l3 == Status.FAIL, report.reasons


def test_gzip_t_passes_f1_f5_f6(results: dict[str, tuple[int, VerifyReport]]) -> None:
    """The point of the demo: gzip -t says OK on files that cannot be restored."""
    for fid in ("F1", "F5", "F6"):
        code, report = results[fid]
        assert code == 0 and report.verdict == Verdict.CORRUPT, fid


def test_section6_catching_layers(
    gallery: dict[str, dict[str, Any]], results: dict[str, tuple[int, VerifyReport]]
) -> None:
    r = {fid: rep for fid, (_, rep) in results.items()}
    assert "l2_complete" in _fails(r["F1"])
    assert {"l2_complete", "l4_tables"} <= _fails(r["F1h"])
    assert "l1_stream_end" in _fails(r["F2"])
    assert "l1_integrity" in _fails(r["F3"])
    assert "l4_fingerprint" in _fails(r["F4"]) and r["F4"].layers[0].status != Status.FAIL
    assert {c.layer for c in r["F5"].checks if c.status == Status.FAIL} == {4}
    fp = next(c for c in r["F5"].checks if c.name == "l4_fingerprint")
    lo, hi = fp.evidence["first_damaged"]["rows"]
    assert fp.evidence["damaged_count"] == 1 and lo <= gallery["F5"]["row"] <= hi
    assert "l3_pk_unique" in _fails(r["F6"])


VOLATILE = {"schema", "scratch_table", "seconds", "stale_dropped"}


def _stable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _stable(v) for k, v in obj.items() if k not in VOLATILE}
    if isinstance(obj, list):
        return [_stable(v) for v in obj]
    return obj


def _comparable(report: VerifyReport) -> tuple:
    """Everything but the L5 scratch schema name and timings (fresh per drill)."""
    layers = [
        (lr.layer, lr.status, lr.full_evidence, lr.checks, lr.reason if lr.layer < 5 else None)
        for lr in report.layers
    ]
    checks = [
        (
            c.layer,
            c.name,
            c.status,
            c.severity,
            _stable(c.evidence),
            c.message if c.layer < 5 else None,
        )
        for c in report.checks
    ]
    return report.verdict, report.ral, report.exit_code, layers, checks


def test_rename_identical(
    tmp_path: Path,
    gallery: dict[str, dict[str, Any]],
    results: dict[str, tuple[int, VerifyReport]],
) -> None:
    """Rule 9: every fault file and manifest copied to random names, dirs and extensions
    gets the same verdict and layer results."""
    for fid, record in gallery.items():
        manifest = _manifest(record)
        renamed = _verify(
            decoy(tmp_path, Path(record["path"])),
            decoy(tmp_path, manifest) if manifest else None,
        )
        assert _comparable(renamed) == _comparable(results[fid][1]), fid


def test_no_scratch_or_matrix_schema_left(results: dict[str, tuple[int, VerifyReport]]) -> None:
    sql = "SELECT nspname FROM pg_namespace WHERE nspname LIKE 'eguard\\_l5\\_%%' OR nspname = %s"
    for dsn in (os.environ["SCRATCH_DSN"], os.environ["PG_DSN"]):
        with psycopg.connect(dsn) as conn:
            assert conn.execute(sql, (SCHEMA,)).fetchall() == []
