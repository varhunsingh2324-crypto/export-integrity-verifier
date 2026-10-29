import copy
import json
from pathlib import Path

import pytest

from eguard.config import load_policy
from eguard.manifest import ManifestError, build_from_chunks, compressed_info, save, seal
from eguard.models import CheckResult, SnapshotInfo, Status, Verdict, VerifyReport
from eguard.verify import verify_file
from tests import pgdump
from tests.gzutil import member

# A policy *copy* with small chunks (a 300-row dump has 6); config/policy.yaml is untouched.
POLICY = copy.deepcopy(load_policy())
POLICY["l4"]["chunk_rows"] = 50
KEY = b"reconcile-key"
N = 300
ROWS = pgdump.rows(N)
HEADER = pgdump.header_lines()  # COPY header line; row r is on line HEADER + r


def _manifest(
    tmp_path: Path, data: bytes, name: str = "m.json", *, db_rows: int | None = N
) -> Path:
    """Like the hardened export: built from the stream, then sealed with the snapshot count
    (`db_rows`, None = unsealed) and the sha256 of exactly the file _verify writes."""
    m = build_from_chunks([data], POLICY, KEY)
    if db_rows is not None:
        gz = tmp_path / f"{name}.written.gz"
        gz.write_bytes(member(data))
        snap = SnapshotInfo(
            id="00000003-0000ABCD-1",
            isolation="repeatable read",
            taken_at="2026-10-29 10:00:00+00",
            counts={pgdump.TABLE: db_rows},
        )
        m = seal(m, KEY, snap, compressed_info(gz, "test", 4096))
    path = tmp_path / name
    save(m, path)
    return path


def _verify(tmp_path: Path, data: bytes, manifest: Path | None) -> VerifyReport:
    path = tmp_path / "export.sql.gz"
    path.write_bytes(member(data))
    return verify_file(path, POLICY, manifest, KEY if manifest else None)


def _l4(report: VerifyReport) -> dict[str, CheckResult]:
    return {c.name: c for c in report.checks if c.layer == 4}


def _with_amount(row_no: int, amount: str) -> list[str]:
    body = ROWS[:]
    fields = body[row_no - 1].split("\t")
    fields[3] = amount
    body[row_no - 1] = "\t".join(fields)
    return body


@pytest.fixture
def manifest(tmp_path: Path) -> Path:
    return _manifest(tmp_path, pgdump.dump_bytes(N))


def test_clean_export_passes_every_l4_check(tmp_path: Path, manifest: Path) -> None:
    report = _verify(tmp_path, pgdump.dump_bytes(N), manifest)
    l4 = _l4(report)
    assert set(l4) == {
        "l4_manifest_signature",
        "l4_tables",
        "l4_row_counts",
        "l4_snapshot_counts",
        "l4_fingerprint",
        "l4_stream_digest",
        "l4_compressed_sha256",
    }
    assert all(c.status == Status.PASS for c in l4.values()), [c.message for c in l4.values()]
    assert report.verdict == Verdict.SUSPECT and report.ral == 4  # no scratch DB here: L5 not run


def test_changed_value_is_localised_to_its_chunk(tmp_path: Path, manifest: Path) -> None:
    report = _verify(tmp_path, pgdump.dump_bytes(body=_with_amount(123, "999.99")), manifest)
    assert report.verdict == Verdict.CORRUPT
    assert all(c.status == Status.PASS for c in report.checks if c.layer <= 3)
    l4 = _l4(report)
    assert l4["l4_row_counts"].status == Status.PASS
    assert l4["l4_stream_digest"].status == Status.FAIL
    assert l4["l4_compressed_sha256"].status == Status.FAIL
    fp = l4["l4_fingerprint"]
    assert fp.status == Status.FAIL
    assert fp.evidence["damaged_count"] == 1
    assert fp.evidence["first_damaged"] == {
        "table": "public.transactions",
        "chunk": 3,
        "of": 6,
        "rows": [101, 150],
        "lines": [HEADER + 101, HEADER + 150],
    }
    assert "chunk 3 of 6" in fp.message and "rows 101–150" in fp.message


def test_dropped_row_fails_counts_and_names_first_chunk(tmp_path: Path, manifest: Path) -> None:
    body = ROWS[:199] + ROWS[200:]  # row 200 missing
    l4 = _l4(_verify(tmp_path, pgdump.dump_bytes(body=body), manifest))
    counts = l4["l4_row_counts"]
    assert counts.status == Status.FAIL
    assert counts.evidence["tables"]["public.transactions"] == {
        "manifest": N,
        "stream": N - 1,
        "delta": -1,
    }
    fp = l4["l4_fingerprint"]
    assert fp.status == Status.FAIL
    assert fp.evidence["first_damaged"]["rows"] == [151, 200]
    assert "shifted" in fp.message


def test_truncated_export_fails_counts(tmp_path: Path, manifest: Path) -> None:
    l4 = _l4(_verify(tmp_path, pgdump.killed_at(N, 120), manifest))
    assert l4["l4_row_counts"].evidence["tables"]["public.transactions"]["delta"] == -180
    assert l4["l4_fingerprint"].evidence["first_damaged"]["rows"] == [101, 150]


def test_missing_and_extra_table(tmp_path: Path, manifest: Path) -> None:
    renamed = pgdump.dump_text(N).replace("public.transactions", "public.transactions2")
    l4 = _l4(_verify(tmp_path, renamed.encode(), manifest))
    t = l4["l4_tables"]
    assert t.status == Status.FAIL
    assert t.evidence["missing"] == ["public.transactions"]
    assert t.evidence["extra"] == ["public.transactions2"]


def test_manifest_of_incomplete_dump_fails_tables(tmp_path: Path) -> None:
    killed = pgdump.killed_at(N, 120)
    l4 = _l4(_verify(tmp_path, killed, _manifest(tmp_path, killed, db_rows=None)))
    assert l4["l4_row_counts"].status == Status.PASS  # the file is what the exporter emitted...
    assert l4["l4_tables"].status == Status.FAIL  # ...but the exporter's own stream was cut
    assert "incomplete" in l4["l4_tables"].message


def test_exporter_dropped_rows_only_snapshot_counts_catch(tmp_path: Path) -> None:
    """Exporter emitted 120 of the 300 rows the snapshot held, then ended *cleanly*: the manifest
    agrees with the file, so only the snapshot count can tell."""
    short = pgdump.dump_bytes(body=ROWS[:120])
    report = _verify(tmp_path, short, _manifest(tmp_path, short, db_rows=N))
    l4 = _l4(report)
    for name in ("l4_tables", "l4_row_counts", "l4_fingerprint", "l4_stream_digest"):
        assert l4[name].status == Status.PASS, name
    snap = l4["l4_snapshot_counts"]
    assert snap.status == Status.FAIL and report.verdict == Verdict.CORRUPT
    assert snap.evidence["tables"][pgdump.TABLE] == {"snapshot": N, "export": 120, "manifest": 120}
    assert "120 rows in the export vs 300 in the database" in snap.message


def test_unsealed_manifest_skips_snapshot_and_sha(tmp_path: Path) -> None:
    data = pgdump.dump_bytes(N)
    report = _verify(tmp_path, data, _manifest(tmp_path, data, db_rows=None))
    l4 = _l4(report)
    assert l4["l4_snapshot_counts"].status == Status.SKIP
    assert l4["l4_compressed_sha256"].status == Status.SKIP
    assert all(
        c.status == Status.PASS for n, c in l4.items() if "snapshot" not in n and "sha" not in n
    )
    assert report.verdict == Verdict.SUSPECT and report.ral == 3  # L4 lacks full evidence


def test_recompressed_export_warns_not_corrupt(tmp_path: Path, manifest: Path) -> None:
    path = tmp_path / "recompressed.sql.gz"
    path.write_bytes(member(pgdump.dump_bytes(N), level=1))
    report = verify_file(path, POLICY, manifest, KEY)
    l4 = _l4(report)
    assert l4["l4_compressed_sha256"].status == Status.WARN
    assert l4["l4_stream_digest"].status == Status.PASS
    assert report.verdict == Verdict.SUSPECT


def test_tampered_manifest_fails_and_skips_reconciliation(tmp_path: Path, manifest: Path) -> None:
    doc = json.loads(manifest.read_text())
    doc["tables"][0]["count"] = N + 1
    manifest.write_text(json.dumps(doc))
    report = _verify(tmp_path, pgdump.dump_bytes(N), manifest)
    l4 = _l4(report)
    assert l4["l4_manifest_signature"].status == Status.FAIL
    assert all(c.status == Status.SKIP for n, c in l4.items() if n != "l4_manifest_signature")
    assert report.verdict == Verdict.CORRUPT


def test_wrong_key_fails_signature(tmp_path: Path, manifest: Path) -> None:
    path = tmp_path / "export.sql.gz"
    path.write_bytes(member(pgdump.dump_bytes(N)))
    report = verify_file(path, POLICY, manifest, b"not-the-key")
    assert _l4(report)["l4_manifest_signature"].status == Status.FAIL


def test_unparseable_manifest_fails_signature(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    l4 = _l4(_verify(tmp_path, pgdump.dump_bytes(N), bad))
    assert l4["l4_manifest_signature"].status == Status.FAIL
    assert "unreadable" in l4["l4_manifest_signature"].message


def test_manifest_without_key_is_tool_error(tmp_path: Path, manifest: Path) -> None:
    path = tmp_path / "export.sql.gz"
    path.write_bytes(member(pgdump.dump_bytes(N)))
    with pytest.raises(ManifestError):
        verify_file(path, POLICY, manifest, None)


def test_no_manifest_skips_l4(tmp_path: Path) -> None:
    report = _verify(tmp_path, pgdump.dump_bytes(N), None)
    (c,) = _l4(report).values()
    assert c.status == Status.SKIP and "no manifest" in c.message
    assert report.ral == 3


def test_uses_manifest_chunk_rows_not_policy(tmp_path: Path, manifest: Path) -> None:
    other = copy.deepcopy(POLICY)
    other["l4"]["chunk_rows"] = 7
    path = tmp_path / "export.sql.gz"
    path.write_bytes(member(pgdump.dump_bytes(body=_with_amount(123, "1.00"))))
    fp = _l4(verify_file(path, other, manifest, KEY))["l4_fingerprint"]
    assert fp.evidence["first_damaged"]["rows"] == [101, 150]
