import shutil
import subprocess
from pathlib import Path

import pytest

from eguard.config import load_policy
from eguard.container import NO_CHECKSUM, check_container, level_hint
from eguard.models import CheckResult, Status, Verdict
from eguard.stream import open_decoder
from eguard.verdict import decide
from eguard.verify import verify_file
from tests import pgdump
from tests.gzutil import dump_like, member

POLICY = load_policy()
DATA = dump_like(3000)
needs_compress = pytest.mark.skipif(shutil.which("compress") is None, reason="ncompress missing")


def _l1(tmp_path: Path, blob: bytes) -> tuple[dict[str, CheckResult], bytes]:
    path = tmp_path / "export.bin"
    path.write_bytes(blob)
    dec = open_decoder(path, 4096)
    out = b"".join(dec)
    return {c.name: c for c in check_container(dec.info, POLICY)}, out


def _statuses(checks: dict[str, CheckResult]) -> dict[str, Status]:
    return {name: c.status for name, c in checks.items()}


def _flip(blob: bytes, offset: int) -> bytes:
    return blob[:offset] + bytes([blob[offset] ^ 0x01]) + blob[offset + 1 :]


def test_healthy_gzip_all_pass(tmp_path: Path) -> None:
    checks, _ = _l1(tmp_path, member(DATA, mtime=1_700_000_000, xfl=2, fname=b"v2.sql"))
    assert set(_statuses(checks).values()) == {Status.PASS}
    fmt = checks["l1_format"].evidence
    assert fmt["compressor"] == "gzip" and fmt["level_hint"] == "max (-9)"
    assert fmt["uncompressed_bytes"] == len(DATA) and fmt["members"] == 1
    assert fmt["header_mtime"] == "2023-11-14T22:13:20+00:00"
    assert fmt["ratio"] > 1
    hdr = checks["l1_header"].evidence["member_headers"][0]
    assert (hdr["os"], hdr["fname"], hdr["xfl"]) == ("Unix", "v2.sql", 2)


def test_every_check_has_evidence_and_message(tmp_path: Path) -> None:
    checks, _ = _l1(tmp_path, member(DATA)[:-3])
    for c in checks.values():
        assert c.layer == 1 and c.evidence and c.message.strip()


@pytest.mark.parametrize(("xfl", "hint"), [(2, "max (-9)"), (4, "fastest (-1)"), (0, "default")])
def test_level_hint(xfl: int, hint: str) -> None:
    assert level_hint(xfl).startswith(hint)


def test_truncated_gzip_fails_stream_end(tmp_path: Path) -> None:
    blob = member(DATA)
    checks, _ = _l1(tmp_path, blob[: int(len(blob) * 0.7)])
    assert checks["l1_stream_end"].status == Status.FAIL
    assert checks["l1_stream_end"].evidence["error"] == "unexpected_eof"
    assert checks["l1_integrity"].status == Status.SKIP
    assert decide(list(checks.values()), POLICY)[0] == Verdict.CORRUPT


def test_byte_flip_fails(tmp_path: Path) -> None:
    blob = member(DATA)
    checks, _ = _l1(tmp_path, _flip(blob, len(blob) // 2))
    failed = {n for n, s in _statuses(checks).items() if s == Status.FAIL}
    assert failed & {"l1_stream_end", "l1_integrity"}
    assert decide(list(checks.values()), POLICY)[0] == Verdict.CORRUPT


def test_crc_mismatch_message(tmp_path: Path) -> None:
    blob = member(DATA)
    checks, out = _l1(tmp_path, _flip(blob, len(blob) - 8))
    c = checks["l1_integrity"]
    assert out == DATA  # inflate succeeds; only the checksum catches it
    assert c.status == Status.FAIL and c.evidence["bad_members"] == [0]
    assert "crc32 expected" in c.message


def test_two_members_pass(tmp_path: Path) -> None:
    checks, out = _l1(tmp_path, member(DATA[:1000]) + member(DATA[1000:]))
    assert out == DATA
    assert checks["l1_integrity"].status == Status.PASS
    assert checks["l1_integrity"].evidence["members_checked"] == 2


@pytest.mark.parametrize("junk", [b"not gzip at all", b"\0" * 64])
def test_trailing_junk_is_policy_status(tmp_path: Path, junk: bytes) -> None:
    checks, out = _l1(tmp_path, member(DATA) + junk)
    assert out == DATA
    c = checks["l1_trailing"]
    assert c.status == Status(POLICY["l1"]["trailing_garbage"])
    assert c.evidence["trailing_bytes"] == len(junk)
    assert decide(list(checks.values()), POLICY)[0] != Verdict.CORRUPT


def test_bad_header_fails(tmp_path: Path) -> None:
    checks, _ = _l1(tmp_path, member(DATA, flags_or=0x40))
    assert checks["l1_header"].status == Status.FAIL
    assert checks["l1_header"].evidence["error"] == "reserved_flags"


def test_unknown_format_fails(tmp_path: Path) -> None:
    checks, _ = _l1(tmp_path, DATA)
    assert list(checks) == ["l1_format"]
    assert checks["l1_format"].status == Status.FAIL


def _compress(data: bytes) -> bytes:
    return subprocess.run(["compress", "-c"], input=data, capture_output=True, check=True).stdout


@needs_compress
def test_dotz_decodes_with_no_checksum_warning(tmp_path: Path) -> None:
    checks, out = _l1(tmp_path, _compress(DATA))
    assert out == DATA
    assert checks["l1_header"].status == Status.PASS
    assert checks["l1_header"].evidence["max_bits"] == 16
    assert checks["l1_stream_end"].status == Status.PASS
    assert checks["l1_checksum"].status == Status.WARN
    assert checks["l1_checksum"].message == NO_CHECKSUM
    assert checks["l1_format"].evidence["compressor"] == "compress (LZW)"
    assert decide(list(checks.values()), POLICY)[0] == Verdict.SUSPECT


@needs_compress
@pytest.mark.parametrize(("byte", "kind"), [(0x88, "bad_maxbits"), (0x90 | 0x20, "reserved_flags")])
def test_dotz_bad_flag_byte(tmp_path: Path, byte: int, kind: str) -> None:
    blob = bytearray(_compress(DATA))
    blob[2] = byte
    checks, out = _l1(tmp_path, bytes(blob))
    assert out == b""
    assert checks["l1_header"].status == Status.FAIL
    assert checks["l1_header"].evidence["error"] == kind


@needs_compress
def test_dotz_damage_is_invisible_to_l1(tmp_path: Path) -> None:
    """The teaching moment: `gzip -dc` exits 0 on truncated or flipped .Z, so L1 cannot vouch."""
    blob = _compress(DATA)
    for damaged in (blob[: len(blob) // 2], _flip(blob, len(blob) // 2)):
        checks, out = _l1(tmp_path, damaged)
        assert out != DATA
        assert checks["l1_stream_end"].status == Status.PASS
        assert checks["l1_checksum"].status == Status.WARN


def test_verify_file_skips_pending_layers(tmp_path: Path) -> None:
    path = tmp_path / "ok.gz"
    dump = pgdump.dump_bytes(3000)
    path.write_bytes(member(dump))
    report = verify_file(path, POLICY)
    assert report.verdict == Verdict.SUSPECT and report.ral == 3
    assert {c.layer for c in report.checks if c.status == Status.SKIP} == {4, 5}
    assert report.checks[0].evidence["decompressed_lines"] == dump.count(b"\n")
