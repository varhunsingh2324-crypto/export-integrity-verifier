import gzip
import subprocess
import tracemalloc
import zlib
from pathlib import Path

import pytest

from eguard.models import StreamEnd
from eguard.stream import (
    Consumer,
    FanOut,
    GzipDecoder,
    LineTooLong,
    isize_matches,
    open_decoder,
    sniff,
)
from tests.gzutil import dump_like, member

DATA = dump_like(2000)  # ~100 KB, several inflate steps at the small chunk sizes below


def _write(tmp_path: Path, blob: bytes, name: str = "x.bin") -> Path:
    path = tmp_path / name
    path.write_bytes(blob)
    return path


def _decode(path: Path, chunk_bytes: int = 4096) -> tuple[bytes, GzipDecoder]:
    decoder = GzipDecoder(path, chunk_bytes)
    return b"".join(decoder), decoder


# --- header fields ---------------------------------------------------------------------------


def test_header_fields_parsed(tmp_path: Path) -> None:
    blob = member(
        DATA, mtime=1_700_000_000, xfl=2, os=3, fname=b"v2.sql", comment=b"hi", extra=b"ab12"
    )
    out, dec = _decode(_write(tmp_path, blob))
    assert out == DATA and dec.info.error is None
    (m,) = dec.info.members
    assert (m.mtime, m.xfl, m.os, m.fname, m.comment, m.extra_bytes) == (
        1_700_000_000,
        2,
        3,
        "v2.sql",
        "hi",
        4,
    )
    assert m.header_crc_ok is None
    assert m.crc_expected == m.crc_actual == zlib.crc32(DATA)
    assert m.isize_expected == m.bytes_out == len(DATA)


@pytest.mark.parametrize(("level", "xfl"), [(1, 4), (9, 2)])
def test_xfl_from_real_gzip(tmp_path: Path, level: int, xfl: int) -> None:
    blob = subprocess.run(
        ["gzip", f"-{level}", "-c"], input=DATA, capture_output=True, check=True
    ).stdout
    _, dec = _decode(_write(tmp_path, blob))
    assert dec.info.members[0].xfl == xfl
    assert dec.info.error is None


def test_header_crc_good(tmp_path: Path) -> None:
    _, dec = _decode(_write(tmp_path, member(DATA, fname=b"n", hcrc=True)))
    assert dec.info.members[0].header_crc_ok is True and dec.info.error is None


def test_header_crc_bad(tmp_path: Path) -> None:
    out, dec = _decode(_write(tmp_path, member(DATA, hcrc=True, bad_hcrc=True)))
    assert out == b"" and dec.info.error.kind == "header_crc"


def test_reserved_flag_bits(tmp_path: Path) -> None:
    _, dec = _decode(_write(tmp_path, member(DATA, flags_or=0x20)))
    assert dec.info.error.kind == "reserved_flags"


def test_bad_method(tmp_path: Path) -> None:
    _, dec = _decode(_write(tmp_path, member(DATA, cm=7)))
    assert dec.info.error.kind == "bad_method"


def test_long_fname_is_bounded_but_crc_covers_all(tmp_path: Path) -> None:
    blob = member(DATA, fname=b"n" * 10_000, hcrc=True)
    out, dec = _decode(_write(tmp_path, blob), chunk_bytes=512)
    assert out == DATA and dec.info.error is None
    assert len(dec.info.members[0].fname) == 4096


# --- multi-member, trailing junk -------------------------------------------------------------


def test_two_concatenated_members(tmp_path: Path) -> None:
    a, b = DATA[:40_000], DATA[40_000:]
    out, dec = _decode(_write(tmp_path, member(a, xfl=4) + member(b, xfl=2)))
    assert out == DATA and dec.info.error is None
    assert [m.bytes_out for m in dec.info.members] == [len(a), len(b)]
    assert dec.info.trailing_bytes == 0


def test_concatenated_by_cat_like_pigz(tmp_path: Path) -> None:
    one = gzip.compress(DATA[:500])
    two = subprocess.run(["pigz", "-c"], input=DATA[500:], capture_output=True, check=True).stdout
    out, dec = _decode(_write(tmp_path, one + two))
    assert out == DATA and len(dec.info.members) == 2 and dec.info.error is None


@pytest.mark.parametrize(("junk", "all_zero"), [(b"garbage!\n" * 3, False), (b"\0" * 512, True)])
def test_trailing_junk(tmp_path: Path, junk: bytes, all_zero: bool) -> None:
    blob = member(DATA)
    out, dec = _decode(_write(tmp_path, blob + junk), chunk_bytes=100)
    assert out == DATA and dec.info.error is None
    assert dec.info.trailing_bytes == len(junk)
    assert dec.info.trailing_offset == len(blob)
    assert dec.info.trailing_all_zero is all_zero


def test_truncated_second_member_is_eof_not_junk(tmp_path: Path) -> None:
    second = member(DATA)
    _, dec = _decode(_write(tmp_path, member(DATA) + second[:30]))
    assert dec.info.error.kind == "unexpected_eof"
    assert dec.info.trailing_bytes == 0


# --- truncation and corruption ---------------------------------------------------------------


@pytest.mark.parametrize("cut", [1, 5, 12, 0.5, -6, -1])
def test_truncated_gzip(tmp_path: Path, cut: float) -> None:
    blob = member(DATA, fname=b"name")
    n = int(len(blob) * cut) if isinstance(cut, float) else cut % len(blob)
    _, dec = _decode(_write(tmp_path, blob[:n]))
    assert dec.info.error is not None
    assert dec.info.error.kind == "unexpected_eof"


def _flip(blob: bytes, offset: int, mask: int = 0x01) -> bytes:
    return blob[:offset] + bytes([blob[offset] ^ mask]) + blob[offset + 1 :]


def test_one_byte_flip_in_deflate_data_detected(tmp_path: Path) -> None:
    blob = member(DATA)
    _, dec = _decode(_write(tmp_path, _flip(blob, len(blob) // 2)))
    m = dec.info.members[0]
    inflate_failed = dec.info.error is not None and dec.info.error.kind == "inflate_error"
    crc_failed = m.crc_expected is not None and m.crc_expected != m.crc_actual
    assert inflate_failed or crc_failed


@pytest.mark.parametrize(("where", "field"), [(-8, "crc"), (-4, "isize")])
def test_one_byte_flip_in_trailer_detected(tmp_path: Path, where: int, field: str) -> None:
    blob = member(DATA)
    out, dec = _decode(_write(tmp_path, _flip(blob, len(blob) + where)))
    m = dec.info.members[0]
    assert out == DATA and dec.info.error is None
    if field == "crc":
        assert m.crc_expected != m.crc_actual
    else:
        assert not isize_matches(m.bytes_out, m.isize_expected)


def test_isize_is_mod_2_32() -> None:
    assert isize_matches(2**32 + 5, 5)
    assert isize_matches(5, 5)
    assert not isize_matches(2**32 + 5, 6)


def test_bomb_is_streamed_in_bounded_chunks(tmp_path: Path) -> None:
    raw = 64 << 20
    comp = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    block = b"\0" * (1 << 20)
    body = b"".join(comp.compress(block) for _ in range(raw >> 20)) + comp.flush()
    crc = 0
    for _ in range(raw >> 20):
        crc = zlib.crc32(block, crc)
    trailer = crc.to_bytes(4, "little") + (raw & 0xFFFFFFFF).to_bytes(4, "little")
    path = _write(tmp_path, member(b"")[:10] + body + trailer)
    tracemalloc.start()
    biggest = 0
    dec = GzipDecoder(path, 1 << 16)
    for chunk in dec:
        biggest = max(biggest, len(chunk))
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert dec.info.bytes_out == raw and dec.info.error is None
    assert dec.info.members[0].crc_actual == crc
    assert biggest <= 1 << 16
    assert peak < 4 << 20, peak  # 64 MiB decoded in < 4 MiB of Python allocations


# --- format sniffing -------------------------------------------------------------------------


def test_sniff_uses_magic_not_name(tmp_path: Path) -> None:
    gz = _write(tmp_path, member(DATA), "looks_plain.sql")
    plain = _write(tmp_path, DATA, "looks_gzip.sql.gz")
    assert sniff(gz) == "gzip"
    assert sniff(plain) == "unknown"
    assert open_decoder(plain, 4096).info.error.kind == "bad_magic"


def test_empty_file(tmp_path: Path) -> None:
    dec = open_decoder(_write(tmp_path, b""), 4096)
    assert list(dec) == [] and dec.info.error.kind == "empty_file"


# --- fan-out ---------------------------------------------------------------------------------


class Recorder(Consumer):
    def __init__(self) -> None:
        self.lines: list[tuple[int, bytes]] = []
        self.end: StreamEnd | None = None

    def on_line(self, line: bytes, lineno: int) -> None:
        self.lines.append((lineno, line))

    def on_end(self, end: StreamEnd) -> None:
        self.end = end


class ChunkRecorder(Consumer):
    def __init__(self) -> None:
        self.data = bytearray()

    def on_chunk(self, data: bytes) -> None:
        self.data += data


def _chunks(blob: bytes, size: int) -> list[bytes]:
    return [blob[i : i + size] for i in range(0, len(blob), size)]


@pytest.mark.parametrize("size", [1, 3, 7, 1000])
def test_fanout_lines_across_chunk_boundaries(size: int) -> None:
    blob = b"alpha\nbe\n\ngamma-long-line\nlast-no-newline"
    fan = FanOut(max_line_bytes=1000)
    a, b, c = fan.subscribe(Recorder()), fan.subscribe(Recorder()), fan.subscribe(ChunkRecorder())
    end = fan.run(_chunks(blob, size))
    expected = list(enumerate(blob.split(b"\n"), start=1))
    assert a.lines == b.lines == expected
    assert bytes(c.data) == blob
    assert a.end == b.end == end
    assert end == StreamEnd(clean=True, bytes_out=len(blob), lines=5, unterminated_tail=True)


def test_fanout_terminated_stream() -> None:
    fan = FanOut(max_line_bytes=100)
    rec = fan.subscribe(Recorder())
    end = fan.run([b"a\nb", b"\n"])
    assert rec.lines == [(1, b"a"), (2, b"b")]
    assert end.unterminated_tail is False


def test_fanout_reports_unclean_decoder(tmp_path: Path) -> None:
    blob = member(DATA)
    dec = open_decoder(_write(tmp_path, blob[: len(blob) // 2]), 4096)
    fan = FanOut(max_line_bytes=1 << 20)
    rec = fan.subscribe(Recorder())
    end = fan.run(dec, is_clean=lambda: dec.info.error is None)
    assert end.clean is False and rec.end == end
    assert end.lines > 0  # partial content still reached every subscriber


def test_fanout_line_too_long() -> None:
    fan = FanOut(max_line_bytes=10)
    fan.subscribe(Recorder())
    with pytest.raises(LineTooLong):
        fan.run([b"0123456", b"789abc"])


def test_fanout_without_line_subscribers_does_not_split() -> None:
    fan = FanOut(max_line_bytes=1)  # would raise if lines were being split
    rec = fan.subscribe(ChunkRecorder())
    fan.run([b"no newline here at all"])
    assert bytes(rec.data) == b"no newline here at all"


def test_gzip_decoder_feeds_fanout_identical_content(tmp_path: Path) -> None:
    dec = open_decoder(_write(tmp_path, member(DATA[:30_000]) + member(DATA[30_000:])), 997)
    fan = FanOut(max_line_bytes=1 << 20)
    rec, raw = fan.subscribe(Recorder()), fan.subscribe(ChunkRecorder())
    end = fan.run(dec, is_clean=lambda: dec.info.error is None)
    assert bytes(raw.data) == DATA
    assert [line for _, line in rec.lines] == DATA.split(b"\n")[:-1]
    assert end.clean and end.lines == 2000 and not end.unterminated_tail
