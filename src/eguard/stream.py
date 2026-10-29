"""Streaming decompressors and the one-pass fan-out every layer subscribes to.

gzip is parsed by hand (RFC 1952) on top of raw-deflate zlib so that every failure mode is ours
to report: header fields, multi-member files, CRC32, ISIZE (mod 2**32), trailing garbage,
unexpected EOF.
`.Z` (Unix compress) is validated here and decoded by a `gzip -dc` subprocess; it has no checksum.

Rules 1-2: nothing decompressed is written to disk or held whole in memory. Inflate
output is capped per step with `max_length`, so even a decompression bomb streams in bounded chunks.
"""

import struct
import subprocess
import tempfile
import zlib
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import BinaryIO, Literal

from eguard.models import ContainerInfo, GzipMember, StreamEnd, StreamError

GZIP_MAGIC = b"\x1f\x8b"
COMPRESS_MAGIC = b"\x1f\x9d"
FHCRC, FEXTRA, FNAME, FCOMMENT = 0x02, 0x04, 0x08, 0x10
FRESERVED = 0xE0
CM_DEFLATE = 8
MAX_HEADER_STRING = 4096  # FNAME/FCOMMENT bytes kept as evidence; the rest is CRC'd and discarded
COMPRESS_RESERVED = 0x60
COMPRESS_BLOCK_MODE = 0x80

Format = Literal["gzip", "compress", "unknown"]


class LineTooLong(Exception):
    """A decompressed line exceeded policy stream.max_line_bytes (tool error, not a verdict)."""


class _Truncated(Exception):
    """Input ended where the format requires more bytes."""


class _Stop(Exception):
    """Decoding stopped on an error already recorded in info.error."""


def sniff(path: Path) -> Format:
    """Container format from the magic bytes only, never from the file name (rule 9)."""
    with path.open("rb") as fh:
        magic = fh.read(2)
    if magic == GZIP_MAGIC:
        return "gzip"
    if magic == COMPRESS_MAGIC:
        return "compress"
    return "unknown"


def isize_matches(bytes_out: int, isize: int) -> bool:
    """RFC 1952: ISIZE is the uncompressed length modulo 2**32."""
    return bytes_out & 0xFFFFFFFF == isize


class _Input:
    """Buffered reader over the compressed file that knows its absolute offset."""

    def __init__(self, fh: BinaryIO, chunk_bytes: int) -> None:
        self._fh = fh
        self._chunk = chunk_bytes
        self._buf = b""
        self.pos = 0  # absolute offset of the next unread byte

    def _fill(self, n: int) -> bool:
        while len(self._buf) < n:
            data = self._fh.read(max(self._chunk, n - len(self._buf)))
            if not data:
                return False
            self._buf += data
        return True

    def peek(self, n: int) -> bytes:
        self._fill(n)
        return self._buf[:n]

    def read_exact(self, n: int) -> bytes:
        if not self._fill(n):
            raise _Truncated
        out, self._buf = self._buf[:n], self._buf[n:]
        self.pos += n
        return out

    def read_cstring(self, crc: int) -> tuple[bytes, int]:
        """Read a NUL-terminated field; keep at most MAX_HEADER_STRING bytes; CRC every byte."""
        kept = b""
        while True:
            if not self._buf and not self._fill(1):
                raise _Truncated
            i = self._buf.find(b"\0")
            piece = self._buf if i < 0 else self._buf[: i + 1]
            crc = zlib.crc32(piece, crc)
            kept += piece[: max(0, MAX_HEADER_STRING - len(kept))]
            self._buf = self._buf[len(piece) :]
            self.pos += len(piece)
            if i >= 0:
                return kept.rstrip(b"\0"), crc

    def chunk(self) -> bytes:
        """Everything buffered, or the next read; b"" at end of file."""
        out, self._buf = (self._buf or self._fh.read(self._chunk)), b""
        self.pos += len(out)
        return out

    def unread(self, data: bytes) -> None:
        self._buf = data + self._buf
        self.pos -= len(data)


class GzipDecoder:
    """Iterate decompressed chunks of a (possibly multi-member) gzip file; `info` is the evidence.

    Decoding problems never raise: the decoder stops and records `info.error`, so the caller always
    gets a report. CRC/ISIZE mismatches are recorded per member and decoding continues.
    """

    def __init__(self, path: Path, chunk_bytes: int) -> None:
        self.path = path
        self.chunk_bytes = chunk_bytes
        self.info = ContainerInfo(format="gzip", compressed_bytes=path.stat().st_size)

    def __iter__(self) -> Iterator[bytes]:
        with self.path.open("rb") as fh:
            inp = _Input(fh, self.chunk_bytes)
            while True:
                member_start = inp.pos
                try:
                    member = self._read_header(inp)
                    if member is None:
                        return
                    self.info.members.append(member)
                    yield from self._inflate(inp, member)
                    self._read_trailer(inp, member)
                except _Truncated:
                    self._fail("unexpected_eof", inp.pos, "file ends inside a gzip member")
                    return
                except _Stop:
                    return
                member.compressed_bytes = inp.pos - member_start
                if not inp.peek(1):
                    return
                if inp.peek(2) != GZIP_MAGIC:
                    self._scan_trailing(inp)
                    return

    def _fail(self, kind: str, offset: int, detail: str) -> None:
        self.info.error = StreamError(kind=kind, offset=offset, detail=detail)

    def _read_header(self, inp: _Input) -> GzipMember | None:
        offset = inp.pos
        fixed = inp.read_exact(10)
        if fixed[:2] != GZIP_MAGIC:
            self._fail("bad_magic", offset, f"expected 1f8b, found {fixed[:2].hex()}")
            return None
        cm, flg, mtime, xfl, os_ = struct.unpack("<BBIBB", fixed[2:])
        if cm != CM_DEFLATE:
            self._fail("bad_method", offset + 2, f"compression method {cm}, expected 8 (deflate)")
            return None
        if flg & FRESERVED:
            self._fail("reserved_flags", offset + 3, f"FLG 0x{flg:02x} sets reserved bits 5-7")
            return None
        member = GzipMember(offset=offset, flags=flg, mtime=mtime, xfl=xfl, os=os_)
        crc = zlib.crc32(fixed)
        if flg & FEXTRA:
            xlen_raw = inp.read_exact(2)
            extra = inp.read_exact(struct.unpack("<H", xlen_raw)[0])
            member.extra_bytes = len(extra)
            crc = zlib.crc32(extra, zlib.crc32(xlen_raw, crc))
        if flg & FNAME:
            name, crc = inp.read_cstring(crc)
            member.fname = name.decode("latin-1")
        if flg & FCOMMENT:
            comment, crc = inp.read_cstring(crc)
            member.comment = comment.decode("latin-1")
        if flg & FHCRC:
            stored = struct.unpack("<H", inp.read_exact(2))[0]
            member.header_crc_ok = stored == crc & 0xFFFF
            if not member.header_crc_ok:
                self._fail(
                    "header_crc", inp.pos - 2, f"FHCRC 0x{stored:04x} != 0x{crc & 0xFFFF:04x}"
                )
                return None
        return member

    def _inflate(self, inp: _Input, member: GzipMember) -> Iterator[bytes]:
        d = zlib.decompressobj(-zlib.MAX_WBITS)
        while not d.eof:
            data = d.unconsumed_tail or inp.chunk()
            try:
                out = d.decompress(data, self.chunk_bytes) if data else d.flush()
            except zlib.error as exc:
                at = inp.pos - len(d.unconsumed_tail)
                self._fail("inflate_error", at, f"deflate stream invalid: {exc}")
                raise _Stop from exc
            if out:
                member.crc_actual = zlib.crc32(out, member.crc_actual)
                member.bytes_out += len(out)
                self.info.bytes_out += len(out)
                yield out
            elif not data:
                raise _Truncated
        inp.unread(d.unused_data)

    def _read_trailer(self, inp: _Input, member: GzipMember) -> None:
        member.crc_expected, member.isize_expected = struct.unpack("<II", inp.read_exact(8))

    def _scan_trailing(self, inp: _Input) -> None:
        self.info.trailing_offset = inp.pos
        all_zero = True
        while data := inp.chunk():
            self.info.trailing_bytes += len(data)
            all_zero = all_zero and not data.strip(b"\0")
        self.info.trailing_all_zero = all_zero


class CompressDecoder:
    """`.Z` (LZW): validate magic and max-bits byte, then decode with `gzip -dc`. No checksum."""

    def __init__(self, path: Path, chunk_bytes: int) -> None:
        self.path = path
        self.chunk_bytes = chunk_bytes
        self.info = ContainerInfo(format="compress", compressed_bytes=path.stat().st_size)

    def _fail(self, kind: str, offset: int, detail: str) -> None:
        self.info.error = StreamError(kind=kind, offset=offset, detail=detail)

    def _header_ok(self) -> bool:
        with self.path.open("rb") as fh:
            head = fh.read(3)
        if len(head) < 3:
            self._fail("unexpected_eof", len(head), "file ends inside the 3-byte .Z header")
            return False
        if head[:2] != COMPRESS_MAGIC:
            self._fail("bad_magic", 0, f"expected 1f9d, found {head[:2].hex()}")
            return False
        flags = head[2]
        self.info.compress_maxbits = flags & 0x1F
        self.info.compress_block_mode = bool(flags & COMPRESS_BLOCK_MODE)
        if flags & COMPRESS_RESERVED:
            self._fail("reserved_flags", 2, f"flag byte 0x{flags:02x} sets reserved bits 0x60")
            return False
        if not 9 <= self.info.compress_maxbits <= 16:
            self._fail("bad_maxbits", 2, f"max bits {self.info.compress_maxbits}, valid is 9..16")
            return False
        return True

    def __iter__(self) -> Iterator[bytes]:
        if not self._header_ok():
            return
        with self.path.open("rb") as fh, tempfile.TemporaryFile() as err:
            proc = subprocess.Popen(["gzip", "-dc"], stdin=fh, stdout=subprocess.PIPE, stderr=err)
            assert proc.stdout is not None
            finished = False
            try:
                while data := proc.stdout.read(self.chunk_bytes):
                    self.info.bytes_out += len(data)
                    yield data
                finished = True
            finally:
                if not finished:
                    proc.kill()
                proc.stdout.close()
                self.info.decoder_exit = proc.wait()
                err.seek(0)
                self.info.decoder_stderr = err.read(MAX_HEADER_STRING).decode(errors="replace")
        if self.info.decoder_exit not in (0, 2):  # gzip: 1 = error, 2 = warning
            detail = f"gzip -dc exited {self.info.decoder_exit}: {self.info.decoder_stderr.strip()}"
            self._fail("decoder_failed", self.info.compressed_bytes, detail)


class UnknownDecoder:
    """Neither gzip nor .Z magic: nothing to decode, the reason is the evidence."""

    def __init__(self, path: Path) -> None:
        self.path = path
        size = path.stat().st_size
        self.info = ContainerInfo(format="unknown", compressed_bytes=size)
        with path.open("rb") as fh:
            magic = fh.read(4)
        kind, detail = (
            ("empty_file", "file is empty") if size == 0 else ("bad_magic", f"magic {magic.hex()}")
        )
        self.info.error = StreamError(kind=kind, offset=0, detail=detail)

    def __iter__(self) -> Iterator[bytes]:
        return iter(())


Decoder = GzipDecoder | CompressDecoder | UnknownDecoder


def open_decoder(path: Path, chunk_bytes: int) -> Decoder:
    fmt = sniff(path)
    if fmt == "gzip":
        return GzipDecoder(path, chunk_bytes)
    if fmt == "compress":
        return CompressDecoder(path, chunk_bytes)
    return UnknownDecoder(path)


class Consumer:
    """Subscriber to the decompressed stream. Override only what you need: a consumer that does not
    override `on_line` never pays for line splitting, one that does not override `on_chunk` never
    sees raw chunks."""

    def on_chunk(self, data: bytes) -> None:
        """Raw decompressed bytes, in order, exactly as decoded."""

    def on_line(self, line: bytes, lineno: int) -> None:
        """One line without its trailing b"\\n"; lineno starts at 1."""

    def on_end(self, end: StreamEnd) -> None:
        """Called once after the last chunk/line."""


def _overrides(consumer: Consumer, name: str) -> bool:
    return getattr(type(consumer), name) is not getattr(Consumer, name)


class FanOut:
    """One decompression pass, many consumers (IMPLEMENTATION_PLAN §3 tee)."""

    def __init__(self, max_line_bytes: int) -> None:
        self.max_line_bytes = max_line_bytes
        self._consumers: list[Consumer] = []

    def subscribe(self, consumer: Consumer) -> Consumer:
        self._consumers.append(consumer)
        return consumer

    def run(
        self, chunks: Iterable[bytes], is_clean: Callable[[], bool] = lambda: True
    ) -> StreamEnd:
        """Drive every consumer from `chunks` in one pass. `is_clean` is asked after the last chunk
        (for a decoder: `lambda: decoder.info.error is None`)."""
        chunk_subs = [c for c in self._consumers if _overrides(c, "on_chunk")]
        line_subs = [c for c in self._consumers if _overrides(c, "on_line")]
        splitter = _LineSplitter(line_subs, self.max_line_bytes)
        bytes_out = 0
        for chunk in chunks:
            bytes_out += len(chunk)
            for c in chunk_subs:
                c.on_chunk(chunk)
            if line_subs:
                splitter.feed(chunk)
        unterminated = splitter.finish()
        end = StreamEnd(
            clean=is_clean(),
            bytes_out=bytes_out,
            lines=splitter.lineno,
            unterminated_tail=unterminated,
        )
        for c in self._consumers:
            c.on_end(end)
        return end


class _LineSplitter:
    """Split chunks on b"\\n" with a bounded carry-over across chunk boundaries."""

    def __init__(self, subs: list[Consumer], max_line_bytes: int) -> None:
        self.subs = subs
        self.max_line_bytes = max_line_bytes
        self.lineno = 0
        self._pending: list[bytes] = []
        self._pending_len = 0

    def _emit(self, line: bytes) -> None:
        self.lineno += 1
        for s in self.subs:
            s.on_line(line, self.lineno)

    def feed(self, chunk: bytes) -> None:
        parts = chunk.split(b"\n")
        if len(parts) == 1:
            self._pending.append(chunk)
            self._pending_len += len(chunk)
            if self._pending_len > self.max_line_bytes:
                raise LineTooLong(
                    f"line {self.lineno + 1} exceeds {self.max_line_bytes} bytes without a newline"
                )
            return
        first = b"".join([*self._pending, parts[0]]) if self._pending else parts[0]
        self._emit(first)
        for line in parts[1:-1]:
            self._emit(line)
        tail = parts[-1]
        self._pending = [tail] if tail else []
        self._pending_len = len(tail)

    def finish(self) -> bool:
        if not self._pending:
            return False
        self._emit(b"".join(self._pending))
        self._pending = []
        return True
