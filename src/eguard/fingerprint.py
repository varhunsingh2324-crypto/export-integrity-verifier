"""Row, table and chunk fingerprints (IMPLEMENTATION_PLAN §4 L4).

    h(row)  = first 8 bytes of BLAKE2b-512(raw COPY line, no newline), big-endian uint64
    table   = (count, sum h mod 2**64, xor h)       order-independent
    chunk   = BLAKE2b-128 over the 8-byte h of `chunk_rows` consecutive rows, in stream order
    root    = BLAKE2b-128 over the chunk digests

Only COPY row lines are hashed, so `\\restrict` keys and other per-run noise never enter a row
fingerprint; the whole stream is covered separately by StreamDigest (sha256). Memory per table is
O(rows / chunk_rows) digests.
"""

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass

from eguard.models import (
    ChunkFingerprint,
    CopyBlock,
    DumpStructure,
    StreamDigestInfo,
    StreamEnd,
    TableDef,
    TableFingerprint,
)
from eguard.stream import Consumer

MASK64 = (1 << 64) - 1
DIGEST_BYTES = 16
ALGORITHMS = {
    "row_hash": "blake2b-512[:8] big-endian uint64 of the raw COPY line without newline",
    "table": "count, sum mod 2^64, xor of row hashes",
    "chunk": "blake2b-128 over the 8-byte row hashes, stream order",
    "root": "blake2b-128 over the chunk digests",
    "stream": "sha256 of the decompressed stream",
}


def row_hash_bytes(line: bytes) -> bytes:
    return hashlib.blake2b(line).digest()[:8]


def row_hash(line: bytes) -> int:
    return int.from_bytes(row_hash_bytes(line), "big")


def hex64(value: int) -> str:
    return f"{value:016x}"


@dataclass(slots=True)
class TableFp:
    """The order-independent part of a table fingerprint."""

    count: int = 0
    sum64: int = 0
    xor64: int = 0

    def add(self, h: int) -> None:
        self.count += 1
        self.sum64 = (self.sum64 + h) & MASK64
        self.xor64 ^= h

    @classmethod
    def of(cls, lines: Iterable[bytes]) -> "TableFp":
        fp = cls()
        for line in lines:
            fp.add(row_hash(line))
        return fp


class _BlockFp:
    """Fingerprint of one COPY block while its rows stream past."""

    def __init__(self, table: str, chunk_rows: int) -> None:
        self.table = table
        self.chunk_rows = chunk_rows
        self.fp = TableFp()
        self.chunks: list[ChunkFingerprint] = []
        self._hasher = hashlib.blake2b(digest_size=DIGEST_BYTES)
        self._first_line = 0
        self._last_line = 0

    def add(self, line: bytes, lineno: int) -> None:
        hb = row_hash_bytes(line)
        self.fp.add(int.from_bytes(hb, "big"))
        if (self.fp.count - 1) % self.chunk_rows == 0:  # first row of a chunk
            self._first_line = lineno
        self._hasher.update(hb)
        self._last_line = lineno
        if self.fp.count % self.chunk_rows == 0:
            self._close_chunk()

    def _close_chunk(self) -> None:
        index = len(self.chunks) + 1
        self.chunks.append(
            ChunkFingerprint(
                index=index,
                first_row=(index - 1) * self.chunk_rows + 1,
                last_row=self.fp.count,
                first_line=self._first_line,
                last_line=self._last_line,
                digest=self._hasher.hexdigest(),
            )
        )
        self._hasher = hashlib.blake2b(digest_size=DIGEST_BYTES)

    def finish(self, closed: bool) -> TableFingerprint:
        if self.fp.count % self.chunk_rows:
            self._close_chunk()
        root = hashlib.blake2b(digest_size=DIGEST_BYTES)
        for c in self.chunks:
            root.update(bytes.fromhex(c.digest))
        return TableFingerprint(
            table=self.table,
            count=self.fp.count,
            sum64=hex64(self.fp.sum64),
            xor64=hex64(self.fp.xor64),
            root=root.hexdigest(),
            closed=closed,
            chunks=self.chunks,
        )


class Fingerprinter:
    """DumpListener: one TableFingerprint per COPY block, in stream order."""

    def __init__(self, chunk_rows: int) -> None:
        if chunk_rows < 1:
            raise ValueError("chunk_rows must be >= 1")
        self.chunk_rows = chunk_rows
        self.tables: list[TableFingerprint] = []
        self._cur: _BlockFp | None = None

    def on_copy_start(self, block: CopyBlock, table: TableDef | None) -> None:
        self._cur = _BlockFp(block.table, self.chunk_rows)

    def on_row(self, block: CopyBlock, line: bytes, lineno: int) -> None:
        assert self._cur is not None
        self._cur.add(line, lineno)

    def on_copy_end(self, block: CopyBlock) -> None:
        assert self._cur is not None
        self.tables.append(self._cur.finish(closed=True))
        self._cur = None

    def on_finish(self, structure: DumpStructure) -> None:
        if self._cur is not None:  # stream ended inside COPY: keep what was seen
            self.tables.append(self._cur.finish(closed=False))
            self._cur = None


class StreamDigest(Consumer):
    """sha256 and size of the whole decompressed stream."""

    def __init__(self) -> None:
        self._sha = hashlib.sha256()
        self._bytes = 0
        self.info: StreamDigestInfo | None = None

    def on_chunk(self, data: bytes) -> None:
        self._sha.update(data)
        self._bytes += len(data)

    def on_end(self, end: StreamEnd) -> None:
        self.info = StreamDigestInfo(
            bytes=self._bytes, lines=end.lines, sha256=self._sha.hexdigest()
        )
