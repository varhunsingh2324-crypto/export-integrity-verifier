"""Per-table and per-column profile of one export (IMPLEMENTATION_PLAN §5 step 1).

It runs in the same single streaming pass as everything else: `Profiler` listens to the parser's
rows and also subscribes to the line fan-out, after the parser, to catch the non-row lines.
Memory is bounded (rule 2): per column one HyperLogLog (2**p registers), a 256-bin
byte histogram and a flush buffer of at most FLUSH_BYTES; per table one deflate stream.
"""

import warnings
import zlib
from typing import Any

import numpy as np
from datasketch import HyperLogLog

from eguard.container import summary
from eguard.models import (
    ColumnProfile,
    ContainerInfo,
    CopyBlock,
    DumpStructure,
    FileProfile,
    StreamEnd,
    TableDef,
    TableProfile,
)
from eguard.stream import Consumer

NULL = b"\\N"
FLUSH_BYTES = 1 << 20  # bytes buffered before a histogram update / deflate call


def histogram(data: bytes | bytearray) -> np.ndarray:
    return np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).astype(np.int64)


def entropy_bits(hist: np.ndarray) -> float | None:
    """Shannon entropy of a byte histogram, in bits per byte; None for no bytes."""
    total = int(hist.sum())
    if total == 0:
        return None
    p = hist[hist > 0] / total
    return float(-(p * np.log2(p)).sum()) + 0.0  # + 0.0: never -0.0


class ByteHistogram(Consumer):
    """Byte histogram of the whole decompressed stream."""

    def __init__(self) -> None:
        self.hist = np.zeros(256, dtype=np.int64)

    def on_chunk(self, data: bytes) -> None:
        self.hist += histogram(data)


class _Deflate:
    """Compressed size of a byte stream at a fixed level, fed in batches."""

    def __init__(self, level: int) -> None:
        self._z = zlib.compressobj(level)
        self._batch: list[bytes] = []
        self._pending = 0
        self.raw = 0
        self.out = 0
        self.hist = np.zeros(256, dtype=np.int64)

    def add(self, line: bytes) -> None:
        """One line; its newline is added here."""
        self._batch.append(line)
        self._pending += len(line) + 1
        if self._pending >= FLUSH_BYTES:
            self.flush()

    def flush(self) -> None:
        if not self._batch:
            return
        data = b"\n".join(self._batch) + b"\n"
        self._batch, self._pending = [], 0
        self.raw += len(data)
        self.out += len(self._z.compress(data))
        self.hist += histogram(data)

    def finish(self) -> None:
        self.flush()
        self.out += len(self._z.flush())


class _Column:
    __slots__ = ("name", "bytes", "nulls", "hll", "hist", "buf")

    def __init__(self, name: str, precision: int) -> None:
        self.name = name
        self.bytes = 0
        self.nulls = 0
        self.hll = HyperLogLog(p=precision)
        self.hist = np.zeros(256, dtype=np.int64)
        self.buf = bytearray()

    def flush(self) -> None:
        if self.buf:
            self.hist += histogram(self.buf)
            self.buf = bytearray()

    def distinct(self) -> int:
        with warnings.catch_warnings():  # datasketch warns near its small-range correction
            warnings.simplefilter("ignore", UserWarning)
            return round(self.hll.count())

    def result(self, rows: int) -> ColumnProfile:
        self.flush()
        return ColumnProfile(
            column=self.name,
            rows=rows,
            bytes=self.bytes,
            value_bytes=int(self.hist.sum()),
            nulls=self.nulls,
            null_fraction=self.nulls / rows if rows else 0.0,
            avg_width=self.bytes / rows if rows else 0.0,
            distinct_hll=self.distinct() if rows > self.nulls else 0,
            entropy_bits=entropy_bits(self.hist),
        )


class _Table:
    def __init__(self, name: str, columns: list[str], level: int, precision: int) -> None:
        self.name = name
        self.precision = precision
        self.cols = [_Column(c, precision) for c in columns]
        self.rows = 0
        self.unparsed_rows = 0
        self.unparsed_bytes = 0
        self.section = _Deflate(level)

    def result(self) -> TableProfile:
        self.section.finish()
        raw = self.section.raw
        return TableProfile(
            table=self.name,
            rows=self.rows,
            unparsed_rows=self.unparsed_rows,
            unparsed_bytes=self.unparsed_bytes,
            raw_bytes=raw,
            fixed_level_bytes=self.section.out,
            fixed_ratio=raw / self.section.out if self.section.out and raw else None,
            entropy_bits=entropy_bits(self.section.hist),
            columns=[c.result(self.rows) for c in self.cols],
        )


class Profiler(Consumer):
    """DumpListener for rows (add to the parser) and line Consumer for everything else (subscribe
    to the fan-out *after* the parser). The parser handles line N-1 when it receives line N, so
    when `on_line(N)` arrives the previous line's fate is known: a row or a non-row line."""

    def __init__(self, level: int, hll_precision: int) -> None:
        self.level = level
        self.precision = hll_precision
        self.tables: dict[str, _Table] = {}
        self._cur: _Table | None = None
        self._other = _Deflate(level)
        self._pending: tuple[bytes, int] | None = None
        self._last_row = 0
        self.end: StreamEnd | None = None

    # -- DumpListener ------------------------------------------------------------------------
    def on_copy_start(self, block: CopyBlock, table: TableDef | None) -> None:
        t = self.tables.get(block.table)
        if t is None:
            t = _Table(block.table, block.columns, self.level, self.precision)
            self.tables[block.table] = t
        self._cur = t

    def on_row(self, block: CopyBlock, line: bytes, lineno: int) -> None:
        self._last_row = lineno
        t = self._cur
        assert t is not None
        t.section.add(line)
        fields = line.split(b"\t")
        if not t.cols and not t.rows:  # unreadable COPY header: take the first row's shape
            t.cols = [_Column(f"column{i + 1}", t.precision) for i in range(len(fields))]
        if len(fields) != len(t.cols):
            t.unparsed_rows += 1
            t.unparsed_bytes += len(line) + 1
            return
        t.rows += 1
        for col, f in zip(t.cols, fields, strict=True):
            col.bytes += len(f)
            if f == NULL:
                col.nulls += 1
                continue
            col.hll.update(f)
            col.buf += f
            if len(col.buf) >= FLUSH_BYTES:
                col.flush()

    def on_copy_end(self, block: CopyBlock) -> None:
        self._cur = None

    def on_finish(self, structure: DumpStructure) -> None:
        pass

    # -- Consumer ----------------------------------------------------------------------------
    def _settle(self) -> None:
        if self._pending is not None:
            line, lineno = self._pending
            if lineno != self._last_row:
                self._other.add(line)
            self._pending = None

    def on_line(self, line: bytes, lineno: int) -> None:
        self._settle()
        self._pending = (line, lineno)

    def on_end(self, end: StreamEnd) -> None:
        self._settle()  # the parser's on_end (subscribed first) has handled the last line
        self._other.finish()
        self.end = end

    # -- result ------------------------------------------------------------------------------
    def result(
        self, path: str, info: ContainerInfo, stream_hist: np.ndarray, seconds: float
    ) -> FileProfile:
        assert self.end is not None
        tables = [t.result() for t in self.tables.values()]
        fields = sum(c.bytes for t in tables for c in t.columns)
        delimiters = sum(t.rows * len(t.columns) for t in tables)
        unparsed = sum(t.unparsed_bytes for t in tables)
        rows_bytes = sum(t.raw_bytes for t in tables)
        return FileProfile(
            path=path,
            **_container(info),
            decompressed_bytes=self.end.bytes_out,
            lines=self.end.lines,
            rows=sum(t.rows + t.unparsed_rows for t in tables),
            field_bytes=fields,
            delimiter_bytes=delimiters,
            unparsed_bytes=unparsed,
            other_bytes=self.end.bytes_out - rows_bytes,
            fixed_level_bytes=sum(t.fixed_level_bytes for t in tables) + self._other.out,
            entropy_bits=entropy_bits(stream_hist),
            tables=tables,
            seconds=round(seconds, 3),
        )


def _container(info: ContainerInfo) -> dict[str, Any]:
    s = summary(info)
    return {
        "format": info.format,
        "compressor": s["compressor"],
        "level_hint": s["level_hint"],
        "xfl": info.members[0].xfl if info.members else None,
        "compress_maxbits": info.compress_maxbits,
        "members": s["members"],
        "container_error": f"{info.error.kind}: {info.error.detail}" if info.error else None,
        "compressed_bytes": info.compressed_bytes,
    }
