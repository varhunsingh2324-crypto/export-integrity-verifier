import hashlib

from hypothesis import given
from hypothesis import strategies as st

from eguard.fingerprint import Fingerprinter, TableFp, row_hash
from eguard.models import CopyBlock

ROW = st.binary(max_size=40).filter(lambda b: b"\n" not in b)
ROWS = st.lists(ROW, min_size=1, max_size=60)


def fingerprint(lines: list[bytes], chunk_rows: int):
    """Drive a Fingerprinter like the parser does: one COPY block, rows on lines 10, 11, ..."""
    fp = Fingerprinter(chunk_rows)
    block = CopyBlock(table="public.t", columns=["a"], header_line=9)
    fp.on_copy_start(block, None)
    for i, line in enumerate(lines):
        fp.on_row(block, line, 10 + i)
    block.closed = True
    fp.on_copy_end(block)
    (table,) = fp.tables
    return table


def test_row_hash_is_first_8_bytes_of_blake2b_512_big_endian() -> None:
    # Literal vector: blake2b(digest_size=8) would give 0xa2c1ff08cc1b38e4, a different hash.
    assert row_hash(b"1\t42\tabc") == 0x6189D28B21B9F4F6
    full = hashlib.blake2b(b"x").digest()
    assert row_hash(b"x") == int.from_bytes(full[:8], "big")


@given(ROWS, st.randoms(use_true_random=False))
def test_table_fp_is_order_independent(lines: list[bytes], rnd) -> None:
    shuffled = lines[:]
    rnd.shuffle(shuffled)
    assert TableFp.of(shuffled) == TableFp.of(lines)


@given(ROWS, st.data())
def test_any_single_row_replacement_changes_fp(lines: list[bytes], data: st.DataObject) -> None:
    i = data.draw(st.integers(0, len(lines) - 1))
    new = data.draw(ROW.filter(lambda b: b != lines[i]))
    assert TableFp.of(lines[:i] + [new] + lines[i + 1 :]) != TableFp.of(lines)


@given(ROWS, st.data())
def test_single_row_delete_insert_duplicate_changes_fp(
    lines: list[bytes], data: st.DataObject
) -> None:
    i = data.draw(st.integers(0, len(lines) - 1))
    new = data.draw(ROW)
    base = TableFp.of(lines)
    assert TableFp.of(lines[:i] + lines[i + 1 :]) != base
    assert TableFp.of(lines[:i] + [new] + lines[i:]) != base
    assert TableFp.of(lines[:i] + [lines[i]] + lines[i:]) != base


def test_duplicate_pair_cancels_in_xor_but_not_in_sum() -> None:
    a, b = TableFp.of([b"r1"]), TableFp.of([b"r1", b"r2", b"r2"])
    assert a.xor64 == b.xor64  # why xor alone is not enough
    assert a.sum64 != b.sum64 and a.count != b.count


def test_chunks_cover_rows_in_stream_order() -> None:
    t = fingerprint([f"row{i}".encode() for i in range(1, 8)], chunk_rows=3)
    assert [(c.index, c.first_row, c.last_row) for c in t.chunks] == [
        (1, 1, 3),
        (2, 4, 6),
        (3, 7, 7),
    ]
    assert [(c.first_line, c.last_line) for c in t.chunks] == [(10, 12), (13, 15), (16, 16)]
    assert t.count == 7 and t.closed
    ref = TableFp.of([f"row{i}".encode() for i in range(1, 8)])
    assert (t.sum64, t.xor64) == (f"{ref.sum64:016x}", f"{ref.xor64:016x}")


@given(st.lists(ROW, min_size=7, max_size=30, unique=True), st.data())
def test_single_row_change_damages_exactly_its_chunk(
    lines: list[bytes], data: st.DataObject
) -> None:
    i = data.draw(st.integers(0, len(lines) - 1))
    new = data.draw(ROW.filter(lambda b: b != lines[i]))
    a = fingerprint(lines, chunk_rows=3)
    b = fingerprint(lines[:i] + [new] + lines[i + 1 :], chunk_rows=3)
    pairs = zip(a.chunks, b.chunks, strict=True)
    damaged = [ca.index for ca, cb in pairs if ca.digest != cb.digest]
    assert damaged == [i // 3 + 1]
    assert a.root != b.root


def test_chunk_digest_is_order_sensitive_table_fp_is_not() -> None:
    a = fingerprint([b"x", b"y", b"z"], chunk_rows=3)
    b = fingerprint([b"z", b"y", b"x"], chunk_rows=3)
    assert (a.count, a.sum64, a.xor64) == (b.count, b.sum64, b.xor64)
    assert a.chunks[0].digest != b.chunks[0].digest


def test_unclosed_block_is_kept_on_finish() -> None:
    fp = Fingerprinter(chunk_rows=2)
    block = CopyBlock(table="public.t", columns=["a"], header_line=1)
    fp.on_copy_start(block, None)
    for i in range(3):
        fp.on_row(block, b"r%d" % i, 2 + i)
    fp.on_finish(None)  # type: ignore[arg-type]
    (t,) = fp.tables
    assert t.count == 3 and not t.closed and len(t.chunks) == 2


def test_empty_block_has_no_chunks() -> None:
    t = fingerprint([], chunk_rows=3)
    assert t.count == 0 and t.chunks == [] and t.sum64 == "0" * 16
