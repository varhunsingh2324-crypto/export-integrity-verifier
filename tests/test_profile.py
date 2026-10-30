import copy
import zlib
from pathlib import Path

import numpy as np
import pytest

from eguard.config import load_policy
from eguard.forensics import profile_file
from eguard.models import ColumnProfile, FileProfile
from eguard.profile import entropy_bits, histogram
from tests import pgdump
from tests.gzutil import member

POLICY = load_policy()
COLS = list(pgdump.COLUMNS)


def _profile(tmp_path: Path, data: bytes, name: str = "export.gz") -> FileProfile:
    path = tmp_path / name
    path.write_bytes(member(data))
    return profile_file(path, copy.deepcopy(POLICY))[0]


def _column(p: FileProfile, name: str) -> ColumnProfile:
    (t,) = p.tables
    return next(c for c in t.columns if c.column == name)


def test_entropy_of_known_bytes() -> None:
    assert entropy_bits(histogram(b"aaaa")) == 0.0
    assert entropy_bits(histogram(bytes(range(256)))) == pytest.approx(8.0)
    assert entropy_bits(histogram(b"ab" * 50)) == pytest.approx(1.0)
    assert entropy_bits(np.zeros(256, dtype=np.int64)) is None


def test_rows_bytes_nulls_are_exact(tmp_path: Path) -> None:
    rows = pgdump.rows(200)
    p = _profile(tmp_path, pgdump.dump_bytes(body=rows))
    fields = [r.split("\t") for r in rows]
    assert p.rows == 200 and p.tables[0].rows == 200 and p.tables[0].unparsed_rows == 0
    for i, name in enumerate(COLS):
        col = _column(p, name)
        values = [f[i].encode() for f in fields]
        assert col.bytes == sum(map(len, values)), name
        assert col.nulls == sum(v == b"\\N" for v in values), name
        assert col.null_fraction == col.nulls / 200
        assert col.avg_width == col.bytes / 200
    remarks = _column(p, "remarks")
    assert remarks.nulls == sum(1 for i in range(1, 201) if i % 7 == 0)  # pgdump.row: every 7th
    assert _column(p, "currency").entropy_bits is not None


def test_byte_components_sum_to_the_stream(tmp_path: Path) -> None:
    data = pgdump.dump_bytes(300)
    p = _profile(tmp_path, data)
    assert p.decompressed_bytes == len(data)
    assert p.field_bytes + p.delimiter_bytes + p.unparsed_bytes + p.other_bytes == len(data)
    assert p.delimiter_bytes == 300 * len(COLS)  # 9 tabs + 1 newline per row
    assert p.compressed_bytes == (tmp_path / "export.gz").stat().st_size
    assert p.format == "gzip" and p.xfl == 0 and p.members == 1 and p.container_error is None


def test_hll_distinct_within_two_percent(tmp_path: Path) -> None:
    p = _profile(tmp_path, pgdump.dump_bytes(5000))
    assert _column(p, "id").distinct_hll == pytest.approx(5000, rel=0.02)
    assert _column(p, "currency").distinct_hll == 3  # USD, EUR, GBP


def test_fixed_level_cost_is_deflate_of_each_section(tmp_path: Path) -> None:
    rows = pgdump.rows(400)
    p = _profile(tmp_path, pgdump.dump_bytes(body=rows))
    level = POLICY["explain"]["level"]
    section = "".join(r + "\n" for r in rows).encode()
    (t,) = p.tables
    assert t.raw_bytes == len(section)
    assert t.fixed_level_bytes == len(zlib.compress(section, level))
    rest = (pgdump.PREAMBLE + pgdump.DDL + pgdump.COPY_HEADER + pgdump.POST_DATA).encode()
    assert p.other_bytes == len(rest)
    assert p.fixed_level_bytes == t.fixed_level_bytes + len(zlib.compress(rest, level))


def test_unparsed_rows_are_counted_not_profiled(tmp_path: Path) -> None:
    rows = pgdump.rows(50)
    bad = "1\t2\t3"
    p = _profile(tmp_path, pgdump.dump_bytes(body=[*rows, bad]))
    (t,) = p.tables
    assert (t.rows, t.unparsed_rows, t.unparsed_bytes) == (50, 1, len(bad) + 1)
    assert p.rows == 51
    assert p.field_bytes + p.delimiter_bytes + p.unparsed_bytes + p.other_bytes == (
        p.decompressed_bytes
    )


def test_all_null_column_has_no_entropy_or_distinct(tmp_path: Path) -> None:
    rows = ["\t".join(r.split("\t")[:8] + ["\\N", "\\N"]) for r in pgdump.rows(30)]
    p = _profile(tmp_path, pgdump.dump_bytes(body=rows))
    remarks = _column(p, "remarks")
    assert remarks.null_fraction == 1.0
    assert remarks.distinct_hll == 0 and remarks.entropy_bits is None and remarks.value_bytes == 0
