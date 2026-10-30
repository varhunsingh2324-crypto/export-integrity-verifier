import copy
import math
import random
import re
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from eguard.config import load_policy
from eguard.forensics import (
    FORMATTERS,
    DecompositionError,
    ProbeSampler,
    column_deltas,
    decompose,
    explain_files,
    factor,
    fmt_change,
    fmt_count,
    fmt_ratio,
    fmt_width,
    probe,
    profile_file,
)
from eguard.models import ExplainReport, FileProfile, StreamEnd
from eguard.report.html import write_reports
from eguard.verify import verify_file
from tests import pgdump
from tests.gzutil import member
from tests.rename import decoy

POLICY = load_policy()
TOL = POLICY["explain"]["identity_tolerance"]


def policy(**explain: Any) -> dict[str, Any]:
    p = copy.deepcopy(POLICY)
    p["explain"] |= {"probe_block_bytes": 16384, "probe_bytes": 1 << 20} | explain
    return p


def write(tmp_path: Path, name: str, data: bytes, level: int = 6, xfl: int = 0) -> Path:
    path = tmp_path / name
    path.write_bytes(member(data, level=level, xfl=xfl))
    return path


def hex_remarks(n: int, seed: int) -> list[str]:
    """Rows whose `remarks` is 96 random hex chars: the expensive-to-compress part."""
    rng = random.Random(seed)
    out = []
    for r in pgdump.rows(n, seed=seed):
        f = r.split("\t")
        f[8] = f"{rng.getrandbits(384):096x}"
        out.append("\t".join(f))
    return out


def purged(rows: list[str]) -> list[str]:
    """The incident's business change in miniature: remarks NULLed."""
    return ["\t".join([*r.split("\t")[:8], "\\N", r.split("\t")[9]]) for r in rows]


def synthetic(rows: int, raw: int, compressed: int, fixed: int, other: int = 0) -> FileProfile:
    """A profile with given totals; field bytes absorb the rest of `raw`."""
    return FileProfile(
        path="synthetic",
        format="gzip",
        compressor="gzip",
        level_hint=None,
        xfl=0,
        compress_maxbits=None,
        members=1,
        container_error=None,
        compressed_bytes=compressed,
        decompressed_bytes=raw,
        lines=rows,
        rows=rows,
        field_bytes=raw - rows - other,
        delimiter_bytes=rows,
        unparsed_bytes=0,
        other_bytes=other,
        fixed_level_bytes=fixed,
        entropy_bits=None,
        tables=[],
        seconds=0.0,
    )


# -- decomposition identity -------------------------------------------------------------------


def test_identity_on_real_profiles(tmp_path: Path) -> None:
    old_rows = hex_remarks(1000, 1)
    new_rows = purged(old_rows) + hex_remarks(300, 2)
    p = policy()
    old, _ = profile_file(write(tmp_path, "a.gz", pgdump.dump_bytes(body=old_rows)), p)
    new, _ = profile_file(write(tmp_path, "b.gz", pgdump.dump_bytes(body=new_rows), 9, 2), p)
    d = decompose(old, new, TOL)
    assert d.observed_ratio == new.compressed_bytes / old.compressed_bytes
    assert d.product == pytest.approx(d.observed_ratio, rel=1e-9)
    assert abs(d.identity_error) < 1e-9
    assert factor(d, "rows").change == pytest.approx(0.3)
    c, cf, e = factor(d, "ratio"), factor(d, "data"), factor(d, "compressor")
    assert c.new / c.old == pytest.approx((cf.new / cf.old) * (e.new / e.old), rel=1e-12)
    w = factor(d, "width")
    assert w.old == old.decompressed_bytes / old.rows and w.new == new.decompressed_bytes / 1300


@settings(max_examples=200, deadline=None)
@given(
    st.integers(1, 10**7),
    st.integers(1, 10**7),
    st.floats(1.0, 500.0),
    st.floats(1.0, 500.0),
    st.floats(1.01, 20.0),
    st.floats(1.01, 20.0),
    st.floats(0.5, 2.0),
    st.floats(0.5, 2.0),
)
def test_identity_property(
    r1: int, r2: int, w1: float, w2: float, c1: float, c2: float, e1: float, e2: float
) -> None:
    def make(r: int, w: float, cf: float, e: float) -> FileProfile:
        raw = max(2 * r, round(r * w))
        return synthetic(r, raw, max(1, round(raw / (cf * e))), max(1, round(raw / cf)))

    d = decompose(make(r1, w1, c1, e1), make(r2, w2, c2, e2), TOL)
    assert abs(d.identity_error) < 1e-9
    assert math.exp(sum(f.effect_ln for f in d.factors if f.effect_ln is not None)) == (
        pytest.approx(d.observed_ratio, rel=1e-9)
    )


def test_components_that_do_not_add_up_fail_the_identity() -> None:
    good = synthetic(1000, 200_000, 90_000, 95_000)
    bad = synthetic(1000, 200_000, 90_000, 95_000)
    bad.other_bytes += 4_000  # W from its parts no longer equals the stream total / R
    decompose(good, good, TOL)
    with pytest.raises(DecompositionError, match="do not add up"):
        decompose(good, bad, TOL)


def test_no_rows_cannot_be_decomposed() -> None:
    with pytest.raises(DecompositionError, match="no COPY rows"):
        decompose(synthetic(0, 5_000, 2_000, 2_000, other=5_000), synthetic(10, 5_000, 2, 2), TOL)


def test_column_deltas_sum_to_delta_w(tmp_path: Path) -> None:
    old_rows = hex_remarks(800, 3)
    p = policy()
    old, _ = profile_file(write(tmp_path, "a.gz", pgdump.dump_bytes(body=old_rows)), p)
    new_body = purged(old_rows) + hex_remarks(240, 4)
    new, _ = profile_file(write(tmp_path, "b.gz", pgdump.dump_bytes(body=new_body)), p)
    d = decompose(old, new, TOL)
    deltas = column_deltas(old, new, d)
    w = factor(d, "width")
    assert sum(x.delta_width for x in deltas) == pytest.approx(w.new - w.old, abs=1e-9)
    assert [x.rank_width for x in deltas] == list(range(1, len(deltas) + 1))
    top = deltas[0]
    assert top.column == "remarks" and top.delta_width < 0
    assert top.new_null_fraction is not None and top.new_null_fraction > 0.7
    assert top.rank_bits == 1  # the purged column also lost the most information per row
    assert {x.column for x in deltas} >= {"(delimiters)", "(non-row bytes)", "(unparsed rows)"}


# -- re-compress probe ------------------------------------------------------------------------


def _explain(tmp_path: Path, old: Path, new: Path, reports: Path | None = None) -> ExplainReport:
    return explain_files(old, new, policy(), reports)


def test_probe_attributes_a_level_change_to_the_compressor(tmp_path: Path) -> None:
    data = pgdump.dump_bytes(body=hex_remarks(3000, 5))
    old, new = write(tmp_path, "a.gz", data, 1, 4), write(tmp_path, "b.gz", data, 9, 2)
    x = _explain(tmp_path, old, new)
    p = x.probe
    assert abs(p.observed_change) > POLICY["explain"]["ratio_unchanged"]
    assert p.probe_change == 0.0 and p.data_share == 0.0
    assert p.hypothesis == x.hypothesis == "H1"
    assert (x.old.level_hint, x.new.level_hint) == ("fastest (-1)", "max (-9)")
    assert factor(x.decomposition, "data").change == 0.0  # same bytes at the fixed level


def test_probe_attributes_a_data_change_to_the_data(tmp_path: Path) -> None:
    rows = hex_remarks(3000, 6)
    old = write(tmp_path, "a.gz", pgdump.dump_bytes(body=rows))
    new = write(tmp_path, "b.gz", pgdump.dump_bytes(body=purged(rows) + hex_remarks(900, 7)))
    x = _explain(tmp_path, old, new)
    p = x.probe
    assert p.data_share is not None and p.data_share >= POLICY["explain"]["data_min_share"]
    assert p.hypothesis == "H2/H3"
    assert p.blocks > 1 and p.sample_bytes == p.blocks * p.block_bytes  # equal size, both files


def test_probe_samples_are_equal_size_and_reproducible() -> None:
    rng = random.Random(9)
    a_data, b_data = rng.randbytes(500_000), rng.randbytes(300_000)

    def sampler(data: bytes, seed: int) -> ProbeSampler:
        s = ProbeSampler(max_bytes=8 * 4096, block_bytes=4096, seed=seed)
        for i in range(0, len(data), 7000):  # chunk boundaries never align with blocks
            s.on_chunk(data[i : i + 7000])
        s.on_end(StreamEnd(clean=True, bytes_out=len(data), lines=0, unterminated_tail=False))
        return s

    ex = policy(probe_seed=0)["explain"]
    a1, a2, a3 = sampler(a_data, 0), sampler(a_data, 0), sampler(a_data, 1)
    assert a1.seen == 500_000 // 4096 and len(a1.kept) == 8
    assert a1.kept == a2.kept and a1.kept != a3.kept
    assert all(a_data[i * 4096 : (i + 1) * 4096] == blk for i, blk in a1.kept)
    r = probe(a1, sampler(b_data, 0), 0.5, ex)
    assert (r.blocks, r.sample_bytes) == (8, 8 * 4096)
    assert r == probe(a2, sampler(b_data, 0), 0.5, ex)


def test_streams_shorter_than_a_block_use_the_whole_stream() -> None:
    a, b = ProbeSampler(1 << 20, 65536, 0), ProbeSampler(1 << 20, 65536, 0)
    a.on_chunk(b"x" * 1000)
    b.on_chunk(b"y" * 700)
    end = StreamEnd(clean=True, bytes_out=0, lines=0, unterminated_tail=False)
    a.on_end(end)
    b.on_end(end)
    r = probe(a, b, 0.0, policy()["explain"])
    assert (r.blocks, r.sample_bytes) == (1, 700)
    assert r.data_share is None and r.hypothesis == "none"  # no observed ratio gap


# -- narrative --------------------------------------------------------------------------------

NUM = re.compile(r"(?<![\w.])[+−-]?\d+(?:,\d{3})*(?:\.\d+)?")


def _leaves(obj: Any) -> tuple[list[float], list[str]]:
    nums: list[float] = []
    strs: list[str] = []
    stack = [obj]
    while stack:
        v = stack.pop()
        if isinstance(v, dict):
            stack += [x for k, x in v.items() if k != "narrative"]
        elif isinstance(v, list):
            stack += v
        elif isinstance(v, str):
            strs.append(v)
        elif isinstance(v, int | float) and not isinstance(v, bool):
            nums.append(v)
    return nums, strs


def assert_numbers_come_from_json(x: ExplainReport) -> None:
    nums, strs = _leaves(x.model_dump(mode="json"))
    allowed = {t for s in strs for t in NUM.findall(s)}
    for v in nums:
        for fmt in FORMATTERS:
            allowed |= set(NUM.findall(fmt(v)))
    for sentence in x.narrative:
        for token in NUM.findall(sentence):
            assert token in allowed, f"{token!r} in {sentence!r} is not a JSON number"


def test_narrative_numbers_match_the_json(tmp_path: Path) -> None:
    rows = hex_remarks(2000, 8)
    old = write(tmp_path, "a.gz", pgdump.dump_bytes(body=rows))
    new = write(tmp_path, "b.gz", pgdump.dump_bytes(body=purged(rows) + hex_remarks(600, 9)))
    x = _explain(tmp_path, old, new)
    assert_numbers_come_from_json(x)
    forged = x.model_copy(update={"narrative": [*x.narrative, "Rows +987.6 % (12,345 → 1)."]})
    with pytest.raises(AssertionError, match="987.6"):  # the check is not vacuous
        assert_numbers_come_from_json(forged)
    d = x.decomposition
    r, w = factor(d, "rows"), factor(d, "width")
    assert (
        x.narrative[0] == f"Rows {fmt_change(r.change)} ({fmt_count(r.old)} → {fmt_count(r.new)})."
    )
    assert x.narrative[1].startswith(
        f"Average row narrowed from {fmt_width(w.old)} to {fmt_width(w.new)} "
        f"({fmt_change(w.change)}), driven by `remarks`"
    )
    c = factor(d, "ratio")
    assert f"Compression ratio {fmt_ratio(c.old)} → {fmt_ratio(c.new)}" in x.narrative[2]
    assert "(H2 narrower rows / H3 more repetitive data)" in x.narrative[3]
    assert f"Net compressed size {fmt_change(d.observed_change)}" in x.narrative[4]
    assert x.narrative[-1].startswith("Integrity: ") and "not verified" in x.narrative[-1]


def _report(tmp_path: Path, path: Path, reports: Path) -> None:
    write_reports(verify_file(path, POLICY, seed=1), reports, f"verify_{path.stem}")


def test_narrative_ends_with_reused_verify_results(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    old = write(tmp_path, "a.gz", pgdump.dump_bytes(400))
    new = write(tmp_path, "b.gz", pgdump.dump_bytes(520))
    _report(tmp_path, old, reports)
    _report(tmp_path, new, reports)
    x = _explain(tmp_path, old, new, reports)
    assert x.integrity_new.status == "found" and x.integrity_new.failed_layers == []
    assert "no integrity layer failed" in x.narrative[-1]
    assert f"new export SUSPECT, RAL {x.integrity_new.ral}" in x.narrative[-1]
    assert_numbers_come_from_json(x)

    killed = write(tmp_path, "k.gz", pgdump.killed_at(520, 300))  # exporter died mid-COPY
    _report(tmp_path, killed, reports)
    x = _explain(tmp_path, old, killed, reports)
    assert x.integrity_new.verdict == "CORRUPT" and 2 in x.integrity_new.failed_layers
    assert "the new export is CORRUPT, failing L2" in x.narrative[-1]
    assert "data loss (H5)" in x.narrative[-1]


def test_stale_verify_report_is_not_reused(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    old = write(tmp_path, "a.gz", pgdump.dump_bytes(300))
    new = write(tmp_path, "b.gz", pgdump.dump_bytes(300))
    _report(tmp_path, new, reports)
    new.write_bytes(member(pgdump.dump_bytes(330)))  # the file changed after it was verified
    x = _explain(tmp_path, old, new, reports)
    assert x.integrity_new.status == "stale" and x.integrity_new.verdict is None
    assert "not verified (verify report: stale)" in x.narrative[-1]


def test_file_names_do_not_change_the_explanation(tmp_path: Path) -> None:
    """Rule 9: renaming both files to random names leaves every measured number identical."""
    rows = hex_remarks(1500, 10)
    old = write(tmp_path, "v1.sql.gz", pgdump.dump_bytes(body=rows))
    new = write(tmp_path, "F7_gzip1.sql.gz", pgdump.dump_bytes(body=purged(rows)), 1, 4)
    a = _explain(tmp_path, old, new)
    b = _explain(tmp_path, decoy(tmp_path, old), decoy(tmp_path, new))
    volatile = {"path", "seconds", "generated_at", "report", "detail"}

    def strip(x: Any) -> Any:
        if isinstance(x, dict):
            return {k: strip(v) for k, v in x.items() if k not in volatile}
        return [strip(v) for v in x] if isinstance(x, list) else x

    assert strip(a.model_dump(mode="json")) == strip(b.model_dump(mode="json"))
