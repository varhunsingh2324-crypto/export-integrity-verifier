"""`eguard explain OLD NEW`: why did the compressed size change? (IMPLEMENTATION_PLAN §2, §5)

    S = R × W ÷ C,  C = C_fixed × E
    ln(S2/S1) = ln(R2/R1) + ln(W2/W1) − ln(C_fixed2/C_fixed1) − ln(E2/E1)

R rows, W decompressed bytes per row, C = decompressed ÷ compressed. C_fixed is the same stream
deflated at policy explain.level (section by section), so it measures the data alone; E = C ÷
C_fixed is what the original compressor did beyond (or short of) that level. The re-compress probe
tests the same split independently on equal-size samples (H1 compressor vs H2/H3 data).

One streaming pass per file, nothing decompressed on disk; every sentence of the narrative is
formatted from a field of the ExplainReport (tests/test_forensics.py checks that).
"""

import json
import math
import random
import time
import zlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from eguard import __version__
from eguard.models import (
    ColumnDelta,
    Decomposition,
    ExplainReport,
    Factor,
    FileProfile,
    IntegrityRef,
    ProbeResult,
    Status,
    VerifyReport,
)
from eguard.parsers.pg_plain import PgPlainParser
from eguard.profile import ByteHistogram, Profiler
from eguard.stream import Consumer, FanOut, open_decoder


class DecompositionError(Exception):
    """The waterfall does not multiply back to the observed size ratio (or cannot be built)."""


# -- re-compress probe ------------------------------------------------------------------------


class ProbeSampler(Consumer):
    """Uniform reservoir (Algorithm R) of fixed-size blocks of the decompressed stream, at most
    `max_bytes` kept. Streams shorter than one block keep their partial block instead."""

    def __init__(self, max_bytes: int, block_bytes: int, seed: int) -> None:
        self.k = max(1, max_bytes // block_bytes)
        self.block = block_bytes
        self.rng = random.Random(seed)
        self.seen = 0  # full blocks offered
        self.kept: list[tuple[int, bytes]] = []  # (block index, bytes)
        self._carry = b""

    def on_chunk(self, data: bytes) -> None:
        if self._carry:
            data = self._carry + data
        view, size = memoryview(data), self.block
        full = len(data) // size
        for i in range(full):
            self._offer(view[i * size : (i + 1) * size])
        self._carry = bytes(view[full * size :])

    def _offer(self, block: memoryview) -> None:
        idx = self.seen
        self.seen += 1
        if len(self.kept) < self.k:
            self.kept.append((idx, bytes(block)))
            return
        j = self.rng.randrange(idx + 1)
        if j < self.k:
            self.kept[j] = (idx, bytes(block))

    def on_end(self, end: Any) -> None:
        if not self.kept and self._carry:
            self.kept.append((0, self._carry))
        self._carry = b""


def _chosen(kept: list[tuple[int, bytes]], n: int, rng: random.Random) -> list[bytes]:
    picked = kept if len(kept) == n else rng.sample(kept, n)
    return [b for _, b in sorted(picked)]


def _deflated(blocks: list[bytes], size: int, level: int) -> int:
    """Deflate the first `size` bytes of the concatenated blocks; return the compressed size."""
    z, left, out = zlib.compressobj(level), size, 0
    for b in blocks:
        if left <= 0:
            break
        piece = b[:left]
        left -= len(piece)
        out += len(z.compress(piece))
    return out + len(z.flush())


def classify(data_share: float | None, ex: dict[str, Any]) -> str:
    if data_share is None:
        return "none"
    if data_share <= ex["h1_max_data_share"]:
        return "H1"
    if data_share >= ex["data_min_share"]:
        return "H2/H3"
    return "mixed"


def probe(
    old: ProbeSampler, new: ProbeSampler, observed_change: float, ex: dict[str, Any]
) -> ProbeResult:
    """Same block count from both reservoirs, same byte count, same deflate level."""
    rng = random.Random(ex["probe_seed"])
    n = min(len(old.kept), len(new.kept))
    a, b = _chosen(old.kept, n, rng), _chosen(new.kept, n, rng)
    size = min(sum(map(len, a)), sum(map(len, b)))
    ra = rb = change = share = None
    if size:
        ra = size / _deflated(a, size, ex["level"])
        rb = size / _deflated(b, size, ex["level"])
        change = rb / ra - 1
        if abs(observed_change) >= ex["ratio_unchanged"]:
            share = math.log(rb / ra) / math.log1p(observed_change)
    return ProbeResult(
        compressor="deflate (zlib)",
        level=ex["level"],
        seed=ex["probe_seed"],
        block_bytes=old.block,
        blocks=n,
        sample_bytes=size,
        old_ratio=ra,
        new_ratio=rb,
        probe_change=change,
        observed_change=observed_change,
        ratio_unchanged=ex["ratio_unchanged"],
        data_share=share,
        hypothesis=classify(share, ex),
    )


# -- one pass per file ------------------------------------------------------------------------


def profile_file(path: Path, policy: dict[str, Any]) -> tuple[FileProfile, ProbeSampler]:
    """Decompress once; the parser, profiler, probe reservoir and byte histogram share the pass."""
    ex, started = policy["explain"], time.perf_counter()
    decoder = open_decoder(path, policy["stream"]["chunk_bytes"])
    fan = FanOut(policy["stream"]["max_line_bytes"])
    hist = ByteHistogram()
    sampler = ProbeSampler(ex["probe_bytes"], ex["probe_block_bytes"], ex["probe_seed"])
    parser, profiler = PgPlainParser(), Profiler(ex["level"], ex["hll_precision"])
    parser.add_listener(profiler)
    for consumer in (hist, sampler, parser, profiler):  # profiler after parser: see Profiler
        fan.subscribe(consumer)
    fan.run(decoder, is_clean=lambda: decoder.info.error is None)
    seconds = time.perf_counter() - started
    return profiler.result(str(path), decoder.info, hist.hist, seconds), sampler


# -- decomposition ----------------------------------------------------------------------------

STEPS = (  # name, label, sign in ln S
    ("rows", "Rows (R)", 1),
    ("width", "Bytes per row (W)", 1),
    ("data", "Compression ratio of the data at a fixed level (C_fixed)", -1),
    ("compressor", "Compressor efficiency (E = C ÷ C_fixed)", -1),
)


def _factors(p: FileProfile) -> dict[str, float]:
    if p.rows == 0:
        raise DecompositionError(f"{p.path}: no COPY rows, so bytes per row is undefined")
    if not p.compressed_bytes or not p.fixed_level_bytes or not p.decompressed_bytes:
        raise DecompositionError(f"{p.path}: empty stream, nothing to decompose")
    raw = p.field_bytes + p.delimiter_bytes + p.unparsed_bytes + p.other_bytes  # W from its parts
    c = p.decompressed_bytes / p.compressed_bytes  # C from the stream total
    c_fixed = p.decompressed_bytes / p.fixed_level_bytes
    return {
        "rows": p.rows,
        "width": raw / p.rows,
        "data": c_fixed,
        "compressor": c / c_fixed,
        "ratio": c,
    }


def decompose(old: FileProfile, new: FileProfile, tolerance: float) -> Decomposition:
    """Raises DecompositionError unless the steps multiply back to S_new / S_old within
    `tolerance` (policy explain.identity_tolerance)."""
    fo, fn = _factors(old), _factors(new)
    factors: list[Factor] = []
    for name, label, sign in STEPS:
        effect = sign * math.log(fn[name] / fo[name])
        factors.append(_factor(name, label, fo[name], fn[name], effect))
    factors.append(_factor("ratio", "Compression ratio (C)", fo["ratio"], fn["ratio"], None))
    observed = new.compressed_bytes / old.compressed_bytes
    product = math.exp(sum(f.effect_ln for f in factors if f.effect_ln is not None))
    error = product / observed - 1
    if not abs(error) <= tolerance:
        raise DecompositionError(
            f"waterfall product {product:.6f} vs observed size ratio {observed:.6f} "
            f"(error {error:+.4%} > {tolerance:.2%}): the byte components do not add up"
        )
    return Decomposition(
        factors=factors,
        observed_ratio=observed,
        observed_change=observed - 1,
        product=product,
        identity_error=error,
    )


def _factor(name: str, label: str, old: float, new: float, effect: float | None) -> Factor:
    return Factor(
        name=name,
        label=label,
        old=old,
        new=new,
        change=new / old - 1,
        effect_ln=effect,
        size_effect=None if effect is None else math.expm1(effect),
    )


def factor(d: Decomposition, name: str) -> Factor:
    return next(f for f in d.factors if f.name == name)


# -- column drill-down ------------------------------------------------------------------------

MAX_DRIVERS = 2  # columns named in the narrative's width sentence
OVERHEAD = ("(delimiters)", "(unparsed rows)", "(non-row bytes)")


def _components(p: FileProfile) -> dict[tuple[str | None, str], dict[str, Any]]:
    """Every component of W, as bytes per row of the whole file (they sum to W)."""
    out: dict[tuple[str | None, str], dict[str, Any]] = {}
    for t in p.tables:
        for c in t.columns:
            bits = None if c.entropy_bits is None else c.entropy_bits * c.value_bytes / p.rows
            out[(t.table, c.column)] = {"width": c.bytes / p.rows, "bits": bits, "col": c}
    for name, value in zip(
        OVERHEAD, (p.delimiter_bytes, p.unparsed_bytes, p.other_bytes), strict=True
    ):
        out[(None, name)] = {"width": value / p.rows, "bits": None, "col": None}
    return out


def _delta(
    key: tuple[str | None, str], o: dict[str, Any] | None, n: dict[str, Any] | None
) -> ColumnDelta:
    oc, nc = (o or {}).get("col"), (n or {}).get("col")
    ob, nb = (o or {}).get("bits"), (n or {}).get("bits")
    ow, nw = (o or {"width": 0.0})["width"], (n or {"width": 0.0})["width"]
    oe, ne = (oc.entropy_bits if oc else None), (nc.entropy_bits if nc else None)
    return ColumnDelta(
        table=key[0],
        column=key[1],
        present="both" if o and n else ("old" if o else "new"),
        old_width=ow,
        new_width=nw,
        delta_width=nw - ow,
        old_avg_width=oc.avg_width if oc else None,
        new_avg_width=nc.avg_width if nc else None,
        old_null_fraction=oc.null_fraction if oc else None,
        new_null_fraction=nc.null_fraction if nc else None,
        old_distinct=oc.distinct_hll if oc else None,
        new_distinct=nc.distinct_hll if nc else None,
        old_entropy=oe,
        new_entropy=ne,
        delta_entropy=None if oe is None or ne is None else ne - oe,
        old_bits_per_row=ob,
        new_bits_per_row=nb,
        delta_bits=None if ob is None and nb is None else (nb or 0.0) - (ob or 0.0),
        rank_width=0,
        rank_bits=None,
    )


def column_deltas(old: FileProfile, new: FileProfile, d: Decomposition) -> list[ColumnDelta]:
    """Every W component, ranked by |Δwidth| (and by |Δbits per row| where entropy applies).
    Raises DecompositionError unless Σ Δwidth equals the decomposition's ΔW."""
    o, n = _components(old), _components(new)
    keys = list(o) + [k for k in n if k not in o]
    deltas = [_delta(k, o.get(k), n.get(k)) for k in keys]
    width = factor(d, "width")
    total = sum(x.delta_width for x in deltas)
    if not math.isclose(total, width.new - width.old, rel_tol=1e-9, abs_tol=1e-9):
        raise DecompositionError(
            f"column widths sum to ΔW {total:.6f}, expected {width.new - width.old:.6f}"
        )
    for rank, x in enumerate(sorted(deltas, key=lambda x: -abs(x.delta_width)), 1):
        x.rank_width = rank
    with_bits = [x for x in deltas if x.delta_bits is not None]
    for rank, x in enumerate(sorted(with_bits, key=lambda x: -abs(x.delta_bits or 0.0)), 1):
        x.rank_bits = rank
    return sorted(deltas, key=lambda x: x.rank_width)


# -- integrity: reuse a saved verify report ---------------------------------------------------


def _sizes(r: VerifyReport) -> tuple[Any, Any]:
    fmt = next((c for c in r.checks if c.name == "l1_format"), None)
    ev = fmt.evidence if fmt else {}
    return ev.get("compressed_bytes"), ev.get("uncompressed_bytes")


def find_verify_report(path: Path, p: FileProfile, reports: Path | None) -> IntegrityRef:
    """The `verify_*.json` under `reports` for this same file. It is reused only if its L1 byte
    counts equal what this pass measured; otherwise it describes another version of the file."""
    if reports is None or not reports.is_dir():
        return IntegrityRef(status="none", detail=f"no report directory {reports}")
    target = path.resolve()
    for f in sorted(reports.glob("verify_*.json")):
        try:
            body = json.loads(f.read_text())
            if not isinstance(body, dict) or "checks" not in body:
                continue  # e.g. verify_all.json
            if Path(body.get("path", "")).resolve() != target:
                continue
            r = VerifyReport.model_validate(body)
        except (OSError, ValueError, ValidationError):
            continue
        if _sizes(r) != (p.compressed_bytes, p.decompressed_bytes):
            return IntegrityRef(
                status="stale",
                report=str(f),
                generated_at=r.generated_at or None,
                detail=f"{f.name} measured {_sizes(r)} bytes (compressed, decompressed), "
                f"this pass {(p.compressed_bytes, p.decompressed_bytes)}: not reused",
            )
        return IntegrityRef(
            status="found",
            report=str(f),
            verdict=r.verdict,
            ral=r.ral,
            failed_layers=[lr.layer for lr in r.layers if lr.status == Status.FAIL],
            incomplete_layers=[
                lr.layer for lr in r.layers if lr.status in (Status.WARN, Status.SKIP)
            ],
            generated_at=r.generated_at or None,
            detail=f"{f.name}: {r.verdict} (RAL {r.ral})",
        )
    return IntegrityRef(status="none", detail=f"no verify report for this file in {reports}")


# -- narrative --------------------------------------------------------------------------------
# Every number in the narrative goes through one of these, from a field of the ExplainReport.


def fmt_count(n: float) -> str:
    return f"{round(n):,}"


def fmt_change(x: float) -> str:
    pct = round(x * 100, 1)
    return f"{'−' if pct < 0 else '+'}{abs(pct):.1f} %"  # never "−0.0 %"


def fmt_fraction(x: float) -> str:
    return f"{x * 100:.1f} %"


def fmt_width(x: float) -> str:
    return f"{x:,.1f} B"


def fmt_bytes(n: float) -> str:
    return f"{round(n):,} B"


def fmt_mib(n: float) -> str:
    return f"{n / 2**20:.1f} MiB"


def fmt_ratio(x: float) -> str:
    return f"{x:.2f}×"


FORMATTERS = (fmt_count, fmt_change, fmt_fraction, fmt_width, fmt_bytes, fmt_mib, fmt_ratio)


def _rows_sentence(d: Decomposition) -> str:
    r = factor(d, "rows")
    return f"Rows {fmt_change(r.change)} ({fmt_count(r.old)} → {fmt_count(r.new)})."


def _width_sentence(x: ExplainReport) -> str:
    w = factor(x.decomposition, "width")
    if fmt_width(w.old) == fmt_width(w.new):
        return f"Average row unchanged at {fmt_width(w.new)} ({fmt_change(w.change)})."
    verb = "narrowed" if w.change < 0 else "widened"
    text = (
        f"Average row {verb} from {fmt_width(w.old)} to {fmt_width(w.new)} ({fmt_change(w.change)})"
    )
    drivers = _drivers(x.columns)
    if not drivers:
        return text + "."
    return text + ", driven by " + " and ".join(_driver(c) for c in drivers) + "."


def _drivers(columns: list[ColumnDelta]) -> list[ColumnDelta]:
    """The largest W component, plus the runner-up when it moved at least half as much."""
    top = [c for c in columns if c.delta_width != 0][:MAX_DRIVERS]
    return [c for c in top if abs(c.delta_width) * 2 >= abs(top[0].delta_width)]


def _driver(c: ColumnDelta) -> str:
    widths = f"{fmt_width(c.old_width)} → {fmt_width(c.new_width)} per row"
    if c.table is None:
        return f"{c.column} ({widths})"
    nulls = ""
    if c.old_null_fraction is not None and c.new_null_fraction is not None:
        nulls = (
            f"; NULL fraction {fmt_fraction(c.old_null_fraction)} → "
            f"{fmt_fraction(c.new_null_fraction)}"
        )
    return f"`{c.column}` ({widths}{nulls})"


def _ratio_sentence(x: ExplainReport) -> str:
    d, level = x.decomposition, x.probe.level
    c, cf, e = factor(d, "ratio"), factor(d, "data"), factor(d, "compressor")
    return (
        f"Compression ratio {fmt_ratio(c.old)} → {fmt_ratio(c.new)} ({fmt_change(c.change)}): "
        f"deflated at a fixed level {level}, the data alone goes {fmt_ratio(cf.old)} → "
        f"{fmt_ratio(cf.new)} ({fmt_change(cf.change)}), and the original compressor's "
        f"efficiency against that level changes {fmt_change(e.change)}."
    )


def _container(p: FileProfile) -> str:
    return f"{p.compressor}, level hint {p.level_hint or 'none'}"


def _probe_sentence(x: ExplainReport) -> str:
    p = x.probe
    if p.old_ratio is None or p.new_ratio is None or p.probe_change is None:
        return "Re-compress probe: no decompressed bytes to sample."
    head = (
        f"Re-compress probe ({fmt_mib(p.sample_bytes)} from each stream, deflate level "
        f"{p.level}): {fmt_ratio(p.old_ratio)} vs {fmt_ratio(p.new_ratio)} "
        f"({fmt_change(p.probe_change)})"
    )
    if p.data_share is None:
        return (
            f"{head}; the files' own compression ratio changed only "
            f"{fmt_change(p.observed_change)} (under {fmt_fraction(p.ratio_unchanged)}), "
            "so there is no compressor effect to attribute."
        )
    share = f"{head}, i.e. {fmt_fraction(p.data_share)} of the files' ratio change"
    old, new = _container(x.old), _container(x.new)
    if p.hypothesis == "H1":
        return (
            f"{share}: the gap disappears at an equal level, so the compressor or its level "
            f"changed (H1): {old} → {new}."
        )
    if p.hypothesis == "H2/H3":
        return (
            f"{share}: the gap persists at an equal level, so the data itself changed "
            f"(H2 narrower rows / H3 more repetitive data), not the compressor ({old} → "
            f"{new})."
        )
    return f"{share}: both the data and the compressor settings contribute ({old} → {new})."


def _net_sentence(d: Decomposition) -> str:
    s = {f.name: fmt_change(f.size_effect or 0.0) for f in d.factors if f.effect_ln is not None}
    return (
        f"Net compressed size {fmt_change(d.observed_change)}; waterfall: rows {s['rows']}, "
        f"row width {s['width']}, data compressibility {s['data']}, compressor "
        f"{s['compressor']}, which multiply back to {fmt_change(d.product - 1)}."
    )


def _side(name: str, ref: IntegrityRef) -> str:
    if ref.status != "found":
        return f"{name} export not verified (verify report: {ref.status})"
    return f"{name} export {ref.verdict}, RAL {ref.ral}"


CAUSE = {
    "H1": "the compressor settings",
    "H2/H3": "data shape",
    "mixed": "data shape and compressor settings",
    "none": "the row count and width",
}


def _integrity_sentence(x: ExplainReport) -> str:
    old, new = x.integrity_old, x.integrity_new
    failed = [(n, r) for n, r in (("new", new), ("old", old)) if r.failed_layers]
    if failed:
        parts = "; ".join(
            f"the {n} export is {r.verdict}, failing " + ", ".join(f"L{i}" for i in r.failed_layers)
            for n, r in failed
        )
        return (
            f"Integrity: {parts}. The size change may include data loss (H5): do not "
            "attribute it to data shape alone."
        )
    if new.status != "found":
        return (
            f"Integrity: {_side('new', new)}, so data loss (H5) is not ruled out; run "
            "`eguard verify` on it before relying on this explanation."
        )
    gaps = sorted(set(old.incomplete_layers) | set(new.incomplete_layers))
    caveat = ""
    if gaps:
        caveat = "; " + ", ".join(f"L{i}" for i in gaps) + " without full evidence"
    return (
        f"Integrity: no integrity layer failed ({_side('old', old)}; {_side('new', new)}"
        f"{caveat}), so nothing points to data loss (H5): the size change is explained by "
        f"{CAUSE[x.hypothesis]}."
    )


def narrative(x: ExplainReport) -> list[str]:
    return [
        _rows_sentence(x.decomposition),
        _width_sentence(x),
        _ratio_sentence(x),
        _probe_sentence(x),
        _net_sentence(x.decomposition),
        _integrity_sentence(x),
    ]


# -- entry point ------------------------------------------------------------------------------


def explain_files(
    old: Path, new: Path, policy: dict[str, Any], reports: Path | None
) -> ExplainReport:
    ex = policy["explain"]
    p_old, s_old = profile_file(old, policy)
    p_new, s_new = profile_file(new, policy)
    d = decompose(p_old, p_new, ex["identity_tolerance"])
    pr = probe(s_old, s_new, factor(d, "ratio").change, ex)
    x = ExplainReport(
        tool=f"eguard {__version__}",
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        old=p_old,
        new=p_new,
        decomposition=d,
        probe=pr,
        hypothesis=pr.hypothesis,
        columns=column_deltas(p_old, p_new, d),
        integrity_old=find_verify_report(old, p_old, reports),
        integrity_new=find_verify_report(new, p_new, reports),
        narrative=[],
    )
    x.narrative = narrative(x)
    return x
