"""L5 sample (IMPLEMENTATION_PLAN §4): reservoir-sample raw COPY lines in the same streaming pass.

    n = ceil(ln(alpha) / ln(1 - p))      alpha = 1 - confidence

If a fraction >= p of rows is unrestorable, a uniform sample of n rows contains at least one of them
with probability >= 1 - alpha (sampling without replacement only raises it). Defaults p = 0.1 %,
95 % -> n = 2995.

Algorithm L (Li 1994), one reservoir per COPY block: after the reservoir is full, the next
replacement position is drawn directly, so the per-row cost is a counter compare. Memory is n raw
lines per block.
"""

import math
import random
from dataclasses import dataclass
from typing import Any

from eguard.models import CheckResult, CopyBlock, DumpStructure, Severity, Status, TableDef

LAYER = 5


def sample_size(p: float, confidence: float) -> int:
    if not 0 < p < 1 or not 0 < confidence < 1:
        raise ValueError(
            f"need 0 < p < 1 and 0 < confidence < 1, got p={p}, confidence={confidence}"
        )
    return math.ceil(math.log(1 - confidence) / math.log1p(-p))


def detection_probability(p: float, k: int) -> float:
    """P(a uniform sample of k rows holds >= 1 bad row) when a fraction p of rows is bad."""
    return 1 - (1 - p) ** k


def pct(x: float) -> str:
    return f"{x * 100:g}%"


def confidence_statement(p: float, confidence: float, table: str, k: int, seen: int) -> str:
    if k >= seen:
        return (
            f"All {seen:,} rows of {table} were restored and compared (exhaustive): no row "
            "was left out of the drill."
        )
    return (
        f"If ≥{pct(p)} of rows were unrestorable, this drill would have caught it with "
        f"{pct(confidence)} probability ({k:,} of {seen:,} rows of {table} restored)."
    )


class Reservoir:
    """Uniform sample of k items from a stream of unknown length (Algorithm L)."""

    __slots__ = ("k", "items", "seen", "_rng", "_w", "_next")

    def __init__(self, k: int, rng: random.Random) -> None:
        if k < 1:
            raise ValueError("k must be >= 1")
        self.k = k
        self.items: list[tuple[int, bytes]] = []
        self.seen = 0
        self._rng = rng
        self._w = 1.0
        self._next: float = math.inf

    def add(self, lineno: int, line: bytes) -> None:
        self.seen += 1
        if self.seen <= self.k:
            self.items.append((lineno, line))
            if self.seen == self.k:
                self._advance()
        elif self.seen == self._next:
            self.items[self._rng.randrange(self.k)] = (lineno, line)
            self._advance()

    def _u(self) -> float:
        while (u := self._rng.random()) == 0.0:
            pass
        return u

    def _advance(self) -> None:
        self._w *= math.exp(math.log(self._u()) / self.k)
        d = math.log1p(-self._w)
        skip = math.inf if d == 0 else math.floor(math.log(self._u()) / d)
        self._next = self.seen + skip + 1


@dataclass
class TableSample:
    block: CopyBlock
    table: TableDef | None
    reservoir: Reservoir  # table is the parser's TableDef: its primary_key fills in post-data

    @property
    def rows(self) -> list[tuple[int, bytes]]:
        """Sampled (dump line number, raw COPY line), in stream order."""
        return sorted(self.reservoir.items)

    @property
    def seen(self) -> int:
        return self.reservoir.seen


class ReservoirSampler:
    """Parser listener (parsers.pg_plain.DumpListener): one reservoir per COPY block."""

    def __init__(self, n: int, seed: int) -> None:
        self.n = n
        self.seed = seed
        self._rng = random.Random(seed)
        self.samples: list[TableSample] = []
        self._cur: Reservoir | None = None

    def on_copy_start(self, block: CopyBlock, table: TableDef | None) -> None:
        self._cur = Reservoir(self.n, self._rng)
        self.samples.append(TableSample(block, table, self._cur))

    def on_row(self, block: CopyBlock, line: bytes, lineno: int) -> None:
        assert self._cur is not None
        self._cur.add(lineno, line)

    def on_copy_end(self, block: CopyBlock) -> None:
        self._cur = None

    def on_finish(self, structure: DumpStructure) -> None:
        self._cur = None


def check_sample(sampler: ReservoirSampler, p: float, confidence: float) -> CheckResult:
    tables: list[dict[str, Any]] = [
        {
            "table": s.block.table,
            "seen": s.seen,
            "sampled": len(s.reservoir.items),
            "exhaustive": s.seen <= sampler.n,
        }
        for s in sampler.samples
    ]
    evidence = {
        "detect_fraction": p,
        "confidence": confidence,
        "n": sampler.n,
        "formula": "n = ceil(ln(1 - confidence) / ln(1 - detect_fraction))",
        "seed": sampler.seed,
        "algorithm": "reservoir sampling, Algorithm L, one reservoir per COPY block",
        "tables": tables,
    }
    if not tables:
        return CheckResult(
            layer=LAYER,
            name="l5_sample",
            status=Status.SKIP,
            severity=Severity.INFO,
            evidence=evidence,
            message="no COPY block in the stream: nothing to sample",
        )
    parts = ", ".join(f"{t['sampled']:,} of {t['seen']:,} rows of {t['table']}" for t in tables)
    return CheckResult(
        layer=LAYER,
        name="l5_sample",
        status=Status.PASS,
        severity=Severity.INFO,
        evidence=evidence,
        message=f"reservoir sample (n = ⌈ln {1 - confidence:g} / ln {1 - p:g}⌉ = {sampler.n:,}, "
        f"seed {sampler.seed}): {parts}",
    )
