"""Bounded-memory sketches (rule 2): Bloom filter and the PK-candidate key tracker."""

import math
import tempfile
from array import array
from collections import Counter
from typing import Any

MASK64 = (1 << 64) - 1
SPILL_BATCH = 1 << 16  # keys buffered before an append to the spill file


def mix64(x: int) -> int:
    """splitmix64 finaliser: a second, independent hash of an already-uniform 64-bit key."""
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9 & MASK64
    x = (x ^ (x >> 27)) * 0x94D049BB133111EB & MASK64
    return x ^ (x >> 31)


class BloomFilter:
    """Fixed-size Bloom filter over 64-bit keys, double hashing (Kirsch-Mitzenmacher)."""

    def __init__(self, size_bytes: int, hashes: int) -> None:
        self.bits = bytearray(size_bytes)
        self.m = size_bytes * 8
        self.k = hashes
        self.n = 0

    def add(self, key: int) -> bool:
        """Insert `key`; True if it was (probably) present already."""
        h2 = mix64(key) | 1
        bits, m = self.bits, self.m
        present = True
        for i in range(self.k):
            idx = (key + i * h2) % m
            byte, bit = idx >> 3, 1 << (idx & 7)
            if not bits[byte] & bit:
                present = False
                bits[byte] |= bit
        if not present:
            self.n += 1
        return present

    def fp_rate(self) -> float:
        """Estimated false-positive probability at the current fill."""
        return (1 - math.exp(-self.k * self.n / self.m)) ** self.k


class KeyTracker:
    """Uniqueness of one column's 64-bit key hashes, in bounded memory.

    Exact `set` up to `set_limit` keys; then a Bloom filter. From the switch on, every key is also
    appended to an anonymous spill file (8 bytes/key). A Bloom hit is only a *suspect*: `result()`
    scans the spill once and counts a duplicate only for keys stored there twice or more, so Bloom
    false positives never become findings. After `prune_dups` duplicates the tracker stops
    (`pruned`): the count becomes a lower bound and memory is released.
    """

    def __init__(
        self, set_limit: int, bloom_bytes: int, bloom_hashes: int, prune_dups: int, examples: int
    ) -> None:
        self.set_limit = set_limit
        self.bloom_bytes = bloom_bytes
        self.bloom_hashes = bloom_hashes
        self.prune_dups = prune_dups
        self.max_examples = examples
        self.keys = 0
        self.dups = 0  # exact while in set mode; + Bloom suspects after the switch
        self._set_dups = 0
        self.pruned = False
        self.examples: list[dict[str, Any]] = []
        self._seen: set[int] | None = set()
        self._bloom: BloomFilter | None = None
        self._spill: Any = None
        self._buf = array("Q")
        self._suspects: dict[int, list[dict[str, Any]]] = {}
        self._confirmed: int | None = None
        self._fp: float | None = None

    @property
    def mode(self) -> str:
        return "bloom" if self._bloom is not None or self._fp is not None else "set"

    def add(self, key: int, lineno: int, value: str) -> None:
        if self.pruned:
            return
        self.keys += 1
        if self._seen is not None:
            if key in self._seen:
                self.dups += 1
                self._example(key, lineno, value)
            else:
                self._seen.add(key)
                if len(self._seen) > self.set_limit:
                    self._to_bloom()
        else:
            assert self._bloom is not None
            self._buf.append(key)
            if len(self._buf) >= SPILL_BATCH:
                self._flush()
            if self._bloom.add(key):
                self.dups += 1
                self._example(key, lineno, value)
        if self.dups > self.prune_dups:
            self._finish(pruned=True)

    def _example(self, key: int, lineno: int, value: str) -> None:
        if self._bloom is None:
            if len(self.examples) < self.max_examples:
                self.examples.append({"line": lineno, "value": value})
        else:  # every suspect is kept (bounded by prune_dups) for confirmation
            self._suspects.setdefault(key, []).append({"line": lineno, "value": value})

    def _to_bloom(self) -> None:
        assert self._seen is not None
        self._bloom = BloomFilter(self.bloom_bytes, self.bloom_hashes)
        self._spill = tempfile.TemporaryFile(prefix="eguard-pk-")
        self._set_dups = self.dups
        for key in self._seen:
            self._bloom.add(key)
            self._buf.append(key)
            if len(self._buf) >= SPILL_BATCH:
                self._flush()
        self._seen = None

    def _flush(self) -> None:
        self._buf.tofile(self._spill)
        self._buf = array("Q")

    def _confirm(self) -> int:
        """Duplicates among suspects, counted exactly from the spill file."""
        if not self._suspects:
            return 0
        self._flush()
        self._spill.seek(0)
        counts: Counter[int] = Counter()
        wanted = self._suspects.keys()
        while chunk := self._spill.read(8 * SPILL_BATCH):
            keys = array("Q")
            keys.frombytes(chunk)
            counts.update(k for k in keys if k in wanted)
        confirmed = 0
        for key, seen in self._suspects.items():
            if counts[key] >= 2:
                confirmed += counts[key] - 1
                room = self.max_examples - len(self.examples)
                self.examples += seen[: max(0, room)]
        return confirmed

    def _finish(self, pruned: bool) -> None:
        if self._confirmed is not None:
            return
        if self._bloom is not None:
            self._fp = self._bloom.fp_rate()
            self._confirmed = self._set_dups + self._confirm()
            self._spill.close()
        else:
            self._confirmed = self.dups
        self.pruned = pruned
        self._seen, self._bloom, self._spill, self._buf = None, None, None, array("Q")

    def close(self) -> None:
        """Release memory and the spill file without the confirmation scan."""
        if self._spill is not None:
            self._spill.close()
        self._seen, self._bloom, self._spill = None, None, None

    def result(self) -> dict[str, Any]:
        mode = self.mode
        suspects = self.dups - self._set_dups
        self._finish(pruned=self.pruned)
        return {
            "mode": mode,
            "keys": self.keys,
            "duplicates": self._confirmed,
            "lower_bound": self.pruned,
            "bloom_suspects": suspects if mode == "bloom" else None,
            "bloom_fp_rate": self._fp,
            "examples": self.examples[: self.max_examples],
        }
