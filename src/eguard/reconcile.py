"""L4 reconciliation (IMPLEMENTATION_PLAN §4): the export's fingerprints vs a signed manifest.

The signature is checked before the pass; an untrusted manifest is never compared against (its
checks are SKIP and the signature FAIL makes the verdict CORRUPT). A trusted manifest is compared
table by table (count, sum, xor) and chunk by chunk, so a mismatch is localised to a row range.
"""

from collections import Counter
from typing import Any

from eguard.manifest import signature_ok
from eguard.models import (
    CheckResult,
    Manifest,
    Severity,
    Status,
    StreamDigestInfo,
    TableFingerprint,
)

LAYER = 4
RECONCILE_CHECKS = ("l4_tables", "l4_row_counts", "l4_fingerprint", "l4_stream_digest")
Pair = tuple[str, TableFingerprint | None, TableFingerprint | None]


def _check(
    name: str, status: Status, evidence: dict[str, Any], message: str, *, critical: bool = True
) -> CheckResult:
    return CheckResult(
        layer=LAYER,
        name=name,
        status=status,
        severity=Severity.CRITICAL if critical else Severity.MAJOR,
        evidence=evidence,
        message=message,
    )


def no_manifest() -> CheckResult:
    return CheckResult(
        layer=LAYER,
        name="l4_manifest",
        status=Status.SKIP,
        severity=Severity.INFO,
        evidence={},
        message="no manifest given: L4 cannot reconcile (pass --manifest; forensic mode against "
        "source counts comes with the hardened export)",
    )


def check_signature(loaded: Manifest | str, key: bytes) -> CheckResult:
    name = "l4_manifest_signature"
    if isinstance(loaded, str):
        return _check(name, Status.FAIL, {"error": loaded}, f"manifest unreadable: {loaded}")
    evidence = {
        "tool": loaded.tool,
        "created_at": loaded.created_at,
        "chunk_rows": loaded.chunk_rows,
        "tables": len(loaded.tables),
        "signed": loaded.signature is not None,
    }
    if loaded.signature is None:
        return _check(name, Status.FAIL, evidence, "manifest is unsigned: it cannot be trusted")
    if not signature_ok(loaded, key):
        return _check(
            name,
            Status.FAIL,
            evidence,
            "manifest signature invalid: altered after signing, or signed with another key; "
            "the export is not reconciled against an untrusted manifest",
        )
    return _check(name, Status.PASS, evidence, f"manifest signature valid ({loaded.tool})")


def untrusted() -> list[CheckResult]:
    return [
        CheckResult(
            layer=LAYER,
            name=name,
            status=Status.SKIP,
            severity=Severity.INFO,
            evidence={},
            message="skipped: manifest untrusted",
        )
        for name in RECONCILE_CHECKS
    ]


def _keyed(tables: list[TableFingerprint]) -> dict[str, TableFingerprint]:
    """`table`, or `table#2` for a second COPY block of the same table."""
    seen: Counter[str] = Counter()
    out: dict[str, TableFingerprint] = {}
    for t in tables:
        seen[t.table] += 1
        out[t.table if seen[t.table] == 1 else f"{t.table}#{seen[t.table]}"] = t
    return out


def _pairs(m: Manifest, tables: list[TableFingerprint]) -> list[Pair]:
    want, got = _keyed(m.tables), _keyed(tables)
    return [(k, want.get(k), got.get(k)) for k in [*want, *(k for k in got if k not in want)]]


def check_tables(m: Manifest, tables: list[TableFingerprint]) -> CheckResult:
    expected, seen = [t.table for t in m.tables], [t.table for t in tables]
    missing = sorted((Counter(expected) - Counter(seen)).elements())
    extra = sorted((Counter(seen) - Counter(expected)).elements())
    problems = []
    if missing:
        problems.append(f"missing from the export: {', '.join(missing)}")
    if extra:
        problems.append(f"not in the manifest: {', '.join(extra)}")
    if not missing and not extra and expected != seen:
        problems.append("COPY blocks are in a different order")
    if not m.dump_complete:
        problems.append("manifest records an incomplete dump: the exporter's own stream was cut")
    evidence = {
        "manifest_tables": expected,
        "export_tables": seen,
        "missing": missing,
        "extra": extra,
        "manifest_dump_complete": m.dump_complete,
    }
    if problems:
        return _check("l4_tables", Status.FAIL, evidence, "; ".join(problems))
    return _check("l4_tables", Status.PASS, evidence, f"{len(seen)} COPY block(s) match manifest")


def check_row_counts(m: Manifest, tables: list[TableFingerprint]) -> CheckResult:
    counts = {}
    for label, a, b in _pairs(m, tables):
        want, got = (a.count if a else 0), (b.count if b else 0)
        counts[label] = {"manifest": want, "stream": got, "delta": got - want}
    bad = {k: v for k, v in counts.items() if v["delta"]}
    if bad:
        detail = "; ".join(f"{k}: {v['stream']:,} vs {v['manifest']:,}" for k, v in bad.items())
        return _check("l4_row_counts", Status.FAIL, {"tables": counts}, f"row counts {detail}")
    total = sum(v["stream"] for v in counts.values())
    return _check(
        "l4_row_counts", Status.PASS, {"tables": counts}, f"{total:,} rows, exactly as manifest"
    )


def _summary(t: TableFingerprint | None) -> dict[str, Any] | None:
    return None if t is None else t.model_dump(include={"count", "sum64", "xor64", "root"})


def _damaged(label: str, a: TableFingerprint, b: TableFingerprint | None) -> list[dict[str, Any]]:
    """Manifest chunks whose digest the export does not reproduce (rows from the manifest, lines
    from the export when it has that chunk)."""
    theirs = b.chunks if b else []
    out = []
    for i, ca in enumerate(a.chunks):
        cb = theirs[i] if i < len(theirs) else None
        if cb is None or cb.digest != ca.digest:
            src = cb or ca
            out.append(
                {
                    "table": label,
                    "chunk": ca.index,
                    "of": len(a.chunks),
                    "rows": [ca.first_row, ca.last_row],
                    "lines": [src.first_line, src.last_line],
                }
            )
    return out


def _table_status(a: TableFingerprint | None, b: TableFingerprint | None) -> str:
    if a is None or b is None:
        return "absent"
    if (a.count, a.sum64, a.xor64) != (b.count, b.sum64, b.xor64):
        return "differs"
    return "match" if a.root == b.root else "reordered"


def _damage_message(label: str, a: TableFingerprint, b: TableFingerprint | None, d: list) -> str:
    if not d:
        return f"{label}: rows beyond the manifest's {a.count:,}"
    first = d[0]
    msg = (
        f"{label}: content differs from the manifest; first damaged chunk {first['chunk']} of "
        f"{first['of']}: rows {first['rows'][0]:,}–{first['rows'][1]:,} (dump lines "
        f"{first['lines'][0]:,}–{first['lines'][1]:,}); {len(d)} of {first['of']} chunk(s) differ"
    )
    if b is None or b.count != a.count:
        msg += " (row count differs, so chunks after the first damaged one are shifted)"
    return msg


def check_fingerprint(
    m: Manifest, tables: list[TableFingerprint], max_examples: int
) -> CheckResult:
    per_table: dict[str, Any] = {}
    damaged: list[dict[str, Any]] = []
    messages: list[str] = []
    for label, a, b in _pairs(m, tables):
        status = _table_status(a, b)
        per_table[label] = {"status": status, "manifest": _summary(a), "export": _summary(b)}
        if status in ("differs", "absent") and a is not None:
            d = _damaged(label, a, b)
            damaged += d
            messages.append(_damage_message(label, a, b, d))
        elif status == "absent":
            messages.append(f"{label}: not in the manifest")
    evidence = {
        "tables": per_table,
        "damaged_count": len(damaged),
        "first_damaged": damaged[0] if damaged else None,
        "damaged_chunks": damaged[:max_examples],
    }
    if messages:
        return _check("l4_fingerprint", Status.FAIL, evidence, "; ".join(messages))
    if any(v["status"] == "reordered" for v in per_table.values()):
        msg = "same rows as the manifest, but in a different order"
        return _check("l4_fingerprint", Status.WARN, evidence, msg, critical=False)
    return _check(
        "l4_fingerprint", Status.PASS, evidence, "every table and chunk fingerprint matches"
    )


def check_stream_digest(m: Manifest, info: StreamDigestInfo, rows_match: bool) -> CheckResult:
    evidence = {"manifest": m.stream.model_dump(), "export": info.model_dump()}
    if info == m.stream:
        return _check(
            "l4_stream_digest", Status.PASS, evidence, "decompressed stream sha256 matches"
        )
    where = (
        "row data matches, so the difference is outside the rows (DDL, comments, markers)"
        if rows_match
        else "see l4_fingerprint for the damaged rows"
    )
    size = (
        f"same length, {info.bytes:,} bytes, different sha256"
        if info.bytes == m.stream.bytes
        else f"{info.bytes:,} bytes vs {m.stream.bytes:,} in the manifest"
    )
    return _check(
        "l4_stream_digest",
        Status.FAIL,
        evidence,
        f"decompressed stream differs from the manifest ({size}); {where}",
    )


def check_reconcile(
    m: Manifest, tables: list[TableFingerprint], info: StreamDigestInfo, max_examples: int
) -> list[CheckResult]:
    """The checks after a valid signature (see check_signature)."""
    fp = check_fingerprint(m, tables, max_examples)
    return [
        check_tables(m, tables),
        check_row_counts(m, tables),
        fp,
        check_stream_digest(m, info, rows_match=fp.status != Status.FAIL),
    ]
