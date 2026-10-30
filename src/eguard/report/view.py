"""VerifyReport -> what the HTML report shows. Pure functions over the checks' evidence only: never
the file name or path (rule 9), and no number that is not in the evidence (rule 5)."""

from typing import Any

from eguard.models import CheckResult, Location, Provenance, Status, Verdict, VerifyReport

MAX_VALUE_CHARS = 80  # dump text quoted in a location (it is untrusted and can be long)


def check(r: VerifyReport, name: str) -> CheckResult | None:
    return next((c for c in r.checks if c.name == name), None)


def _clip(value: Any) -> str:
    text = str(value)
    return text if len(text) <= MAX_VALUE_CHARS else text[:MAX_VALUE_CHARS] + "…"


def _l1(c: CheckResult) -> list[Location]:
    ev = c.evidence
    if c.name == "l1_stream_end" and "offset" in ev:
        detail = f"{ev.get('detail')} ({ev.get('error')})"
        return [Location(layer=1, check=c.name, byte_offset=ev["offset"], detail=detail)]
    if c.name == "l1_integrity":
        return [
            Location(
                layer=1,
                check=c.name,
                detail=f"gzip member starting at compressed byte {m['offset']:,}: CRC32 "
                f"{m['crc32_actual']} computed, {m['crc32_expected']} in its trailer (the damage "
                "is inside this member; row-level checks narrow it down)",
            )
            for m in ev.get("detail", [])
        ]
    return []


def _l2(c: CheckResult) -> list[Location]:
    ev = c.evidence
    if c.name != "l2_complete":
        return []
    oc = ev.get("open_copy")
    if not oc:
        return [Location(layer=2, check=c.name, lines=(ev["lines"], ev["lines"]), detail=c.message)]
    detail = f"stream ends after row {oc['rows']:,} of this table (last complete row)"
    if ev.get("partial_line_bytes"):
        detail += f", then a partial row of {ev['partial_line_bytes']:,} bytes"
    last = oc["last_row_line"] or oc["header_line"]
    return [
        Location(
            layer=2,
            check=c.name,
            table=oc["table"],
            rows=(oc["rows"], oc["rows"]),
            lines=(last, last),
            detail=detail,
        )
    ]


def _l3(c: CheckResult) -> list[Location]:
    ev = c.evidence
    if c.name == "l3_row_validity":
        return [
            Location(
                layer=3,
                check=c.name,
                table=e.get("table"),
                lines=(e["line"], e["line"]),
                detail=f"{e.get('column')}: {e.get('reason')} ({_clip(e.get('value'))!r})",
            )
            for e in ev.get("examples", [])
        ]
    out = []
    for table, t in ev.get("tables", {}).items():
        if t.get("status") != "FAIL":
            continue
        key = ", ".join(t.get("pk", []))
        out += [
            Location(
                layer=3,
                check=c.name,
                table=table,
                lines=(e["line"], e["line"]),
                detail=f"duplicate {key} = {_clip(e['value'])}",
            )
            for e in t.get("examples", [])
        ]
    return out


def _l4(c: CheckResult) -> list[Location]:
    ev = c.evidence
    if c.name == "l4_fingerprint":
        return [
            Location(
                layer=4,
                check=c.name,
                table=d["table"],
                chunk=(d["chunk"], d["of"]),
                rows=tuple(d["rows"]),
                lines=tuple(d["lines"]),
                detail="row content differs from the manifest in this chunk",
            )
            for d in ev.get("damaged_chunks", [])
        ]
    if c.name not in ("l4_row_counts", "l4_snapshot_counts"):
        return []
    other = "manifest" if c.name == "l4_row_counts" else "snapshot"
    found = "stream" if c.name == "l4_row_counts" else "export"
    return [
        Location(
            layer=4,
            check=c.name,
            table=table,
            detail=f"{t[found]:,} rows in the export vs {t[other]:,} in the {other}",
        )
        for table, t in ev.get("tables", {}).items()
        if t.get(found) != t.get(other)
    ]


def _l5(c: CheckResult) -> list[Location]:
    key = {"l5_restore": "rejected", "l5_round_trip": "mismatched"}.get(c.name)
    if key is None:
        return []
    return [
        Location(
            layer=5,
            check=c.name,
            table=t["table"],
            lines=(e["line"], e["line"]),
            detail=_clip(e.get("error") or f"columns differ: {e.get('columns')}"),
        )
        for t in c.evidence.get("tables", [])
        for e in t.get(key, [])
    ]


_BY_LAYER = {1: _l1, 2: _l2, 3: _l3, 4: _l4, 5: _l5}


def locations(r: VerifyReport) -> list[Location]:
    """Where in the stream each non-PASS check found its problem, in layer order."""
    failed = sorted((c for c in r.checks if c.status != Status.PASS), key=lambda c: c.layer)
    return [loc for c in failed for loc in _BY_LAYER[c.layer](c)]


def _span(label: str, span: tuple[int, int] | None) -> str | None:
    if span is None:
        return None
    a, b = span
    return f"{label} {a:,}" if a == b else f"{label}s {a:,}–{b:,}"


def where(loc: Location) -> str:
    """One phrase: table, chunk k of n, rows, lines, byte offset (whatever is known)."""
    parts = [
        loc.table,
        f"chunk {loc.chunk[0]} of {loc.chunk[1]}" if loc.chunk else None,
        _span("row", loc.rows),
        _span("dump line", loc.lines),
        f"compressed byte {loc.byte_offset:,}" if loc.byte_offset is not None else None,
    ]
    return ", ".join(p for p in parts if p) or "whole file"


def _ev(c: CheckResult | None, key: str) -> Any:
    return c.evidence.get(key) if c else None


def provenance(r: VerifyReport) -> Provenance:
    fmt, hdr = check(r, "l1_format"), check(r, "l2_header")
    snap, sig = check(r, "l4_snapshot_counts"), check(r, "l4_manifest_signature")
    csha, sample = check(r, "l4_compressed_sha256"), check(r, "l5_sample")
    if sig is None:
        status = "no manifest" if check(r, "l4_manifest") else "not checked"
    elif sig.status == Status.PASS:
        status = "signed, HMAC-SHA256 signature valid"
    else:
        status = f"untrusted: {sig.message}"
    return Provenance(
        compressor=_ev(fmt, "compressor"),
        level_hint=_ev(fmt, "level_hint"),
        manifest_compressor=(_ev(csha, "manifest") or {}).get("compressor"),
        pg_dump=_ev(hdr, "dumped_by"),
        dumped_from=_ev(hdr, "dumped_from"),
        snapshot_id=_ev(snap, "snapshot_id"),
        snapshot_taken_at=_ev(snap, "taken_at"),
        manifest=r.manifest,
        manifest_status=status,
        manifest_created_at=_ev(sig, "created_at"),
        l5_seed=_ev(sample, "seed"),
        tool=r.tool,
    )


def confidence(r: VerifyReport) -> list[str]:
    """The L5 confidence statement(s), else why the drill gives none."""
    rt = check(r, "l5_round_trip")
    if rt is not None and rt.evidence.get("confidence_statements"):
        return list(rt.evidence["confidence_statements"])
    l5 = [c for c in r.checks if c.layer == 5 and c.status != Status.PASS]
    if not l5:
        return ["No restore drill ran, so no confidence statement can be made."]
    return [f"No confidence statement: L5 {c.name} {c.status}: {c.message}" for c in l5]


def _plural(n: int, word: str) -> str:
    return f"{n:,} {word}" if n == 1 else f"{n:,} {word}s"


def _rows_checked(r: VerifyReport) -> tuple[int, int] | None:
    tables = check(r, "l2_tables")
    per = tables.evidence.get("per_table", {}) if tables else {}
    return (sum(t["rows"] for t in per.values()), len(per)) if per else None


def _verified(r: VerifyReport) -> list[str]:
    out = [
        "This export is complete and restorable: all five verification layers passed with "
        f"full evidence (RAL {r.ral} of 5)."
    ]
    if counted := _rows_checked(r):
        snap = check(r, "l4_snapshot_counts")
        anchor = " and the row counts the database itself reported when the export started"
        out.append(
            f"All {counted[0]:,} rows in {_plural(counted[1], 'table')} were checked one by one "
            f"and match the signed manifest{anchor if snap and snap.status == Status.PASS else ''}."
        )
    rt = check(r, "l5_round_trip")
    if rt is not None:
        n = sum(t.get("round_tripped", 0) for t in rt.evidence.get("tables", []))
        out.append(
            f"A test restore of {n:,} sampled rows into a throwaway schema succeeded and every "
            "row came back identical."
        )
    return out[:3]


def _corrupt(r: VerifyReport) -> list[str]:
    n = len(r.reasons)
    out = [
        f"Do not rely on this export for recovery: {n} critical check(s) failed (RAL {r.ral} of 5)."
    ]
    failed = {c.name for c in r.checks if c.status == Status.FAIL}
    if locs := [loc for loc in locations(r) if loc.check in failed]:
        first = next((loc for loc in locs if loc.table), locs[0])  # the most specific one
        out.append(f"The first problem found is at {where(first)}: {first.detail}.")
    elif r.reasons:
        out.append(f"The first problem found: {r.reasons[0].rstrip('.')}.")
    out.append(
        "Produce a new export, verify it before relying on it, and keep any older verified "
        "backup until then."
    )
    return out


def _next_step(r: VerifyReport) -> str:
    if check(r, "l4_manifest"):
        return (
            "To close the gap, export with `eguard export` (signed manifest) and verify with "
            "--manifest."
        )
    l5 = [c for c in r.checks if c.layer == 5]
    if any(c.status == Status.SKIP for c in l5) or not l5:
        return "To close the gap, verify again with a scratch database (SCRATCH_DSN) for the drill."
    return "The layer table below lists exactly what is missing."


def _suspect(r: VerifyReport) -> list[str]:
    weak = [f"L{lr.layer} {lr.name}" for lr in r.layers if not lr.full_evidence]
    failed = any(c.status == Status.FAIL for c in r.checks)
    found = "No critical check failed" if failed else "No check found damage"
    out = [
        f"{found}, but this export cannot be fully vouched for: {', '.join(weak)} "
        f"{'lacks' if len(weak) == 1 else 'lack'} full evidence (RAL {r.ral} of 5)."
    ]
    if r.reasons:
        out.append(f"Main gap: {r.reasons[0].split(';')[0].rstrip('.')}.")
    out.append(_next_step(r))
    return out


def summary(r: VerifyReport) -> list[str]:
    """2-3 plain-English sentences for management."""
    if r.verdict == Verdict.VERIFIED:
        return _verified(r)
    if r.verdict == Verdict.CORRUPT:
        return _corrupt(r)
    if r.verdict == Verdict.SUSPECT:
        return _suspect(r)
    return [f"The verification could not complete ({r.verdict}).", *r.reasons[:1]]
