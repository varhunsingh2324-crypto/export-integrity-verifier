"""L1 container integrity: turn what the decoder recorded (ContainerInfo) into checks."""

from datetime import UTC, datetime
from typing import Any

from eguard.models import CheckResult, ContainerInfo, GzipMember, Severity, Status

LAYER = 1
MEMBERS_SHOWN = 10  # per-member evidence kept in the report; the count is always complete
HEADER_ERRORS = {"bad_magic", "bad_method", "reserved_flags", "header_crc", "bad_maxbits"}
STREAM_ERRORS = {"unexpected_eof", "inflate_error", "decoder_failed"}
NO_CHECKSUM = "container has no checksum — L1 cannot vouch for content; higher layers required"

GZIP_OS = {
    0: "FAT",
    1: "Amiga",
    2: "VMS",
    3: "Unix",
    4: "VM/CMS",
    5: "Atari TOS",
    6: "HPFS",
    7: "Macintosh",
    8: "Z-System",
    9: "CP/M",
    10: "TOPS-20",
    11: "NTFS",
    12: "QDOS",
    13: "Acorn RISCOS",
    255: "unknown",
}


def level_hint(xfl: int) -> str:
    """RFC 1952 XFL: 2 = maximum compression (slowest), 4 = fastest; else unspecified."""
    return {2: "max (-9)", 4: "fastest (-1)"}.get(xfl, "default/unspecified")


def _mtime(mtime: int) -> str | None:
    return datetime.fromtimestamp(mtime, UTC).isoformat() if mtime else None


def _check(
    name: str, status: Status, severity: Severity, evidence: dict[str, Any], message: str
) -> CheckResult:
    return CheckResult(
        layer=LAYER, name=name, status=status, severity=severity, evidence=evidence, message=message
    )


def summary(info: ContainerInfo) -> dict[str, Any]:
    first = info.members[0] if info.members else None
    ratio = info.bytes_out / info.compressed_bytes if info.compressed_bytes else None
    if info.format == "gzip":
        compressor = "gzip"
        hint = level_hint(first.xfl) if first else None
    elif info.format == "compress":
        compressor, hint = "compress (LZW)", f"max bits {info.compress_maxbits}"
    else:
        compressor, hint = "unknown", None
    return {
        "compressor": compressor,
        "level_hint": hint,
        "members": len(info.members),
        "compressed_bytes": info.compressed_bytes,
        "uncompressed_bytes": info.bytes_out,
        "ratio": round(ratio, 4) if ratio else None,
        "header_mtime": _mtime(first.mtime) if first else None,
    }


def _member_evidence(m: GzipMember) -> dict[str, Any]:
    return {
        "offset": m.offset,
        "mtime": _mtime(m.mtime),
        "xfl": m.xfl,
        "level_hint": level_hint(m.xfl),
        "os": GZIP_OS.get(m.os, f"other ({m.os})"),
        "fname": m.fname,
        "comment": m.comment,
        "extra_bytes": m.extra_bytes,
        "header_crc_ok": m.header_crc_ok,
        "crc32_expected": None if m.crc_expected is None else f"0x{m.crc_expected:08x}",
        "crc32_actual": f"0x{m.crc_actual:08x}",
        "isize_expected": m.isize_expected,
        "bytes_out": m.bytes_out,
    }


def check_format(info: ContainerInfo) -> CheckResult:
    evidence = summary(info)
    if info.format == "unknown":
        err = info.error
        evidence["reason"] = err.detail if err else None
        return _check(
            "l1_format",
            Status.FAIL,
            Severity.CRITICAL,
            evidence,
            f"not a gzip or .Z container ({err.detail if err else 'unrecognised'})",
        )
    return _check(
        "l1_format",
        Status.PASS,
        Severity.INFO,
        evidence,
        f"{evidence['compressor']} container, level hint {evidence['level_hint']}",
    )


def check_header(info: ContainerInfo) -> CheckResult:
    evidence: dict[str, Any] = {"members": len(info.members)}
    if info.format == "gzip":
        evidence["member_headers"] = [_member_evidence(m) for m in info.members[:MEMBERS_SHOWN]]
    else:
        evidence |= {"max_bits": info.compress_maxbits, "block_mode": info.compress_block_mode}
    err = info.error
    if err and err.kind in HEADER_ERRORS:
        evidence |= {"error": err.kind, "offset": err.offset}
        return _check(
            "l1_header",
            Status.FAIL,
            Severity.CRITICAL,
            evidence,
            f"invalid header at byte {err.offset}: {err.detail}",
        )
    return _check("l1_header", Status.PASS, Severity.CRITICAL, evidence, "header fields valid")


def check_stream_end(info: ContainerInfo) -> CheckResult:
    evidence: dict[str, Any] = {
        "compressed_bytes": info.compressed_bytes,
        "uncompressed_bytes": info.bytes_out,
        "decoder_exit": info.decoder_exit,
        "decoder_stderr": info.decoder_stderr or None,
    }
    err = info.error
    if err and err.kind in STREAM_ERRORS:
        evidence |= {"error": err.kind, "offset": err.offset, "detail": err.detail}
        pct = 100 * err.offset / info.compressed_bytes if info.compressed_bytes else 0.0
        return _check(
            "l1_stream_end",
            Status.FAIL,
            Severity.CRITICAL,
            evidence,
            f"{err.kind} at compressed byte {err.offset:,} ({pct:.1f} % of file) after "
            f"{info.bytes_out:,} decompressed bytes: {err.detail}",
        )
    if info.decoder_exit == 2:
        return _check(
            "l1_stream_end",
            Status.WARN,
            Severity.MAJOR,
            evidence,
            f"decoder warning: {(info.decoder_stderr or '').strip()}",
        )
    return _check("l1_stream_end", Status.PASS, Severity.CRITICAL, evidence, "stream ends cleanly")


def check_integrity(info: ContainerInfo) -> CheckResult:
    """CRC32 and ISIZE (mod 2**32) of every member whose trailer was reached."""
    checked = [m for m in info.members if m.crc_expected is not None]
    bad = [
        i
        for i, m in enumerate(info.members)
        if m.crc_expected is not None
        and (m.crc_expected != m.crc_actual or m.isize_expected != m.bytes_out & 0xFFFFFFFF)
    ]
    evidence: dict[str, Any] = {
        "members": len(info.members),
        "members_checked": len(checked),
        "bad_members": bad[:MEMBERS_SHOWN],
        "detail": [_member_evidence(info.members[i]) for i in bad[:MEMBERS_SHOWN]],
    }
    if bad:
        m = info.members[bad[0]]
        return _check(
            "l1_integrity",
            Status.FAIL,
            Severity.CRITICAL,
            evidence,
            f"{len(bad)} member(s) fail CRC32/ISIZE; member {bad[0]}: crc32 expected "
            f"0x{m.crc_expected:08x} got 0x{m.crc_actual:08x}, isize expected "
            f"{m.isize_expected} got {m.bytes_out & 0xFFFFFFFF}",
        )
    if not checked or len(checked) < len(info.members):
        return _check(
            "l1_integrity",
            Status.SKIP,
            Severity.CRITICAL,
            evidence,
            f"trailer of {len(info.members) - len(checked)} member(s) never reached; "
            f"{len(checked)} checked OK",
        )
    return _check(
        "l1_integrity",
        Status.PASS,
        Severity.CRITICAL,
        evidence,
        f"CRC32 and ISIZE match for all {len(checked)} member(s)",
    )


def check_trailing(info: ContainerInfo, policy: dict[str, Any]) -> CheckResult:
    evidence = {
        "trailing_bytes": info.trailing_bytes,
        "offset": info.trailing_offset,
        "all_zero": info.trailing_all_zero,
    }
    if not info.trailing_bytes:
        return _check("l1_trailing", Status.PASS, Severity.MAJOR, evidence, "no trailing bytes")
    kind = "zero padding" if info.trailing_all_zero else "non-gzip data"
    return _check(
        "l1_trailing",
        Status(policy["l1"]["trailing_garbage"]),
        Severity.MAJOR,
        evidence,
        f"{info.trailing_bytes:,} bytes of {kind} after the last member at byte "
        f"{info.trailing_offset:,} (ignored by gzip; content before it is CRC-checked)",
    )


def check_container(info: ContainerInfo, policy: dict[str, Any]) -> list[CheckResult]:
    checks = [check_format(info)]
    if info.format == "unknown":
        return checks
    checks += [check_header(info), check_stream_end(info)]
    if info.format == "gzip":
        checks += [check_integrity(info), check_trailing(info, policy)]
    else:
        checks.append(
            _check(
                "l1_checksum",
                Status.WARN,
                Severity.MAJOR,
                {"format": "compress", "checksum": None},
                NO_CHECKSUM,
            )
        )
    return checks
