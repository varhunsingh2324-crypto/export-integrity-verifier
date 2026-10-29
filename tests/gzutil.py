"""Hand-crafted gzip members for tests (RFC 1952), so every header field is under our control."""

import struct
import zlib

FHCRC, FEXTRA, FNAME, FCOMMENT = 0x02, 0x04, 0x08, 0x10


def member(
    data: bytes,
    *,
    mtime: int = 0,
    xfl: int = 0,
    os: int = 3,
    fname: bytes | None = None,
    comment: bytes | None = None,
    extra: bytes | None = None,
    hcrc: bool = False,
    bad_hcrc: bool = False,
    flags_or: int = 0,
    cm: int = 8,
    level: int = 6,
) -> bytes:
    flg = (
        (FEXTRA if extra is not None else 0)
        | (FNAME if fname is not None else 0)
        | (FCOMMENT if comment is not None else 0)
        | (FHCRC if hcrc else 0)
        | flags_or
    )
    header = b"\x1f\x8b" + struct.pack("<BBIBB", cm, flg, mtime, xfl, os)
    if extra is not None:
        header += struct.pack("<H", len(extra)) + extra
    if fname is not None:
        header += fname + b"\0"
    if comment is not None:
        header += comment + b"\0"
    if hcrc:
        header += struct.pack("<H", (zlib.crc32(header) ^ (1 if bad_hcrc else 0)) & 0xFFFF)
    comp = zlib.compressobj(level, zlib.DEFLATED, -zlib.MAX_WBITS)
    body = comp.compress(data) + comp.flush()
    trailer = struct.pack("<II", zlib.crc32(data), len(data) & 0xFFFFFFFF)
    return header + body + trailer


def dump_like(rows: int, seed: int = 7) -> bytes:
    """Deterministic, moderately incompressible text that looks like COPY rows."""
    import random

    rng = random.Random(seed)
    lines = [
        f"{i}\t{rng.randrange(10**6)}\t{rng.getrandbits(128):032x}\t{rng.random():.6f}"
        for i in range(rows)
    ]
    return ("\n".join(lines) + "\n").encode()
