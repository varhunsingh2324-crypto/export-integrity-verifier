"""`eguard verify`: one streaming pass over the export; every layer subscribes to that stream."""

import secrets
from pathlib import Path
from typing import Any

from eguard.container import check_container
from eguard.fingerprint import Fingerprinter, StreamDigest
from eguard.l5 import l5_checks
from eguard.manifest import ManifestError, check_compatible, file_sha256, load
from eguard.models import CheckResult, Manifest, Status, StreamEnd, VerifyReport
from eguard.parsers.pg_plain import PgPlainParser
from eguard.reconcile import check_reconcile, check_signature, no_manifest, untrusted
from eguard.rows import RowValidator, check_rows
from eguard.sampler import ReservoirSampler, sample_size
from eguard.stream import Consumer, FanOut, open_decoder
from eguard.structure import check_structure
from eguard.verdict import build_report


class StreamStats(Consumer):
    """Counts decompressed lines; also keeps the line fan-out path exercised end to end."""

    def __init__(self) -> None:
        self.end: StreamEnd | None = None

    def on_line(self, line: bytes, lineno: int) -> None:
        pass

    def on_end(self, end: StreamEnd) -> None:
        self.end = end


def _trusted_manifest(
    manifest: Path | None, key: bytes | None
) -> tuple[Manifest | None, list[CheckResult]]:
    """Load and authenticate the manifest before the pass: (trusted manifest or None, L4 checks so
    far). A manifest that fails its signature is never compared against."""
    if manifest is None:
        return None, [no_manifest()]
    if key is None:
        raise ManifestError("a manifest was given but no HMAC key (MANIFEST_HMAC_KEY)")
    loaded = load(manifest)
    sig = check_signature(loaded, key)
    if sig.status != Status.PASS:
        return None, [sig, *untrusted()]
    assert isinstance(loaded, Manifest)
    check_compatible(loaded)
    return loaded, [sig]


def verify_file(
    path: Path,
    policy: dict[str, Any],
    manifest: Path | None = None,
    key: bytes | None = None,
    *,
    scratch_dsn: str | None = None,
    source_dsn: str | None = None,
    seed: int | None = None,
) -> VerifyReport:
    """`seed` None draws a fresh one (recorded in l5_sample): a fixed default would let a crafted
    dump keep its bad rows out of a predictable sample."""
    trusted, l4 = _trusted_manifest(manifest, key)
    decoder = open_decoder(path, policy["stream"]["chunk_bytes"])
    fan = FanOut(policy["stream"]["max_line_bytes"])
    fan.subscribe(StreamStats())
    parser = PgPlainParser()
    rows = RowValidator(policy)
    parser.add_listener(rows)
    l5 = policy["l5"]
    n = sample_size(l5["detect_fraction"], l5["confidence"])
    sampler = ReservoirSampler(n, secrets.randbelow(1 << 32) if seed is None else seed)
    parser.add_listener(sampler)
    if trusted is not None:  # fingerprints cost a hash per row: only when there is a reference
        fp, digest = Fingerprinter(trusted.chunk_rows), StreamDigest()
        parser.add_listener(fp)
        fan.subscribe(digest)
    fan.subscribe(parser)
    end = fan.run(decoder, is_clean=lambda: decoder.info.error is None)
    checks = check_container(decoder.info, policy)
    checks[0].evidence["decompressed_lines"] = end.lines
    checks += check_structure(parser.s, end)
    checks += check_rows(rows)
    if trusted is not None:
        assert digest.info is not None
        # A second read of the compressed bytes (no second decompression), only if recorded.
        file_digest = (
            file_sha256(path, policy["stream"]["chunk_bytes"]) if trusted.compressed else None
        )
        max_examples = policy["l3"]["max_error_examples"]
        l4 += check_reconcile(trusted, fp.tables, digest.info, max_examples, file_digest)
    checks += l4
    checks += l5_checks(sampler, policy, scratch_dsn, source_dsn)
    return build_report(str(path), checks, policy, str(manifest) if manifest else None)
