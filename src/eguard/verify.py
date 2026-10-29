"""`eguard verify`: one streaming pass over the export; every layer subscribes to that stream."""

from pathlib import Path
from typing import Any

from eguard.container import check_container
from eguard.fingerprint import Fingerprinter, StreamDigest
from eguard.manifest import ManifestError, check_compatible, load
from eguard.models import CheckResult, Manifest, Severity, Status, StreamEnd, VerifyReport
from eguard.parsers.pg_plain import PgPlainParser
from eguard.reconcile import check_reconcile, check_signature, no_manifest, untrusted
from eguard.rows import RowValidator, check_rows
from eguard.stream import Consumer, FanOut, open_decoder
from eguard.structure import check_structure
from eguard.verdict import decide

# Layers not built yet are reported as SKIP, so the verdict can never exceed SUSPECT without them.
PENDING_LAYERS = {
    5: ("restore drill", 5),
}


class StreamStats(Consumer):
    """Counts decompressed lines; also keeps the line fan-out path exercised end to end."""

    def __init__(self) -> None:
        self.end: StreamEnd | None = None

    def on_line(self, line: bytes, lineno: int) -> None:
        pass

    def on_end(self, end: StreamEnd) -> None:
        self.end = end


def _pending_checks() -> list[CheckResult]:
    return [
        CheckResult(
            layer=layer,
            name=f"l{layer}_pending",
            status=Status.SKIP,
            severity=Severity.INFO,
            evidence={"phase": phase},
            message=f"L{layer} {what} not implemented yet (phase {phase})",
        )
        for layer, (what, phase) in PENDING_LAYERS.items()
    ]


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
) -> VerifyReport:
    trusted, l4 = _trusted_manifest(manifest, key)
    decoder = open_decoder(path, policy["stream"]["chunk_bytes"])
    fan = FanOut(policy["stream"]["max_line_bytes"])
    fan.subscribe(StreamStats())
    parser = PgPlainParser()
    rows = RowValidator(policy)
    parser.add_listener(rows)
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
        l4 += check_reconcile(trusted, fp.tables, digest.info, policy["l3"]["max_error_examples"])
    checks += l4
    checks += _pending_checks()
    verdict, level = decide(checks)
    return VerifyReport(path=str(path), verdict=verdict, ral=level, checks=checks)
