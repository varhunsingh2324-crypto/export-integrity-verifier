"""Manifest: build from a dump stream, sign (HMAC-SHA256), save, load (IMPLEMENTATION_PLAN §7).

The manifest is built from the very stream the exporter writes (behind `tee`), so it records what
the exporter emitted. The HMAC key comes from MANIFEST_HMAC_KEY; without the key a manifest can be
read but neither signed nor trusted.
"""

import hashlib
import hmac
import json
import os
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from eguard import __version__
from eguard.fingerprint import ALGORITHMS, Fingerprinter, StreamDigest
from eguard.models import DumpStructure, Manifest, TableFingerprint
from eguard.parsers.pg_plain import COMPLETE, PgPlainParser
from eguard.stream import FanOut

FORMAT_VERSION = 1
PLACEHOLDER_KEY = "change-me"  # the value in .env.example
MAX_MANIFEST_BYTES = 16 << 20  # a manifest is KBs; refuse to slurp anything absurd


class ManifestError(Exception):
    """Configuration problem (missing key, incompatible manifest): a tool error, not a verdict."""


def hmac_key_from_env(env: Mapping[str, str] = os.environ) -> bytes:
    key = env.get("MANIFEST_HMAC_KEY", "")
    if not key:
        raise ManifestError(
            "MANIFEST_HMAC_KEY is not set (copy .env.example to .env; `make` exports it, "
            "or run `set -a; . ./.env; set +a`)"
        )
    return key.encode()


def canonical_bytes(m: Manifest) -> bytes:
    body = m.model_dump(mode="json", exclude={"signature"})
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _mac(m: Manifest, key: bytes) -> str:
    return hmac.new(key, canonical_bytes(m), hashlib.sha256).hexdigest()


def sign(m: Manifest, key: bytes) -> Manifest:
    return m.model_copy(update={"signature": _mac(m, key)})


def signature_ok(m: Manifest, key: bytes) -> bool:
    return m.signature is not None and hmac.compare_digest(m.signature, _mac(m, key))


def check_compatible(m: Manifest) -> None:
    """A correctly signed manifest made with other algorithms cannot be compared: tool error."""
    if m.format_version != FORMAT_VERSION or m.algorithms != ALGORITHMS:
        raise ManifestError(
            f"manifest format {m.format_version} / algorithms {m.algorithms} not supported "
            f"(expected format {FORMAT_VERSION} / {ALGORITHMS})"
        )


def dump_complete(s: DumpStructure) -> bool:
    return s.state == COMPLETE and all(b.closed for b in s.copies)


def make_manifest(
    tables: list[TableFingerprint], digest: StreamDigest, s: DumpStructure, chunk_rows: int
) -> Manifest:
    assert digest.info is not None
    return Manifest(
        format_version=FORMAT_VERSION,
        tool=f"eguard {__version__}",
        created_at=datetime.now(UTC).isoformat(timespec="seconds"),
        algorithms=ALGORITHMS,
        chunk_rows=chunk_rows,
        stream=digest.info,
        dumped_by=s.dumped_by,
        dump_complete=dump_complete(s),
        tables=tables,
    )


def build_from_chunks(chunks: Iterable[bytes], policy: dict[str, Any], key: bytes) -> Manifest:
    """One streaming pass over decompressed dump bytes -> signed manifest."""
    chunk_rows = policy["l4"]["chunk_rows"]
    fan = FanOut(policy["stream"]["max_line_bytes"])
    digest = StreamDigest()
    parser = PgPlainParser()
    fp = Fingerprinter(chunk_rows)
    parser.add_listener(fp)
    fan.subscribe(digest)
    fan.subscribe(parser)
    fan.run(chunks)
    return sign(make_manifest(fp.tables, digest, parser.s, chunk_rows), key)


def save(m: Manifest, path: Path) -> None:
    """Write via a temp file + rename, so a crash never leaves a half-written manifest."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(m.model_dump_json(indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def load(path: Path) -> Manifest | str:
    """The manifest, or why it is unreadable. A missing file raises OSError (tool error)."""
    size = path.stat().st_size
    if size > MAX_MANIFEST_BYTES:
        return f"{size} bytes exceeds {MAX_MANIFEST_BYTES}"
    try:
        return Manifest.model_validate_json(path.read_bytes())
    except ValidationError as exc:
        return "; ".join(
            f"{'.'.join(map(str, e['loc'])) or 'document'}: {e['msg']}" for e in exc.errors()[:5]
        )
