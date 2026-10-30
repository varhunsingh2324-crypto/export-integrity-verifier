"""`eguard verify-all`: verify every export in a directory; one row each: gzip -t, L1-L5, verdict.

Which manifest belongs to which file is orchestration, like passing --manifest by hand: it comes
from the fault gallery record (data/reports/faults.json), else the `eguard export` default
<manifests>/<name>.manifest.json. Detection itself never sees a file name (rule 9).
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from eguard.manifest import ManifestError, hmac_key_from_env
from eguard.models import Verdict, VerifyReport
from eguard.stream import LineTooLong
from eguard.verify import verify_file

EXTENSIONS = (".gz", ".Z")  # .partial / .FAILED leftovers have other suffixes and are skipped
EXPORT_SUFFIXES = (".sql.gz", ".sql.Z", ".gz", ".Z")


class MatrixRow(BaseModel):
    path: str
    label: str  # fault ID from the gallery record, else the file name
    manifest: str | None
    gzip_t: int | None  # exit code of `gzip -t`; None when gzip is not on PATH
    report: VerifyReport | None = None
    error: str | None = None  # tool error for this file (exit 3)

    @property
    def exit_code(self) -> int:
        return self.report.exit_code if self.report else Verdict.TOOL_ERROR.exit_code


def discover(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix in EXTENSIONS)


def gallery_records(gallery: Path | None) -> dict[Path, tuple[str, Path | None]]:
    """Resolved file path -> (fault ID, manifest) from a `sim.faults` report."""
    if gallery is None or not gallery.exists():
        return {}
    body = json.loads(gallery.read_text())
    return {
        Path(r["path"]).resolve(): (r["fault"], Path(r["manifest"]) if r.get("manifest") else None)
        for r in body.get("faults", [])
    }


def export_name(path: Path) -> str:
    """`v3.sql.gz` -> `v3`, as scripts/export_with_manifest.sh names its default manifest."""
    for suffix in EXPORT_SUFFIXES:
        if path.name.endswith(suffix):
            return path.name[: -len(suffix)]
    return path.name


def report_stem(path: Path, root: Path) -> str:
    """`verify_<path under root>` with `/` -> `__`: fault_source/v2.sql.gz and v2.sql.gz differ."""
    rel = path.relative_to(root) if path.is_relative_to(root) else Path(path.name)
    return "verify_" + "__".join([*rel.parent.parts, export_name(rel)])


def pairing(
    path: Path, known: dict[Path, tuple[str, Path | None]], manifests: Path
) -> tuple[str, Path | None]:
    if hit := known.get(path.resolve()):
        return hit
    default = manifests / f"{export_name(path)}.manifest.json"
    return path.name, default if default.exists() else None


def gzip_t(path: Path) -> int | None:
    if shutil.which("gzip") is None:
        return None
    return subprocess.run(["gzip", "-t", str(path)], capture_output=True).returncode


def verify_one(
    path: Path,
    label: str,
    manifest: Path | None,
    policy: dict[str, Any],
    *,
    scratch_dsn: str | None,
    seed: int | None,
) -> MatrixRow:
    row = MatrixRow(
        path=str(path),
        label=label,
        manifest=str(manifest) if manifest else None,
        gzip_t=gzip_t(path),
    )
    try:
        key = hmac_key_from_env() if manifest is not None else None
        row.report = verify_file(path, policy, manifest, key, scratch_dsn=scratch_dsn, seed=seed)
    except (OSError, LineTooLong, ManifestError) as exc:
        row.error = str(exc)
    return row


def worst_exit(rows: list[MatrixRow]) -> int:
    """Rule 7 over many files: 3 (tool error) > 2 (CORRUPT) > 1 (SUSPECT) > 0; no files is 3."""
    return max((r.exit_code for r in rows), default=Verdict.TOOL_ERROR.exit_code)
