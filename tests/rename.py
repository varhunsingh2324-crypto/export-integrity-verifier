"""CONTRIBUTING.md rule 9 helpers: copy files to random names and compare verdicts."""

import secrets
import shutil
from pathlib import Path

from eguard.models import VerifyReport


def decoy(tmp_path: Path, path: Path) -> Path:
    """A copy under a random directory, name and extension."""
    copy = tmp_path / secrets.token_hex(4) / f"{secrets.token_hex(6)}.{secrets.token_hex(2)}"
    copy.parent.mkdir()
    shutil.copyfile(path, copy)
    return copy


def signature(report: VerifyReport) -> tuple:
    return report.verdict, report.ral, [(c.name, c.status, c.evidence) for c in report.checks]
