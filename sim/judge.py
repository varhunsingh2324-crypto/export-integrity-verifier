"""`make judge-test`: damage a COPY of an export at a byte offset chosen by the judge, so anyone can
check ExportGuard against a fault it has never seen. The source file is never modified.

Prints the damaged copy's path on stdout (the Makefile verifies it) and what changed on stderr.
"""

import json
import shutil
import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from sim.faults import ROOT, _copy_prefix, _flip, load_faults_config

MODES = ("flip", "truncate")


def parse_offset(text: str, size: int) -> int:
    """Bytes, or a percentage of the file (`50%`). Must land inside the file: 0 <= offset < size."""
    offset = int(size * float(text[:-1]) / 100) if text.endswith("%") else int(text)
    if not 0 <= offset < size:
        raise ValueError(f"offset {offset:,} is outside the file (0 to {size - 1:,})")
    return offset


def corrupt_copy(src: Path, out_dir: Path, offset: int, mode: str, mask: int) -> dict[str, Any]:
    """flip: XOR the byte at `offset` with `mask`. truncate: keep the first `offset` bytes."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)}, not {mode!r}")
    dst = out_dir / f"judge_{mode}_{offset}_{src.name}"
    record: dict[str, Any] = {"source": str(src), "path": str(dst), "mode": mode}
    record["source_bytes"] = src.stat().st_size
    if mode == "truncate":
        _copy_prefix(src, dst, offset)
        return record | {"kept": offset}
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    return record | _flip(dst, offset, mask)


def main(
    file: Path,
    offset: Annotated[str, typer.Option(help="Byte offset, or a percentage such as 50%.")],
    mode: Annotated[str, typer.Option(help="flip | truncate")] = "flip",
    mask: Annotated[
        int | None, typer.Option(help="XOR mask (default: config/sim.yaml f3).")
    ] = None,
    out_dir: Annotated[Path, typer.Option()] = ROOT / "data" / "dev",
) -> None:
    try:
        size = file.stat().st_size
        at = parse_offset(offset, size)
        xor = mask if mask is not None else load_faults_config().f3.xor_mask
        if not 1 <= xor <= 255:
            raise ValueError(f"mask must be 1-255, not {xor}")
        record = corrupt_copy(file, out_dir, at, mode, xor)
    except (OSError, ValueError) as exc:
        typer.echo(f"judge-test: {exc}", err=True)
        raise typer.Exit(3) from exc  # rule 7: a tool error, never a verdict
    typer.echo(json.dumps(record), err=True)
    typer.echo(record["path"])


if __name__ == "__main__":
    try:
        typer.run(main)
    except SystemExit as exc:  # click usage errors exit 2, which would read as CORRUPT
        sys.exit(3 if exc.code not in (0, None, 3) else exc.code)
