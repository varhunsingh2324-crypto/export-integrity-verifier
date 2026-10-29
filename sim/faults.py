"""Fault-injection gallery (IMPLEMENTATION_PLAN.md §6). Parameters live in config/sim.yaml `faults`.

Each generator copies its source with bounded buffers (never a whole file in memory, never a
decompressed copy on disk) and returns a record of exactly what it changed.
"""

import json
import shutil
from pathlib import Path
from typing import Annotated, Any

import typer
import yaml
from pydantic import BaseModel, Field
from rich.console import Console

from sim.incident import DEFAULT_SIM, ROOT

COPY_CHUNK = 1 << 20


class F2Config(BaseModel):
    truncate_fraction: float = Field(gt=0, lt=1)


class F3Config(BaseModel):
    offset_fraction: float = Field(ge=0, lt=1)
    xor_mask: int = Field(ge=1, le=255)


class FaultsConfig(BaseModel):
    f2: F2Config
    f3: F3Config


def load_faults_config(path: Path = DEFAULT_SIM) -> FaultsConfig:
    with path.open(encoding="utf-8") as fh:
        return FaultsConfig.model_validate(yaml.safe_load(fh)["faults"])


def _copy_prefix(src: Path, dst: Path, n: int) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open("rb") as fin, dst.open("wb") as fout:
        remaining = n
        while remaining and (data := fin.read(min(COPY_CHUNK, remaining))):
            fout.write(data)
            remaining -= len(data)


def make_f2(src: Path, dst: Path, cfg: F2Config) -> dict[str, Any]:
    """F2: file truncated at rest (disk full, interrupted copy): keep a prefix of the bytes."""
    size = src.stat().st_size
    keep = int(size * cfg.truncate_fraction)
    _copy_prefix(src, dst, keep)
    return {"fault": "F2", "source": str(src), "path": str(dst), "source_bytes": size, "kept": keep}


def make_f3(src: Path, dst: Path, cfg: F3Config) -> dict[str, Any]:
    """F3: one byte flipped mid-file (bit rot) — XOR one byte in place in a streamed copy."""
    size = src.stat().st_size
    offset = int(size * cfg.offset_fraction)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    with dst.open("r+b") as fh:
        fh.seek(offset)
        old = fh.read(1)[0]
        fh.seek(offset)
        fh.write(bytes([old ^ cfg.xor_mask]))
    return {
        "fault": "F3",
        "source": str(src),
        "path": str(dst),
        "offset": offset,
        "old_byte": f"0x{old:02x}",
        "new_byte": f"0x{old ^ cfg.xor_mask:02x}",
    }


app = typer.Typer(help="Build the fault gallery from the incident's v2 export.")
console = Console()


@app.command()
def build(
    source: Annotated[Path, typer.Option()] = ROOT / "data" / "exports" / "v2.sql.gz",
    out_dir: Annotated[Path, typer.Option()] = ROOT / "data" / "exports",
    report: Annotated[Path, typer.Option()] = ROOT / "data" / "reports" / "faults.json",
) -> None:
    """Write F2 and F3 (F1, F4-F7 land with phases 3-4 and 7)."""
    if not source.is_file():
        console.print(f"[red]{source} not found — run `make incident` first[/]")
        raise typer.Exit(1)
    cfg = load_faults_config()
    records = [
        make_f2(source, out_dir / "F2_truncated.sql.gz", cfg.f2),
        make_f3(source, out_dir / "F3_byteflip.sql.gz", cfg.f3),
    ]
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(records, indent=2) + "\n")
    for r in records:
        console.print(f"{r['fault']}: {r['path']}")
    console.print("F1, F4-F7: not built yet (phases 3, 4, 7)")
    console.print(f"report: {report}")


if __name__ == "__main__":
    app()
