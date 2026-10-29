"""Fault-injection gallery (IMPLEMENTATION_PLAN.md §6). Parameters live in config/sim.yaml `faults`.

Each generator copies its source with bounded buffers (never a whole file in memory, never a
decompressed copy on disk) and returns a record of exactly what it changed.
"""

import gzip
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Annotated, Any

import typer
import yaml
from pydantic import BaseModel, Field
from rich.console import Console

from sim.incident import (
    DEFAULT_SIM,
    LEGACY_EXPORT,
    ROOT,
    drop_schema,
    load_sim_config,
    run_incident,
    scaled_rows,
)

COPY_CHUNK = 1 << 20
COPY_END = b"\\.\n"
DUMP_COMPLETE = b"-- PostgreSQL database dump complete\n"


class F1Config(BaseModel):
    timeout_seconds: float = Field(gt=0)
    max_attempts: int = Field(ge=1)


class F2Config(BaseModel):
    truncate_fraction: float = Field(gt=0, lt=1)


class F3Config(BaseModel):
    offset_fraction: float = Field(ge=0, lt=1)
    xor_mask: int = Field(ge=1, le=255)


class F6Config(BaseModel):
    start_row: int = Field(ge=1)
    rows: int = Field(ge=1)


class FaultsConfig(BaseModel):
    source_rows: int = Field(gt=0)  # v1 rows of the small incident variant every fault comes from
    schema_: str = Field(alias="schema")
    f1: F1Config
    f2: F2Config
    f3: F3Config
    f6: F6Config


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


def is_copy_header(line: bytes) -> bool:
    return line.startswith(b"COPY ") and line.endswith(b" FROM stdin;\n")


def dump_outcome(path: Path) -> dict[str, Any]:
    """Independent oracle for F1 (deliberately not eguard's parser): where did the dump stop?"""
    copy_seen = closed = complete = False
    rows = 0
    with gzip.open(path, "rb") as fh:
        for line in fh:
            if is_copy_header(line):
                copy_seen = True
            elif copy_seen and not closed:
                if line == COPY_END:
                    closed = True
                elif line.endswith(b"\n"):
                    rows += 1
            elif line == DUMP_COMPLETE:
                complete = True
    if complete:
        kind = "completed"
    elif copy_seen and not closed and rows:
        kind = "mid_copy"
    else:
        kind = "before_data"
    return {"outcome": kind, "complete_rows_written": rows}


def _gzip_t(path: Path) -> int:
    return subprocess.run(["gzip", "-t", str(path)], capture_output=True).returncode


def make_f1(qualified_table: str, dst: Path, cfg: F1Config) -> dict[str, Any]:
    """F1: pg_dump killed by `timeout` inside the naive `pg_dump | gzip` pipe.

    Timing decides where the kill lands, so each attempt is checked by `dump_outcome` and the
    timeout is bisected until pg_dump died inside the COPY data. Every attempt is recorded.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    lo, hi, t = 0.0, float("inf"), cfg.timeout_seconds
    attempts: list[dict[str, Any]] = []
    for _ in range(cfg.max_attempts):
        env = os.environ | {"LEGACY_DUMP_TIMEOUT": f"{t:.3f}"}
        proc = subprocess.run(
            [str(LEGACY_EXPORT), qualified_table, str(dst)], env=env, capture_output=True, cwd=ROOT
        )
        outcome = dump_outcome(dst)
        attempts.append({"timeout_seconds": round(t, 3), "script_exit": proc.returncode} | outcome)
        if outcome["outcome"] == "mid_copy":
            return {
                "fault": "F1",
                "table": qualified_table,
                "path": str(dst),
                "timeout_seconds": round(t, 3),
                "script_exit": proc.returncode,
                "gzip_t_exit": _gzip_t(dst),
                "complete_rows_written": outcome["complete_rows_written"],
                "attempts": attempts,
            }
        if outcome["outcome"] == "completed":
            hi = t
            t = (lo + t) / 2
        else:
            lo = t
            t = t * 2 if hi == float("inf") else (t + hi) / 2
    raise RuntimeError(f"F1: pg_dump never killed mid-COPY in {cfg.max_attempts} tries: {attempts}")


def make_f6(src: Path, dst: Path, cfg: F6Config) -> dict[str, Any]:
    """F6: a bad retry re-sends a chunk — rows [start_row, start_row + rows) of the first COPY
    block appear twice in a row. Streamed: only the duplicated rows are buffered."""
    last = cfg.start_row + cfg.rows - 1
    buf: list[bytes] = []
    table, lineno, row, inserted_at = None, 0, 0, None
    dst.parent.mkdir(parents=True, exist_ok=True)
    with (
        gzip.open(src, "rb") as fin,
        dst.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=6) as fout,
    ):
        for line in fin:
            lineno += 1
            fout.write(line)
            if inserted_at is not None:
                continue
            if table is None:
                if is_copy_header(line):
                    table = line.split()[1].decode()
                continue
            if line == COPY_END:
                raise ValueError(f"F6: {table} has {row} rows, need >= {last}")
            row += 1
            if row >= cfg.start_row:
                buf.append(line)
            if row == last:
                fout.writelines(buf)
                inserted_at, buf = lineno + 1, []
    if inserted_at is None:
        raise ValueError(f"F6: no COPY block with >= {last} rows in {src}")
    return {
        "fault": "F6",
        "source": str(src),
        "path": str(dst),
        "table": table,
        "duplicated_stream_rows": [cfg.start_row, last],  # positions in the COPY block, not ids
        "inserted_at_line": inserted_at,
        "lines_added": cfg.rows,
    }


app = typer.Typer(help="Build the fault gallery from a small incident variant (disk budget).")
console = Console()


@app.command()
def build(
    out_dir: Annotated[Path, typer.Option()] = ROOT / "data" / "exports",
    report: Annotated[Path, typer.Option()] = ROOT / "data" / "reports" / "faults.json",
) -> None:
    """Run the incident at `faults.source_rows` in its own schema, then write F1, F2, F3, F6 from it
    (F4, F5, F7 land with phases 4 and 7). The schema is dropped afterwards. Needs the database."""
    cfg, sim = load_faults_config(), load_sim_config()
    scale = cfg.source_rows / sim.base_rows
    if scaled_rows(sim, scale) != cfg.source_rows:
        raise typer.BadParameter(f"source_rows {cfg.source_rows} not reachable from base_rows")
    src_dir = out_dir / "fault_source"
    try:
        incident = run_incident(sim, scale, cfg.schema_, src_dir)
        source = src_dir / "v2.sql.gz"
        records = [
            make_f1(f"{cfg.schema_}.{sim.table}", out_dir / "F1_killed.sql.gz", cfg.f1),
            make_f2(source, out_dir / "F2_truncated.sql.gz", cfg.f2),
            make_f3(source, out_dir / "F3_byteflip.sql.gz", cfg.f3),
            make_f6(source, out_dir / "F6_dupchunk.sql.gz", cfg.f6),
        ]
    finally:
        drop_schema(cfg.schema_)
    report.parent.mkdir(parents=True, exist_ok=True)
    body = {"source": incident.model_dump(mode="json"), "faults": records}
    report.write_text(json.dumps(body, indent=2) + "\n")
    console.print(
        f"source: {incident.v1.rows:,}-row variant, v2 {incident.v2.rows:,} rows ({src_dir})"
    )
    for r in records:
        console.print(f"{r['fault']}: {r['path']}")
    console.print("F4, F5, F7: not built yet (phases 4, 7)")
    console.print(f"report: {report}")


if __name__ == "__main__":
    app()
