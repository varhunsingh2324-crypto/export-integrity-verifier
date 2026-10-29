"""Fault-injection gallery (IMPLEMENTATION_PLAN.md §6). Parameters live in config/sim.yaml `faults`.

Each generator copies its source with bounded buffers (never a whole file in memory, never a
decompressed copy on disk) and returns a record of exactly what it changed.
"""

import gzip
import json
import os
import shutil
import subprocess
from collections.abc import Callable
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Annotated, Any

import typer
import yaml
from pydantic import BaseModel, Field, field_validator
from rich.console import Console

from eguard.manifest import hmac_key_from_env, load
from eguard.models import Manifest
from sim.incident import (
    DEFAULT_SIM,
    LEGACY_EXPORT,
    ROOT,
    IncidentResult,
    SimConfig,
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


class F4Config(BaseModel):
    offset_fraction: float = Field(ge=0, lt=1)
    xor_mask: int = Field(ge=1, le=255)


class F5Config(BaseModel):
    row: int = Field(ge=1)  # row position in the first COPY block
    column: str
    delta: Decimal

    @field_validator("delta")
    @classmethod
    def _nonzero(cls, value: Decimal) -> Decimal:
        if value == 0:
            raise ValueError("delta must change the value")
        return value


class F6Config(BaseModel):
    start_row: int = Field(ge=1)
    rows: int = Field(ge=1)


class FaultsConfig(BaseModel):
    source_rows: int = Field(gt=0)  # v1 rows of the small incident variant every fault comes from
    schema_: str = Field(alias="schema")
    f1: F1Config
    f2: F2Config
    f3: F3Config
    f4: F4Config
    f5: F5Config
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


def _flip(path: Path, offset: int, mask: int) -> dict[str, Any]:
    """XOR one byte in place; return where and what changed."""
    with path.open("r+b") as fh:
        fh.seek(offset)
        old = fh.read(1)[0]
        fh.seek(offset)
        fh.write(bytes([old ^ mask]))
    return {"offset": offset, "old_byte": f"0x{old:02x}", "new_byte": f"0x{old ^ mask:02x}"}


def make_f3(src: Path, dst: Path, cfg: F3Config) -> dict[str, Any]:
    """F3: one byte flipped mid-file (bit rot) — XOR one byte in place in a streamed copy."""
    offset = int(src.stat().st_size * cfg.offset_fraction)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    return {"fault": "F3", "source": str(src), "path": str(dst)} | _flip(dst, offset, cfg.xor_mask)


COMPRESS_HEADER = 3  # 1F 9D + flags byte; F4 flips data, not the header L1 validates


def make_f4(src: Path, dst: Path, cfg: F4Config) -> dict[str, Any]:
    """F4: the dump `compress`ed to .Z (no checksum), then one byte flipped mid-file. The source is
    decompressed in chunks straight into `compress -c -f` (never to disk)."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("wb") as fout, gzip.open(src, "rb") as fin:
        proc = subprocess.Popen(["compress", "-c", "-f"], stdin=subprocess.PIPE, stdout=fout)
        assert proc.stdin is not None
        while data := fin.read(COPY_CHUNK):
            proc.stdin.write(data)
        proc.stdin.close()
        if proc.wait() != 0:
            raise RuntimeError(f"F4: compress exited {proc.returncode}")
    offset = max(COMPRESS_HEADER, int(dst.stat().st_size * cfg.offset_fraction))
    flipped = _flip(dst, offset, cfg.xor_mask)
    gzip_dc = subprocess.run(["gzip", "-dc", str(dst)], stdout=subprocess.DEVNULL).returncode
    record = {"fault": "F4", "source": str(src), "path": str(dst)}
    return record | flipped | {"gzip_dc_exit": gzip_dc}


def copy_columns(header: bytes) -> list[str]:
    """Column names of `COPY t (a, b, ...) FROM stdin;`."""
    inner = header[header.index(b"(") + 1 : header.rindex(b")")]
    return [c.strip().strip(b'"').decode() for c in inner.split(b",")]


def _alter(line: bytes, index: int, delta: Decimal) -> tuple[bytes, str, str]:
    fields = line.rstrip(b"\n").split(b"\t")
    old = fields[index].decode()
    try:
        value = Decimal(old)
    except InvalidOperation as exc:
        raise ValueError(f"F5: value {old!r} is not numeric") from exc
    new = str((value + delta).quantize(value))  # keep the column's scale, e.g. 2 decimals
    fields[index] = new.encode()
    return b"\t".join(fields) + b"\n", old, new


def make_f5(src: Path, dst: Path, cfg: F5Config) -> dict[str, Any]:
    """F5: silent value corruption inside a valid container: `column` of COPY row `row` (first
    COPY block) is changed by `delta`, then the dump is re-gzipped. Streamed line by line."""
    table, index, row, lineno, change = None, -1, 0, 0, None
    dst.parent.mkdir(parents=True, exist_ok=True)
    with (
        gzip.open(src, "rb") as fin,
        dst.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=6) as fout,
    ):
        for line in fin:
            lineno += 1
            if table is not None and change is None:
                if line == COPY_END:
                    raise ValueError(f"F5: {table} has {row} rows, need >= {cfg.row}")
                row += 1
                if row == cfg.row:
                    line, old, new = _alter(line, index, cfg.delta)
                    change = {"row": row, "line": lineno, "old_value": old, "new_value": new}
            elif table is None and is_copy_header(line):
                table = line.split()[1].decode()
                index = copy_columns(line).index(cfg.column)
            fout.write(line)
    if change is None:
        raise ValueError(f"F5: no COPY block with >= {cfg.row} rows in {src}")
    return (
        {"fault": "F5", "source": str(src), "path": str(dst), "table": table}
        | change
        | {"column": cfg.column}
    )


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


# Faults derived from the hardened export of the source (v2 state); they are verified against the
# manifest that export wrote. F1 is a separate, killed legacy pg_dump run (no manifest by design).
FROM_SOURCE = ("F2", "F3", "F4", "F5", "F6")
SOURCE_NAME = "v2_hardened.sql.gz"
SOURCE_MANIFEST = "fault_source_v2.manifest.json"
HARDENED_EXPORT = ROOT / "scripts" / "export_with_manifest.sh"


def manifest_summary(path: Path) -> dict[str, Any]:
    m = load(path)
    if not isinstance(m, Manifest):
        raise RuntimeError(f"{path}: {m}")
    return {
        "path": str(path),
        "rows": sum(t.count for t in m.tables),
        "chunk_rows": m.chunk_rows,
        "chunks": sum(len(t.chunks) for t in m.tables),
        "snapshot": m.snapshot.model_dump() if m.snapshot else None,
        "compressed": m.compressed.model_dump() if m.compressed else None,
    }


def hardened_source(table: str, out: Path, manifest: Path) -> dict[str, Any]:
    """Export the source with scripts/export_with_manifest.sh, so its manifest carries snapshot
    counts and the compressed sha256. Exit 1 (SUSPECT: L5 pending) is the healthy result for now."""
    proc = subprocess.run(
        [str(HARDENED_EXPORT), "-m", str(manifest), str(out), table],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"hardened export exited {proc.returncode}: {proc.stderr[-2000:]}")
    return manifest_summary(manifest) | {"source": str(out), "export_exit": proc.returncode}


Maker = Callable[[], dict[str, Any]]


def _makers(cfg: FaultsConfig, source: Path, out_dir: Path, table: str) -> dict[str, Maker]:
    return {
        "F1": lambda: make_f1(table, out_dir / "F1_killed.sql.gz", cfg.f1),
        "F2": lambda: make_f2(source, out_dir / "F2_truncated.sql.gz", cfg.f2),
        "F3": lambda: make_f3(source, out_dir / "F3_byteflip.sql.gz", cfg.f3),
        "F4": lambda: make_f4(source, out_dir / "F4_bitflip.sql.Z", cfg.f4),
        "F5": lambda: make_f5(source, out_dir / "F5_amount.sql.gz", cfg.f5),
        "F6": lambda: make_f6(source, out_dir / "F6_dupchunk.sql.gz", cfg.f6),
    }


def _with_incident(
    cfg: FaultsConfig, sim: SimConfig, src_dir: Path, manifest: Path, makers: dict[str, Maker]
) -> tuple[IncidentResult, dict[str, Any], list[dict[str, Any]]]:
    """Run the incident at `faults.source_rows` in its own schema, export its v2 state with the
    hardened script, build every fault, drop the schema."""
    scale = cfg.source_rows / sim.base_rows
    if scaled_rows(sim, scale) != cfg.source_rows:
        raise typer.BadParameter(f"source_rows {cfg.source_rows} not reachable from base_rows")
    table = f"{cfg.schema_}.{sim.table}"
    try:
        incident = run_incident(sim, scale, cfg.schema_, src_dir)
        summary = hardened_source(table, src_dir / SOURCE_NAME, manifest)
        return incident, summary, [make() for make in makers.values()]
    finally:
        drop_schema(cfg.schema_)


def _report_body(
    report: Path,
    incident: IncidentResult | None,
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    """New records replace same-ID ones; with --only (no incident) the others are kept."""
    old = json.loads(report.read_text()) if incident is None and report.exists() else {}
    by_id = {r["fault"]: r for r in old.get("faults", [])} | {r["fault"]: r for r in records}
    for fid, r in by_id.items():
        if fid in FROM_SOURCE:
            r["manifest"] = manifest["path"]
    return {
        "source": incident.model_dump(mode="json") if incident else old.get("source"),
        "source_manifest": manifest,
        "faults": [by_id[k] for k in sorted(by_id)],
    }


app = typer.Typer(help="Build the fault gallery from a small incident variant (disk budget).")
console = Console()


@app.command()
def build(
    out_dir: Annotated[Path, typer.Option()] = ROOT / "data" / "exports",
    report: Annotated[Path, typer.Option()] = ROOT / "data" / "reports" / "faults.json",
    manifest_dir: Annotated[Path, typer.Option()] = ROOT / "data" / "manifests",
    only: Annotated[
        list[str] | None,
        typer.Option(help="Rebuild only these (F2-F6) from the existing source; no database."),
    ] = None,
) -> None:
    """Without --only: run the incident at `faults.source_rows` in its own schema (dropped after),
    export its v2 state with the hardened script (source + signed manifest with snapshot counts),
    and build F1-F6; needs the database and MANIFEST_HMAC_KEY. F7 lands with phase 7."""
    cfg, sim = load_faults_config(), load_sim_config()
    hmac_key_from_env()  # fail before the slow part, not after it
    src_dir = out_dir / "fault_source"
    source, manifest_path = src_dir / SOURCE_NAME, manifest_dir / SOURCE_MANIFEST
    makers = _makers(cfg, source, out_dir, f"{cfg.schema_}.{sim.table}")
    incident = None
    if only:
        if bad := sorted(set(only) - set(FROM_SOURCE)):
            raise typer.BadParameter(f"--only takes {', '.join(FROM_SOURCE)}, not {bad}")
        if not (source.exists() and manifest_path.exists()):
            raise typer.BadParameter(f"{source} or its manifest missing: run `make faults` first")
        records = [makers[f]() for f in sorted(set(only))]
        manifest = manifest_summary(manifest_path) | {"source": str(source)}
    else:
        incident, manifest, records = _with_incident(cfg, sim, src_dir, manifest_path, makers)
    body = _report_body(report, incident, manifest, records)
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(body, indent=2, default=str) + "\n")
    console.print(f"source: {source} (manifest {manifest['path']}, {manifest['chunks']} chunks)")
    for r in records:
        console.print(f"{r['fault']}: {r['path']}")
    console.print(f"report: {report}")


if __name__ == "__main__":
    app()
