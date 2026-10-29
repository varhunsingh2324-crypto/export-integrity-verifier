"""Reproduce the incident: seed -> export v1 -> privacy purge + growth -> export v2.

All knobs live in config/sim.yaml. SQL runs inside the db container (avoids client/server
version mismatch); exports go through the deliberately naive scripts/legacy_export.sh.
"""

import gzip
import json
import subprocess
from datetime import date
from pathlib import Path
from typing import Annotated

import typer
import yaml
from pydantic import BaseModel, Field
from rich.console import Console
from rich.table import Table

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SIM = ROOT / "config" / "sim.yaml"
SIM_DIR = ROOT / "sim"
LEGACY_EXPORT = ROOT / "scripts" / "legacy_export.sh"
COMPOSE = ["docker", "compose", "-f", str(ROOT / "docker-compose.yml")]
PSQL = ["exec", "-T", "db", "psql", "-U", "eguard", "-d", "eguard"]
DUMP_COMPLETE = b"-- PostgreSQL database dump complete"


class V1Config(BaseModel):
    ts_start: date
    ts_end: date
    accounts: int = Field(gt=0)
    merchants: int = Field(gt=0)
    currencies: list[str] = Field(min_length=1)
    statuses: list[str] = Field(min_length=1)
    channels: list[str] = Field(min_length=1)
    remarks_chars: int = Field(ge=0)
    meta_trace_chars: int = Field(ge=0)


class PurgeConfig(BaseModel):
    cutoff: date
    meta_drop_keys: list[str]


class GrowthConfig(BaseModel):
    fraction: float = Field(gt=0)
    ts_start: date
    ts_end: date
    accounts: int = Field(gt=0)
    merchants: int = Field(gt=0)
    currencies: list[str] = Field(min_length=1)
    statuses: list[str] = Field(min_length=1)
    channels: list[str] = Field(min_length=1)
    amounts: list[float] = Field(min_length=1)
    meta: str


class Target(BaseModel):
    value: float
    tolerance: float = Field(ge=0)

    def met(self, actual: float) -> bool:
        return abs(actual - self.value) <= self.tolerance


class Targets(BaseModel):
    rows_change: Target
    size_change: Target


class SimConfig(BaseModel):
    seed: float = Field(ge=-1, le=1)
    base_rows: int = Field(gt=0)
    table: str
    v1: V1Config
    purge: PurgeConfig
    growth: GrowthConfig
    targets: Targets


class ExportStat(BaseModel):
    path: Path
    rows: int
    raw_bytes: int
    gz_bytes: int


class IncidentResult(BaseModel):
    scale: float
    v1: ExportStat
    v2: ExportStat
    rows_change: float
    size_change: float
    raw_change: float
    rows_ok: bool
    size_ok: bool


def load_sim_config(path: Path = DEFAULT_SIM) -> SimConfig:
    with path.open(encoding="utf-8") as fh:
        return SimConfig.model_validate(yaml.safe_load(fh))


def scaled_rows(cfg: SimConfig, scale: float) -> int:
    if scale <= 0:
        raise ValueError(f"scale must be > 0, got {scale}")
    return round(cfg.base_rows * scale)


def pct_change(old: float, new: float) -> float:
    return (new - old) / old


def _pg_array(values: list[str] | list[float]) -> str:
    return "{" + ",".join(str(v) for v in values) + "}"


def run_sql(sql: str, variables: dict[str, object]) -> str:
    """Run SQL with psql inside the db container; returns unaligned tuples-only stdout."""
    cmd = [*COMPOSE, *PSQL, "-X", "-q", "-tA", "-v", "ON_ERROR_STOP=1"]
    for key, value in variables.items():
        cmd += ["-v", f"{key}={value}"]
    proc = subprocess.run(cmd, input=sql, capture_output=True, text=True, cwd=ROOT)
    if proc.returncode != 0:
        raise RuntimeError(f"psql failed ({proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout.strip()


def run_sql_file(name: str, variables: dict[str, object]) -> str:
    return run_sql((SIM_DIR / name).read_text(encoding="utf-8"), variables)


def count_rows(schema: str, table: str) -> int:
    return int(
        run_sql('SELECT count(*) FROM :"schema".:"table";', {"schema": schema, "table": table})
    )


def drop_schema(schema: str) -> None:
    run_sql('DROP SCHEMA IF EXISTS :"schema" CASCADE;', {"schema": schema})


def seed(cfg: SimConfig, rows: int, schema: str) -> None:
    v1 = cfg.v1
    run_sql_file(
        "seed.sql",
        {
            "schema": schema,
            "rows": rows,
            "seed": cfg.seed,
            "ts_start": v1.ts_start,
            "ts_end": v1.ts_end,
            "accounts": v1.accounts,
            "merchants": v1.merchants,
            "currencies": _pg_array(v1.currencies),
            "statuses": _pg_array(v1.statuses),
            "channels": _pg_array(v1.channels),
            "remarks_chars": v1.remarks_chars,
            "meta_trace_chars": v1.meta_trace_chars,
        },
    )


def business_change(cfg: SimConfig, v1_rows: int, schema: str) -> None:
    """Privacy purge of old rows, then +growth.fraction low-entropy rows."""
    purge, grow = cfg.purge, cfg.growth
    run_sql_file(
        "purge.sql",
        {
            "schema": schema,
            "cutoff": purge.cutoff,
            "meta_drop_keys": _pg_array(purge.meta_drop_keys),
        },
    )
    run_sql_file(
        "grow.sql",
        {
            "schema": schema,
            "rows": round(v1_rows * grow.fraction),
            "seed": cfg.seed,
            "ts_start": grow.ts_start,
            "ts_end": grow.ts_end,
            "accounts": grow.accounts,
            "merchants": grow.merchants,
            "currencies": _pg_array(grow.currencies),
            "statuses": _pg_array(grow.statuses),
            "channels": _pg_array(grow.channels),
            "amounts": _pg_array(grow.amounts),
            "meta": grow.meta,
        },
    )


def raw_size(path: Path) -> tuple[int, bytes]:
    """Stream-decompress (never to disk); return raw byte count and the stream's last 4 KiB."""
    total, tail = 0, b""
    with gzip.open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            total += len(chunk)
            tail = (tail + chunk)[-4096:]
    return total, tail


def legacy_export(schema: str, table: str, out: Path) -> ExportStat:
    rows = count_rows(schema, table)
    out.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run([str(LEGACY_EXPORT), f"{schema}.{table}", str(out)], cwd=ROOT)
    if proc.returncode != 0:
        raise RuntimeError(f"legacy export failed ({proc.returncode})")
    raw, tail = raw_size(out)
    # Sanity guard for the simulation only: calibration numbers must come from a complete dump.
    if DUMP_COMPLETE not in tail:
        raise RuntimeError(f"{out}: dump is missing the completion marker")
    return ExportStat(path=out, rows=rows, raw_bytes=raw, gz_bytes=out.stat().st_size)


def run_incident(cfg: SimConfig, scale: float, schema: str, out_dir: Path) -> IncidentResult:
    seed(cfg, scaled_rows(cfg, scale), schema)
    v1 = legacy_export(schema, cfg.table, out_dir / "v1.sql.gz")
    business_change(cfg, v1.rows, schema)
    v2 = legacy_export(schema, cfg.table, out_dir / "v2.sql.gz")
    rows_change = pct_change(v1.rows, v2.rows)
    size_change = pct_change(v1.gz_bytes, v2.gz_bytes)
    return IncidentResult(
        scale=scale,
        v1=v1,
        v2=v2,
        rows_change=rows_change,
        size_change=size_change,
        raw_change=pct_change(v1.raw_bytes, v2.raw_bytes),
        rows_ok=cfg.targets.rows_change.met(rows_change),
        size_ok=cfg.targets.size_change.met(size_change),
    )


app = typer.Typer(help="Reproduce the ExportGuard incident (IMPLEMENTATION_PLAN.md §6).")
console = Console()
Scale = Annotated[float, typer.Option(help="Multiplier on base_rows (e.g. 0.02 for tests/CI).")]
Schema = Annotated[str, typer.Option(help="Schema holding the transactions table.")]


def _print_result(result: IncidentResult, targets: Targets) -> None:
    table = Table(title=f"incident (scale {result.scale:g})")
    for col in ("", "rows", "raw dump bytes", "gzip bytes", "bytes/row (gz)"):
        table.add_column(col, justify="right")
    for name, s in (("v1", result.v1), ("v2", result.v2)):
        table.add_row(
            name, f"{s.rows:,}", f"{s.raw_bytes:,}", f"{s.gz_bytes:,}", f"{s.gz_bytes / s.rows:.1f}"
        )
    per_row = [s.gz_bytes / s.rows for s in (result.v1, result.v2)]
    table.add_row(
        "change",
        f"{result.rows_change:+.2%}",
        f"{result.raw_change:+.2%}",
        f"{result.size_change:+.2%}",
        f"{pct_change(*per_row):+.2%}",
    )
    console.print(table)
    for label, ok, actual, target in (
        ("rows", result.rows_ok, result.rows_change, targets.rows_change),
        ("gzip size", result.size_ok, result.size_change, targets.size_change),
    ):
        mark = "[green]PASS[/]" if ok else "[red]FAIL[/]"
        console.print(
            f"{mark} {label} {actual:+.2%} (target {target.value:+.0%} ± {target.tolerance:.0%})"
        )


@app.command("seed")
def seed_cmd(scale: Scale = 1.0, schema: Schema = "public") -> None:
    """Create and load the transactions table."""
    cfg = load_sim_config()
    rows = scaled_rows(cfg, scale)
    seed(cfg, rows, schema)
    console.print(f"seeded {schema}.{cfg.table}: {count_rows(schema, cfg.table):,} rows")


@app.command("run")
def run_cmd(
    scale: Scale = 1.0,
    schema: Schema = "public",
    out_dir: Annotated[Path, typer.Option()] = ROOT / "data" / "exports",
    report: Annotated[Path, typer.Option()] = ROOT / "data" / "reports" / "incident.json",
) -> None:
    """Seed, export v1, apply the business change, export v2, and compare."""
    cfg = load_sim_config()
    result = run_incident(cfg, scale, schema, out_dir)
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(result.model_dump(mode="json"), indent=2) + "\n")
    _print_result(result, cfg.targets)
    console.print(f"report: {report}")
    raise typer.Exit(0 if result.rows_ok and result.size_ok else 1)


if __name__ == "__main__":
    app()
