"""Scale benchmark (phase 8): `eguard verify` (L1–L5, with manifest) at 1×/3×/5× of base_rows,
plus one timed full re-import of the 1× export for comparison.

Per scale: seed `bench.schema` at scale × base_rows, export it with the hardened script (signed
manifest), measure `eguard verify --manifest` with bench/l1_memory.measure (wall, peak RSS from
wait4, sampled VmRSS), then delete the export, its manifest and the schema before the next scale
(rule 10). Before each scale the export size is estimated; if it would push the project
past `bench.disk_budget_bytes`, the run stops and results.md says so.

The re-import streams `gzip -dc` into psql inside the container (ON_ERROR_STOP) in a throwaway
database, records wall time and pg_database_size growth, and drops the database in `finally`.
Every number written to bench/results.md comes from this run (CONTRIBUTING.md rule 5).
"""

import json
import os
import platform
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(Path(__file__).parent)]

from l1_memory import RESULTS, _commit, _cpu, measure  # noqa: E402

from sim.faults import hardened_export  # noqa: E402
from sim.incident import (  # noqa: E402
    COMPOSE,
    DEFAULT_SIM,
    drop_schema,
    load_sim_config,
    run_sql,
    scaled_rows,
    seed,
)

BENCH_DIR = ROOT / "data" / "bench"
EXPORTS = ROOT / "data" / "exports"
REPORTS = ROOT / "data" / "reports"
V1 = EXPORTS / "v1.sql.gz"
# Faults whose bytes a plain re-import would load (bench labels only; no verdict depends on them):
# F5 is a well-formed dump with one value changed, F1 a dump whose exporter was killed mid-COPY.
FAULT_REIMPORTS = (("F5", "F5_amount.sql.gz"), ("F1", "F1_killed.sql.gz"))
MARGIN = 1.1  # the estimate is padded: row widths vary a little between scales
FALLBACK_UNIT = 60_000_000  # bytes per 1× when nothing has been measured yet (v1 1× is 49.5 MB)
HEADER = "# Benchmarks\n\nEvery number here is produced by a script in `bench/`; newest first.\n\n"


class BenchConfig(BaseModel):
    scales: list[int] = Field(min_length=1)
    schema_: str = Field(alias="schema")
    restore_db: str
    reimport_scale: int
    disk_budget_bytes: int = Field(gt=0)


def load_bench_config(path: Path = DEFAULT_SIM) -> BenchConfig:
    with path.open(encoding="utf-8") as fh:
        return BenchConfig.model_validate(yaml.safe_load(fh)["bench"])


def project_bytes() -> int:
    out = subprocess.run(["du", "-sb", str(ROOT)], capture_output=True, text=True, check=True)
    return int(out.stdout.split()[0])


def estimate_bytes(scale: int, unit_bytes: int) -> int:
    return round(scale * unit_bytes * MARGIN)


def fits(project: int, estimate: int, budget: int) -> bool:
    return project + estimate <= budget


def _psql(db: str) -> list[str]:
    return [*COMPOSE, "exec", "-T", "db", "psql", "-U", "eguard", "-d", db, "-X", "-q", "-tA"]


def _admin(sql: str, db: str = "eguard") -> str:
    proc = subprocess.run(
        [*_psql(db), "-v", "ON_ERROR_STOP=1", "-c", sql], capture_output=True, text=True, cwd=ROOT
    )
    if proc.returncode != 0:
        raise RuntimeError(f"psql failed ({proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout.strip()


def _db_size(db: str) -> int:
    return int(_admin(f"SELECT pg_database_size('{db}');"))


def _load(db: str, schema: str, path: Path) -> dict[str, Any]:
    """Stream `gzip -dc path | psql -v ON_ERROR_STOP=1` into a fresh `db` and measure it. psql's
    exit code is recorded, not raised: a failed load is a result here."""
    _admin(f'DROP DATABASE IF EXISTS "{db}";')
    _admin(f'CREATE DATABASE "{db}";')
    try:
        _admin(f'CREATE SCHEMA "{schema}";', db)  # pg_dump -t does not emit CREATE SCHEMA
        before = _db_size(db)
        start = time.perf_counter()
        unzip = subprocess.Popen(
            ["gzip", "-dc", str(path)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        load = subprocess.run(
            [*_psql(db), "-v", "ON_ERROR_STOP=1"],
            stdin=unzip.stdout,
            capture_output=True,
            text=True,
            cwd=ROOT,
        )
        unzip.stdout.close()
        rc_unzip = unzip.wait()
        wall = time.perf_counter() - start
        table = f'"{schema}".transactions'
        exists = _admin(f"SELECT to_regclass('{table}') IS NOT NULL;", db) == "t"
        rows = int(_admin(f"SELECT count(*) FROM {table};", db)) if exists else None
        errors = [ln for ln in load.stderr.splitlines() if "ERROR" in ln or "FATAL" in ln]
        return {
            "wall_s": wall,
            "db_bytes": _db_size(db) - before,
            "rows": rows,
            "gzip_exit": rc_unzip,
            "psql_exit": load.returncode,
            "psql_error": errors[0].strip() if errors else None,
        }
    finally:
        _admin(f'DROP DATABASE IF EXISTS "{db}";')


def reimport(cfg: BenchConfig, path: Path) -> dict[str, Any]:
    """Full re-import of a healthy export: the operation ExportGuard replaces."""
    r = _load(cfg.restore_db, cfg.schema_, path)
    if r["gzip_exit"] != 0 or r["psql_exit"] != 0:
        raise RuntimeError(f"re-import of {path} failed: {r}")
    return r


def _matrix_row(path: Path) -> dict[str, Any]:
    matrix = json.loads((REPORTS / "verify_all.json").read_text())
    rel = path.relative_to(ROOT).as_posix()
    report = next(r["report"] for r in matrix["rows"] if r["path"] == rel)
    fails = [c for c in report["checks"] if c["status"] == "FAIL"]
    return {
        "verdict": report["verdict"],
        "exit": report["exit_code"],
        "fails": [c["name"] for c in fails],
        "first_message": fails[0]["message"] if fails else None,
    }


def reimport_faults(cfg: BenchConfig) -> list[dict[str, Any]]:
    """Re-import F5 and F1 the same way as the 1× export and record what psql says, next to the
    rows the source table held (F0's sealed manifest) and ExportGuard's verdict from verify-all."""
    gallery = json.loads((REPORTS / "faults.json").read_text())
    records = {r["fault"]: r for r in gallery["faults"]}
    source_rows = gallery["source_manifest"]["rows"]
    out = []
    for fault, name in FAULT_REIMPORTS:
        path = EXPORTS / name
        schema = records[fault]["table"].split(".")[0]
        r = _load(cfg.restore_db, schema, path)
        r |= {"fault": fault, "file": path.relative_to(ROOT).as_posix()}
        r |= {"source_rows": source_rows, "eguard": _matrix_row(path)}
        out.append(r)
    return out


def _table_bytes(schema: str) -> int:
    sql = "SELECT pg_total_relation_size(format('%I.transactions', :'schema'));"
    return int(run_sql(sql, {"schema": schema}))


def run_scale(cfg: BenchConfig, scale: int, do_reimport: bool) -> dict[str, Any]:
    sim = load_sim_config()
    rows = scaled_rows(sim, scale)
    out = BENCH_DIR / f"s{scale}x.sql.gz"
    manifest = BENCH_DIR / f"s{scale}x.manifest.json"
    BENCH_DIR.mkdir(parents=True, exist_ok=True)
    try:
        start = time.perf_counter()
        seed(sim, rows, cfg.schema_)
        seed_s = time.perf_counter() - start
        table_bytes = _table_bytes(cfg.schema_)
        start = time.perf_counter()
        hardened_export(f"{cfg.schema_}.{sim.table}", out, manifest)
        export_s = time.perf_counter() - start
        run = measure(out, ("--manifest", str(manifest)))
        run |= {"scale": scale, "rows": rows, "seed_s": seed_s, "export_s": export_s}
        run |= {"table_bytes": table_bytes}
        if do_reimport:
            run["reimport"] = reimport(cfg, out)
        return run
    finally:
        for p in (out, manifest, out.with_name(out.name + ".FAILED")):
            p.unlink(missing_ok=True)
        manifest.with_name(manifest.name + ".FAILED").unlink(missing_ok=True)
        drop_schema(cfg.schema_)


def _first_line(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    return ((proc.stdout or proc.stderr).strip().splitlines() or ["unknown"])[0]


def env_info() -> dict[str, str]:
    mem_kib = next(
        int(line.split()[1])
        for line in Path("/proc/meminfo").read_text().splitlines()
        if line.startswith("MemTotal:")
    )
    return {
        "cpu": f"{_cpu()} · {os.cpu_count()} CPUs",
        "memory": f"{mem_kib / (1 << 20):.1f} GiB RAM",
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "postgres": _admin("SHOW server_version;"),
        "pg_dump": _first_line([*COMPOSE, "exec", "-T", "db", "pg_dump", "--version"]),
        "pigz": _first_line(["pigz", "--version"]),
        "gzip": _first_line(["gzip", "--version"]),
        "commit": _commit(),
    }


def _row(r: dict[str, Any]) -> str:
    mb_c, mb_u, wall = r["compressed_bytes"] / 1e6, r["uncompressed_bytes"] / 1e6, r["wall_s"]
    layers = " ".join(f"L{k}:{v}" for k, v in sorted(r["layers"].items()))
    return (
        f"| {r['scale']}× | {r['rows']:,} | {r['table_bytes'] / 1e6:,.1f} MB | {mb_c:,.1f} MB | "
        f"{mb_u:,.1f} MB | {r['export_s']:.1f} s | {wall:.1f} s | {mb_c / wall:.1f} | "
        f"{mb_u / wall:.1f} | {r['peak_rss_mib']:.1f} MiB | {r['l5_sample_n']} | {layers} | "
        f"{r['verdict']} RAL {r['ral']} (exit {r['exit']}) |"
    )


def _reimport_lines(runs: list[dict[str, Any]]) -> list[str]:
    done = [r for r in runs if "reimport" in r]
    if not done:
        return ["Full re-import: not run (its scale was not reached)."]
    r = done[0]
    ri = r["reimport"]
    return [
        f"| {r['scale']}× ({r['rows']:,} rows, {r['compressed_bytes'] / 1e6:,.1f} MB) | "
        f"{ri['wall_s']:.1f} s | {ri['db_bytes'] / 1e6:,.1f} MB | {ri['rows']:,} | "
        f"{r['wall_s']:.1f} s | {ri['wall_s'] / r['wall_s']:.1f}× |",
    ]


def to_markdown(
    runs: list[dict[str, Any]],
    env: dict[str, str],
    stopped: str | None,
    when: datetime,
    faults: list[dict[str, Any]] | None = None,
) -> str:
    lines = [
        f"## Scale benchmark: verify L1–L5 vs full re-import ({when:%Y-%m-%d %H:%M} UTC)",
        "",
        f"`bench/scale.py` · commit {env['commit']}",
        "",
        f"- Machine: {env['cpu']} · {env['memory']} · {env['os']}",
        f"- Versions: Python {env['python']} · PostgreSQL {env['postgres']} · {env['pg_dump']} "
        f"· {env['pigz']} · {env['gzip']}",
        "",
        "| scale | rows | table in DB | compressed | uncompressed | hardened export | verify | "
        "compressed MB/s | uncompressed MB/s | peak RSS | L5 sample | layers | verdict |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|",
        *(_row(r) for r in runs),
        "",
    ]
    if stopped:
        lines += [f"**Stopped early:** {stopped}", ""]
    lines += [
        "| full re-import of | re-import wall | DB disk used | rows loaded | verify wall | "
        "re-import ÷ verify |",
        "|---|---:|---:|---:|---:|---:|",
        *_reimport_lines(runs),
        "",
        "verify = `eguard verify --json FILE --manifest MANIFEST` with SCRATCH_DSN set (L5 drill "
        "included). Peak RSS comes from wait4() on that process. 'hardened export' is "
        "`scripts/export_with_manifest.sh` (pg_dump | pigz -6 + manifest-build, then its own "
        "verify). 'table in DB' is pg_total_relation_size (in the Docker volume, outside the "
        "project disk budget). Each scale's export, manifest and schema were deleted before the "
        "next scale. The re-import DB was dropped afterwards.",
        "",
        "Reproduce: `make up && make bench` (needs `.env` with PG_DSN, SCRATCH_DSN, "
        "MANIFEST_HMAC_KEY; scales and disk budget in `config/sim.yaml` `bench:`; the fault "
        "re-imports need `make faults verify-all` first).",
        "",
    ]
    if faults:
        lines += _proves_lines(runs, faults)
    return "\n".join(lines)


def _proves_lines(runs: list[dict[str, Any]], faults: list[dict[str, Any]]) -> list[str]:
    lines = [
        "### What re-import proves vs what ExportGuard proves",
        "",
        "Each fault file was re-imported the same way as the 1× export (`gzip -dc | psql -v "
        "ON_ERROR_STOP=1` into a fresh throwaway database, dropped afterwards). ExportGuard's "
        "verdict is from `make verify-all` (`data/reports/verify_all.json`).",
        "",
        "| export | psql exit | rows loaded / rows in source table | first psql error | "
        "ExportGuard | failing checks |",
        "|---|---:|---:|---|---|---|",
    ]
    for f in faults:
        loaded = "table not created" if f["rows"] is None else f"{f['rows']:,}"
        eg = f["eguard"]
        lines.append(
            f"| {f['fault']} `{f['file']}` | {f['psql_exit']} | {loaded} / {f['source_rows']:,} | "
            f"{'`' + f['psql_error'] + '`' if f['psql_error'] else '–'} | "
            f"{eg['verdict']} (exit {eg['exit']}) | {', '.join(eg['fails']) or '–'} |"
        )
    lines.append("")
    for f in faults:
        eg = f["eguard"]
        said = "reported success" if f["psql_exit"] == 0 else f"failed (exit {f['psql_exit']})"
        lines.append(
            f"- **{f['fault']}**: psql {said} and loaded {f['rows'] or 0:,} of "
            f'{f["source_rows"]:,} rows. ExportGuard: {eg["verdict"]}, "{eg["first_message"]}"'
        )
    done = [r for r in runs if "reimport" in r]
    if done and done[0].get("l5_scratch_bytes") is not None:
        r = done[0]
        lines.append(
            f"- **Space**: the full re-import of {r['scale']}× used "
            f"{r['reimport']['db_bytes'] / 1e6:,.1f} MB of database space; ExportGuard's L5 drill "
            f"on the same file restored a {r['l5_sample_n']:,}-row sample into "
            f"{r['l5_scratch_bytes'] / (1 << 20):,.1f} MiB of scratch."
        )
    lines += [
        "- A re-import shows whether the bytes load; it has no record of what the source held, "
        "so a load that succeeds says nothing about missing or changed rows. ExportGuard's L4 "
        "compares against the signed manifest written at export time.",
        "- Speed: only the times in the tables above were measured; no other speed claim is made.",
        "",
    ]
    return lines


def _unit_bytes(runs: list[dict[str, Any]]) -> int:
    if runs:
        return round(runs[0]["compressed_bytes"] / runs[0]["scale"])
    return V1.stat().st_size if V1.is_file() else FALLBACK_UNIT


def main() -> None:
    cfg = load_bench_config()
    env = env_info()
    runs: list[dict[str, Any]] = []
    stopped = None
    for scale in cfg.scales:
        project, est = project_bytes(), estimate_bytes(scale, _unit_bytes(runs))
        if not fits(project, est, cfg.disk_budget_bytes):
            stopped = (
                f"{scale}× was skipped: its export is estimated at {est / 1e6:,.0f} MB and the "
                f"project is already {project / 1e6:,.0f} MB, over the "
                f"{cfg.disk_budget_bytes / 1e6:,.0f} MB disk budget."
            )
            print(stopped, file=sys.stderr)
            break
        print(f"scale {scale}×: project {project / 1e6:,.0f} MB + est. {est / 1e6:,.0f} MB")
        runs.append(run_scale(cfg, scale, scale == cfg.reimport_scale))
    faults = None
    if (REPORTS / "faults.json").is_file() and (REPORTS / "verify_all.json").is_file():
        faults = reimport_faults(cfg)
    else:
        print("no fault gallery/matrix: fault re-imports skipped", file=sys.stderr)
    text = to_markdown(runs, env, stopped, datetime.now(UTC), faults)
    print(text)
    old = RESULTS.read_text().removeprefix(HEADER) if RESULTS.exists() else ""
    RESULTS.write_text(HEADER + text + "\n" + old)


if __name__ == "__main__":
    main()
