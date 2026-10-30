"""ExportGuard command-line interface."""

import json
import os
import platform
import shutil
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table
from typer.core import TyperGroup

from eguard import __version__
from eguard.config import load_policy
from eguard.models import Status, Verdict, VerifyReport

console = Console()
err = Console(stderr=True)


class _Group(TyperGroup):
    """Rule 7 on every command: 0-2 are verdicts, so anything that is not one exits 3. Click would
    exit 2 (= CORRUPT) on a usage error and 1 (= SUSPECT) on a crash or Ctrl-C."""

    def make_context(self, *args: Any, **kwargs: Any) -> Any:
        try:
            return super().make_context(*args, **kwargs)
        except typer.TyperException as exc:  # usage errors before the subcommand
            exc.exit_code = Verdict.TOOL_ERROR.exit_code
            raise

    def invoke(self, ctx: Any) -> Any:
        try:
            return super().invoke(ctx)
        except typer.Exit:
            raise
        except typer.TyperException as exc:  # usage errors, BadParameter, unknown command
            exc.exit_code = Verdict.TOOL_ERROR.exit_code
            raise
        except (typer.Abort, KeyboardInterrupt, EOFError) as exc:
            err.print("[red]tool error:[/] interrupted")
            raise typer.Exit(Verdict.TOOL_ERROR.exit_code) from exc
        except Exception as exc:
            err.print_exception()
            raise typer.Exit(Verdict.TOOL_ERROR.exit_code) from exc


app = typer.Typer(
    cls=_Group, help="ExportGuard: verify compressed database exports without re-importing."
)

TOOLS = ("gzip", "pigz", "compress")
DATA = Path(__file__).resolve().parents[2] / "data"


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"eguard {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version_callback, is_eager=True)
    ] = False,
) -> None:
    """ExportGuard CLI."""


def _db_check(dsn: str | None) -> dict[str, Any]:
    if not dsn:
        return {"name": "postgres", "ok": False, "detail": "PG_DSN not set"}
    import psycopg

    try:
        with psycopg.connect(dsn, connect_timeout=5) as conn:
            version = conn.execute("SHOW server_version").fetchone()[0]
            scratch = conn.execute(
                "SELECT 1 FROM information_schema.schemata WHERE schema_name = 'scratch'"
            ).fetchone()
    except psycopg.Error as exc:
        return {"name": "postgres", "ok": False, "detail": f"unreachable: {exc}".strip()}
    if scratch is None:
        return {"name": "postgres", "ok": False, "detail": f"{version}, scratch schema missing"}
    return {"name": "postgres", "ok": True, "detail": f"{version}, scratch schema present"}


def _environment_checks() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = [
        {"name": "python", "ok": True, "detail": platform.python_version()},
    ]
    for tool in TOOLS:
        path = shutil.which(tool)
        checks.append({"name": tool, "ok": path is not None, "detail": path or "not on PATH"})
    checks.append(_db_check(os.environ.get("PG_DSN")))
    return checks


@app.command()
def doctor(
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Check that the toolchain and database needed by ExportGuard are available."""
    checks = _environment_checks()
    all_ok = all(c["ok"] for c in checks)
    if as_json:
        typer.echo(json.dumps({"ok": all_ok, "checks": checks}, indent=2))
    else:
        table = Table(title="eguard doctor")
        for column in ("check", "status", "detail"):
            table.add_column(column)
        for c in checks:
            status = "[green]OK[/]" if c["ok"] else "[red]MISSING[/]"
            table.add_row(c["name"], status, c["detail"])
        console.print(table)
    raise typer.Exit(0 if all_ok else Verdict.TOOL_ERROR.exit_code)


STATUS_STYLE = {Status.PASS: "green", Status.FAIL: "red", Status.WARN: "yellow", Status.SKIP: "dim"}
VERDICT_STYLE = {Verdict.VERIFIED: "green", Verdict.SUSPECT: "yellow", Verdict.CORRUPT: "red"}


def _print_report(report: VerifyReport) -> None:
    table = Table(title=f"eguard verify {report.path}")
    for column in ("layer", "check", "status", "detail"):
        table.add_column(column)
    for c in report.checks:
        style = STATUS_STYLE[c.status]
        table.add_row(f"L{c.layer}", c.name, f"[{style}]{c.status}[/]", c.message)
    console.print(table)
    layers = " · ".join(
        f"L{lr.layer} [{STATUS_STYLE[lr.status]}]{lr.status}[/]" for lr in report.layers
    )
    console.print(f"layers: {layers}")
    for c in report.checks:
        for statement in c.evidence.get("confidence_statements", []):
            console.print(f"[bold]confidence:[/] {statement}")
    style = VERDICT_STYLE.get(report.verdict, "red")
    console.print(f"verdict: [bold {style}]{report.verdict}[/] (RAL {report.ral})")
    if report.reasons:
        why = "missing evidence" if report.verdict == Verdict.SUSPECT else "failed"
        console.print(f"{why}:")
        for reason in report.reasons:
            console.print(f"  - {reason}", markup=False)


def _tool_error(path: str, exc: Exception, as_json: bool) -> typer.Exit:
    if as_json:
        code = Verdict.TOOL_ERROR.exit_code
        body = {"path": path, "verdict": "TOOL_ERROR", "exit_code": code, "error": str(exc)}
        typer.echo(json.dumps(body))
    else:
        console.print(f"[red]tool error:[/] {exc}")
    return typer.Exit(Verdict.TOOL_ERROR.exit_code)


@app.command()
def verify(
    path: Annotated[Path, typer.Argument(help="Compressed export (.gz or .Z; format from magic).")],
    manifest: Annotated[
        Path | None,
        typer.Option(help="Signed manifest from export time; enables L4 (key: MANIFEST_HMAC_KEY)."),
    ] = None,
    scratch_dsn: Annotated[
        str | None,
        typer.Option(envvar="SCRATCH_DSN", help="Database for the L5 sampled restore drill."),
    ] = None,
    dsn: Annotated[
        str | None,
        typer.Option(help="Live source database: compare the sample by PK (differences = drift)."),
    ] = None,
    seed: Annotated[
        int | None, typer.Option(help="L5 sample seed (default: random, recorded in the report).")
    ] = None,
    report_dir: Annotated[
        Path | None,
        typer.Option(help="Also write verify_<name>.json and .html (self-contained) here."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Verify an export in one streaming pass. Exit: 0 VERIFIED, 1 SUSPECT, 2 CORRUPT, 3 error."""
    from eguard.manifest import ManifestError, hmac_key_from_env
    from eguard.stream import LineTooLong
    from eguard.verify import verify_file

    try:
        key = hmac_key_from_env() if manifest is not None else None
        report = verify_file(
            path,
            load_policy(),
            manifest,
            key,
            scratch_dsn=scratch_dsn or None,
            source_dsn=dsn or None,
            seed=seed,
        )
    except (OSError, LineTooLong, ManifestError) as exc:
        raise _tool_error(str(path), exc, as_json) from exc
    if as_json:
        typer.echo(report.model_dump_json(indent=2))
    else:
        _print_report(report)
    if report_dir is not None:
        from eguard.matrix import report_stem

        _write_reports(report, report_dir, report_stem(path, path.parent))
    raise typer.Exit(report.verdict.exit_code)


def _write_reports(
    report: VerifyReport, out_dir: Path, stem: str, gzip_t: int | None = None
) -> None:
    from eguard.report.html import write_reports

    json_path, html_path = write_reports(report, out_dir, stem, gzip_t=gzip_t)
    err.print(f"report: {json_path} + {html_path.name}")


@app.command("report")
def report_cmd(
    report_json: Annotated[Path, typer.Argument(help="A saved `verify --json` report.")],
    out: Annotated[Path | None, typer.Option(help="HTML to write (default: same name).")] = None,
) -> None:
    """Re-render the self-contained HTML from a saved JSON report. Exit: 0 written; 3 error."""
    from pydantic import ValidationError

    from eguard.report.html import render_html

    try:
        report = VerifyReport.model_validate_json(report_json.read_text())
        target = out or report_json.with_suffix(".html")
        target.write_text(render_html(report), encoding="utf-8")
    except (OSError, ValidationError) as exc:
        err.print(f"[red]tool error:[/] {exc}")
        raise typer.Exit(Verdict.TOOL_ERROR.exit_code) from exc
    err.print(f"report: {target}")


SHORT_FACTOR = {
    "rows": "rows R",
    "width": "bytes/row W",
    "data": "data ratio C_fixed",
    "compressor": "compressor E=C/C_fixed",
    "ratio": "ratio C (=C_fixed×E)",
}


def _bar(effect: float | None, biggest: float) -> str:
    if effect is None:
        return ""
    style = "yellow" if effect >= 0 else "green"
    return f"[{style}]{'█' * round(12 * abs(effect) / biggest)}[/]"


def _print_explain(x: Any, top: int) -> None:
    from eguard.forensics import fmt_bytes, fmt_change, fmt_fraction, fmt_mib, fmt_ratio
    from eguard.report.html import HYPOTHESIS, _value

    d = x.decomposition
    console.print(f"[bold]eguard explain[/] {x.old.path} → {x.new.path}")
    for name, p in (("old", x.old), ("new", x.new)):
        xfl = f", XFL {p.xfl}" if p.xfl is not None else ""
        bad = f" [red]{p.container_error}[/]" if p.container_error else ""
        console.print(
            f"  {name}: {p.format} ({p.compressor}{xfl}, level hint {p.level_hint or 'none'}), "
            f"{fmt_bytes(p.compressed_bytes)} compressed, {fmt_bytes(p.decompressed_bytes)} "
            f"decompressed, {p.seconds:.1f} s{bad}",
            markup=bool(bad),
        )
    table = Table(title=f"S = R × W ÷ C  (C_fixed: deflate level {x.probe.level})")
    for column in ("factor", "old", "new", "change", "size effect", "waterfall"):
        left = column in ("factor", "waterfall")
        table.add_column(column, justify="left" if left else "right", no_wrap=True)
    biggest = max((abs(f.effect_ln) for f in d.factors if f.effect_ln is not None), default=0) or 1
    for f in d.factors:
        effect = fmt_change(f.size_effect) if f.size_effect is not None else ""
        old, new = _value(f.name, f.old), _value(f.name, f.new)
        bar = _bar(f.effect_ln, biggest)
        table.add_row(SHORT_FACTOR[f.name], old, new, fmt_change(f.change), effect, bar)
    table.add_row(
        "[bold]size S[/]",
        fmt_bytes(x.old.compressed_bytes),
        fmt_bytes(x.new.compressed_bytes),
        fmt_change(d.observed_change),
        fmt_change(d.product - 1),
        f"err {d.identity_error:.0e}",
    )
    console.print(table)
    p = x.probe
    ratios = (
        f"{fmt_ratio(p.old_ratio)} → {fmt_ratio(p.new_ratio)} ({fmt_change(p.probe_change)})"
        if p.old_ratio is not None and p.new_ratio is not None and p.probe_change is not None
        else "no data"
    )
    share = fmt_fraction(p.data_share) if p.data_share is not None else "n/a"
    console.print(
        f"probe: {fmt_mib(p.sample_bytes)} per stream, {p.compressor} level {p.level}, seed "
        f"{p.seed}: {ratios}; files {fmt_change(p.observed_change)}; probe keeps {share}",
        markup=False,
    )
    console.print(f"[bold]hypothesis:[/] {HYPOTHESIS[x.hypothesis]}")
    _print_columns(x, top)
    console.print("[bold]narrative:[/]")
    for sentence in x.narrative:
        console.print(f"  {sentence}", markup=False)


def _print_columns(x: Any, top: int) -> None:
    tables = sorted({c.table for c in x.columns if c.table is not None})
    title = f"columns by |Δ width| (top {top}" + (f", {tables[0]})" if len(tables) == 1 else ")")
    table = Table(title=title)
    heads = ("#", "column", "B/row", "Δ", "NULL", "bits/B", "Δbits/row")
    for column in heads:
        table.add_column(column, justify="left" if column == "column" else "right", no_wrap=True)
    for c in x.columns[:top]:
        name = c.column if c.table is None or len(tables) == 1 else f"{c.table}.{c.column}"
        nulls = (
            f"{c.old_null_fraction:.0%}→{c.new_null_fraction:.0%}"
            if c.old_null_fraction is not None and c.new_null_fraction is not None
            else "–"
        )
        ent = (
            f"{c.old_entropy:.2f}→{c.new_entropy:.2f}"
            if c.old_entropy is not None and c.new_entropy is not None
            else "–"
        )
        bits = f"{c.delta_bits:+.1f}" if c.delta_bits is not None else "–"
        widths = f"{c.old_width:.1f}→{c.new_width:.1f}"
        table.add_row(str(c.rank_width), name, widths, f"{c.delta_width:+.1f}", nulls, ent, bits)
    console.print(table)


@app.command()
def explain(
    old: Annotated[Path, typer.Argument(help="The earlier export (.gz or .Z).")],
    new: Annotated[Path, typer.Argument(help="The later export.")],
    reports: Annotated[
        Path, typer.Option(help="Where to look for each file's saved verify_*.json (reused).")
    ] = DATA / "reports",
    report_dir: Annotated[
        Path | None,
        typer.Option(help="Also write explain_<old>__<new>.json and .html (self-contained) here."),
    ] = None,
    probe_bytes: Annotated[
        int | None, typer.Option(min=1, help="Re-compress probe sample per file (policy default).")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Explain a compressed-size change as rows × bytes-per-row ÷ compression ratio, with a
    re-compress probe (compressor vs data) and a column drill-down. One streaming pass per file.

    Exit: 0 explained; 3 tool error. explain issues no verdict: run `eguard verify` for that."""
    from eguard.forensics import DecompositionError, explain_files
    from eguard.stream import LineTooLong

    policy = load_policy()
    if probe_bytes is not None:
        policy["explain"]["probe_bytes"] = probe_bytes
    top = policy["explain"]["top_columns"]
    try:
        for path in (old, new):
            if not path.is_file():
                raise FileNotFoundError(f"{path}: no such file")
        x = explain_files(old, new, policy, reports)
    except (OSError, LineTooLong, DecompositionError) as exc:
        raise _tool_error(f"{old} {new}", exc, as_json) from exc
    if as_json:
        typer.echo(x.model_dump_json(indent=2))
    else:
        _print_explain(x, top)
    if report_dir is not None:
        from eguard.matrix import explain_stem
        from eguard.report.html import write_explain_reports

        json_path, html_path = write_explain_reports(x, report_dir, explain_stem(old, new), top)
        err.print(f"report: {json_path} + {html_path.name}")
    raise typer.Exit(0)


@app.command("manifest-build")
def manifest_build(
    out: Annotated[
        Path | None, typer.Option(help="Write the manifest here (default: stdout).")
    ] = None,
) -> None:
    """Read a decompressed dump from stdin (e.g. behind `tee`) and write a signed manifest.

    Exit: 0 manifest written; 2 written, but the dump is incomplete (CORRUPT); 3 tool error."""
    from eguard.manifest import PLACEHOLDER_KEY, ManifestError, build_from_chunks, hmac_key_from_env
    from eguard.manifest import save as save_manifest
    from eguard.stream import LineTooLong

    policy = load_policy()
    stdin = typer.get_binary_stream("stdin")
    size = policy["stream"]["chunk_bytes"]
    try:
        key = hmac_key_from_env()
        m = build_from_chunks(iter(lambda: stdin.read(size), b""), policy, key)
        if out is None:
            typer.echo(m.model_dump_json(indent=2))
        else:
            save_manifest(m, out)
    except (OSError, LineTooLong, ManifestError) as exc:
        err.print(f"[red]tool error:[/] {exc}")
        raise typer.Exit(Verdict.TOOL_ERROR.exit_code) from exc
    if key == PLACEHOLDER_KEY.encode():
        err.print("[yellow]warning:[/] MANIFEST_HMAC_KEY is the .env.example placeholder")
    rows = sum(t.count for t in m.tables)
    chunks = sum(len(t.chunks) for t in m.tables)
    err.print(
        f"manifest: {len(m.tables)} table(s), {rows:,} rows, {chunks} chunk(s), "
        f"{m.stream.bytes:,} bytes, sha256 {m.stream.sha256[:16]}…"
    )
    if not m.dump_complete:
        err.print("[red]dump incomplete:[/] no completion marker or an unclosed COPY block")
        raise typer.Exit(Verdict.CORRUPT.exit_code)


def _db_counts(pairs: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for pair in pairs:
        table, sep, n = pair.rpartition("=")
        if not sep or not table or not n.isdigit():
            raise ValueError(f"--db-count wants schema.table=N, got {pair!r}")
        counts[table] = int(n)
    return counts


@app.command("manifest-seal")
def manifest_seal(
    manifest: Annotated[Path, typer.Argument(help="Manifest written by manifest-build.")],
    compressed: Annotated[Path, typer.Option(help="The finished compressed export.")],
    snapshot: Annotated[str, typer.Option(help="pg_export_snapshot() id pg_dump ran in.")],
    taken_at: Annotated[str, typer.Option(help="now() of the snapshot transaction.")],
    db_count: Annotated[
        list[str], typer.Option(help="schema.table=N, count(*) in that snapshot; repeatable.")
    ],
    compressor: Annotated[str, typer.Option(help="e.g. 'pigz -6'.")] = "unknown",
) -> None:
    """Add snapshot counts and the compressed sha256 to a signed manifest, then re-sign it.

    Exit: 0 sealed; 3 tool error (bad/unsigned manifest, missing key, unreadable file)."""
    from eguard.manifest import ManifestError, compressed_info, hmac_key_from_env, load, seal
    from eguard.manifest import save as save_manifest
    from eguard.models import SnapshotInfo

    try:
        counts = _db_counts(db_count)
        key = hmac_key_from_env()
        loaded = load(manifest)
        if isinstance(loaded, str):
            raise ManifestError(f"manifest unreadable: {loaded}")
        snap = SnapshotInfo(
            id=snapshot, isolation="repeatable read", taken_at=taken_at, counts=counts
        )
        info = compressed_info(compressed, compressor, load_policy()["stream"]["chunk_bytes"])
        save_manifest(seal(loaded, key, snap, info), manifest)
    except (OSError, ValueError, ManifestError) as exc:
        err.print(f"[red]tool error:[/] {exc}")
        raise typer.Exit(Verdict.TOOL_ERROR.exit_code) from exc
    err.print(f"sealed: snapshot {snapshot}, {info.bytes:,} compressed bytes, sha256 {info.sha256}")


EXPORT_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "export_with_manifest.sh"


@app.command("export")
def export(
    table: Annotated[list[str], typer.Option(help="schema.table to dump; repeatable.")],
    out: Annotated[Path, typer.Option(help="Compressed export to write (.sql.gz).")],
    manifest: Annotated[
        Path | None, typer.Option(help="Default: data/manifests/<name>.manifest.json.")
    ] = None,
) -> None:
    """Hardened export (scripts/export_with_manifest.sh), then `eguard verify` on the result.

    Exit: verify's own code (0 VERIFIED, 1 SUSPECT, 2 CORRUPT); 2 if any pipeline stage failed
    (output renamed .FAILED); 3 tool/config error."""
    import subprocess

    if not EXPORT_SCRIPT.is_file():
        err.print(f"[red]tool error:[/] {EXPORT_SCRIPT} not found")
        raise typer.Exit(Verdict.TOOL_ERROR.exit_code)
    cmd = [str(EXPORT_SCRIPT), *(["-m", str(manifest)] if manifest else []), str(out), *table]
    code = subprocess.run(cmd).returncode
    if code not in range(4):  # e.g. the script was killed by a signal: outcome unknown
        err.print(f"[red]tool error:[/] export script exited {code}")
        code = Verdict.TOOL_ERROR.exit_code
    raise typer.Exit(code)


def _gzip_t_cell(code: int | None) -> str:
    if code is None:
        return "[dim]n/a[/]"
    return "[green]OK[/]" if code == 0 else f"[red]FAIL ({code})[/]"


def _print_matrix(rows: list[Any], root: Path) -> None:
    table = Table(title=f"eguard verify-all {root}")
    for column in ("export", "fault", "gzip -t", "L1", "L2", "L3", "L4", "L5", "verdict", "exit"):
        table.add_column(column)
    for r in rows:
        name = str(Path(r.path).relative_to(root)) if Path(r.path).is_relative_to(root) else r.path
        if r.report is None:
            cells = ["–"] * 5 + [f"[red]TOOL_ERROR[/]: {r.error}"]
        else:
            cells = [f"[{STATUS_STYLE[lr.status]}]{lr.status}[/]" for lr in r.report.layers]
            style = VERDICT_STYLE.get(r.report.verdict, "red")
            cells.append(f"[{style}]{r.report.verdict}[/] (RAL {r.report.ral})")
        table.add_row(name, r.label, _gzip_t_cell(r.gzip_t), *cells, str(r.exit_code))
    console.print(table)


@app.command("verify-all")
def verify_all(
    root: Annotated[Path, typer.Argument(help="Directory of exports (searched recursively).")] = (
        DATA / "exports"
    ),
    gallery: Annotated[
        Path, typer.Option(help="Fault gallery record: fault IDs and their manifests.")
    ] = DATA / "reports" / "faults.json",
    manifests: Annotated[
        Path, typer.Option(help="Default manifest per export: <dir>/<name>.manifest.json.")
    ] = DATA / "manifests",
    scratch_dsn: Annotated[
        str | None,
        typer.Option(envvar="SCRATCH_DSN", help="Database for the L5 sampled restore drill."),
    ] = None,
    seed: Annotated[int | None, typer.Option(help="L5 sample seed (default: random).")] = None,
    out: Annotated[Path | None, typer.Option(help="Also write the JSON matrix here.")] = None,
    report_dir: Annotated[
        Path | None,
        typer.Option(help="Also write one verify_<name>.json + .html per export here."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Verify every .gz/.Z export under ROOT; print fault × (gzip -t, L1-L5, verdict).

    Exit: the worst row (3 tool error > 2 CORRUPT > 1 SUSPECT > 0 VERIFIED); 3 if none found."""
    from eguard.matrix import (
        discover,
        gallery_records,
        pairing,
        report_stem,
        verify_one,
        worst_exit,
    )

    policy = load_policy()
    known = gallery_records(gallery)
    rows = []
    for path in discover(root):
        label, manifest = pairing(path, known, manifests)
        row = verify_one(path, label, manifest, policy, scratch_dsn=scratch_dsn or None, seed=seed)
        if report_dir is not None and row.report is not None:
            _write_reports(row.report, report_dir, report_stem(path, root), row.gzip_t)
        rows.append(row)
    code = worst_exit(rows)
    body = {"root": str(root), "exit_code": code, "rows": [r.model_dump(mode="json") for r in rows]}
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(body, indent=2) + "\n")
    if as_json:
        typer.echo(json.dumps(body, indent=2))
    elif rows:
        _print_matrix(rows, root)
    else:
        err.print(f"[red]tool error:[/] no .gz/.Z exports under {root}")
    raise typer.Exit(code)
