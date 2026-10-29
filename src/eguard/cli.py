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

from eguard import __version__
from eguard.config import load_policy
from eguard.models import Status, Verdict, VerifyReport

app = typer.Typer(help="ExportGuard: verify compressed database exports without re-importing.")
console = Console()

TOOLS = ("gzip", "pigz", "compress")


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
    style = VERDICT_STYLE.get(report.verdict, "red")
    console.print(f"verdict: [bold {style}]{report.verdict}[/] (RAL {report.ral})")


@app.command()
def verify(
    path: Annotated[Path, typer.Argument(help="Compressed export (.gz or .Z; format from magic).")],
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Verify an export in one streaming pass. Exit: 0 VERIFIED, 1 SUSPECT, 2 CORRUPT, 3 error."""
    from eguard.stream import LineTooLong
    from eguard.verify import verify_file

    try:
        report = verify_file(path, load_policy())
    except (OSError, LineTooLong) as exc:
        if as_json:
            typer.echo(json.dumps({"path": str(path), "verdict": "TOOL_ERROR", "error": str(exc)}))
        else:
            console.print(f"[red]tool error:[/] {exc}")
        raise typer.Exit(Verdict.TOOL_ERROR.exit_code) from exc
    if as_json:
        typer.echo(report.model_dump_json(indent=2))
    else:
        _print_report(report)
    raise typer.Exit(report.verdict.exit_code)
