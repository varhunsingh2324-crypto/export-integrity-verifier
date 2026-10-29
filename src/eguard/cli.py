"""ExportGuard command-line interface."""

import json
import os
import platform
import shutil
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from eguard import __version__
from eguard.models import Verdict

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
