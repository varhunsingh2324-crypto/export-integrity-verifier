from typer.testing import CliRunner

import eguard
from eguard.cli import app

runner = CliRunner()


def test_package_has_version() -> None:
    assert eguard.__version__


def test_cli_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert eguard.__version__ in result.stdout
