import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from eguard.cli import app
from eguard.config import load_policy
from eguard.manifest import (
    ManifestError,
    build_from_chunks,
    hmac_key_from_env,
    load,
    save,
    signature_ok,
)
from eguard.models import Manifest
from tests import pgdump

POLICY = load_policy()
KEY = b"test-hmac-key"
DATA = pgdump.dump_bytes(300)
runner = CliRunner()


def chunks(data: bytes, size: int = 997) -> list[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)]


@pytest.fixture
def manifest() -> Manifest:
    return build_from_chunks(chunks(DATA), POLICY, KEY)


def test_build_records_tables_stream_and_signs(manifest: Manifest) -> None:
    assert manifest.dump_complete and manifest.chunk_rows == POLICY["l4"]["chunk_rows"]
    (t,) = manifest.tables
    assert t.table == "public.transactions" and t.count == 300 and t.closed
    assert manifest.stream.bytes == len(DATA)
    assert manifest.stream.lines == DATA.count(b"\n")
    assert signature_ok(manifest, KEY)


def test_build_is_independent_of_chunking(manifest: Manifest) -> None:
    other = build_from_chunks(chunks(DATA, 1), POLICY, KEY)
    assert other.tables == manifest.tables and other.stream == manifest.stream


def test_roundtrip_through_disk_keeps_signature(tmp_path: Path, manifest: Manifest) -> None:
    path = tmp_path / "m.json"
    save(manifest, path)
    loaded = load(path)
    assert isinstance(loaded, Manifest) and loaded == manifest
    assert signature_ok(loaded, KEY)
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize(
    "path,value",
    [
        (("tables", 0, "count"), 299),
        (("tables", 0, "sum64"), "0" * 16),
        (("tables", 0, "chunks", 0, "digest"), "f" * 32),
        (("tables", 0, "table"), "public.other"),
        (("dump_complete",), False),
        (("stream", "sha256"), "0" * 64),
        (("chunk_rows",), 7),
    ],
)
def test_any_tampered_field_fails_signature(
    tmp_path: Path, manifest: Manifest, path: tuple, value: object
) -> None:
    doc = json.loads(manifest.model_dump_json())
    target = doc
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    tampered = tmp_path / "t.json"
    tampered.write_text(json.dumps(doc))
    loaded = load(tampered)
    assert isinstance(loaded, Manifest)
    assert not signature_ok(loaded, KEY)


def test_wrong_key_and_unsigned_fail(manifest: Manifest) -> None:
    assert not signature_ok(manifest, b"other-key")
    assert not signature_ok(manifest.model_copy(update={"signature": None}), KEY)


def test_unparseable_manifest_returns_reason(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"format_version": 1, "tables": [')
    assert isinstance(load(bad), str)
    bad.write_text('{"format_version": 1}')
    assert "tool" in load(bad)


def test_missing_manifest_file_raises_os_error(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        load(tmp_path / "nope.json")


def test_hmac_key_from_env() -> None:
    assert hmac_key_from_env({"MANIFEST_HMAC_KEY": "abc"}) == b"abc"
    with pytest.raises(ManifestError, match="MANIFEST_HMAC_KEY"):
        hmac_key_from_env({})


# -- eguard manifest-build ----------------------------------------------------------------
ENV = {"MANIFEST_HMAC_KEY": KEY.decode()}


def test_cli_manifest_build_from_stdin_to_file(tmp_path: Path) -> None:
    out = tmp_path / "v.manifest.json"
    result = runner.invoke(app, ["manifest-build", "--out", str(out)], input=DATA, env=ENV)
    assert result.exit_code == 0, result.output
    m = load(out)
    assert isinstance(m, Manifest) and signature_ok(m, KEY) and m.tables[0].count == 300
    assert result.stdout == ""  # summary goes to stderr so stdout stays pipe-clean


def test_cli_manifest_build_to_stdout(manifest: Manifest) -> None:
    result = runner.invoke(app, ["manifest-build"], input=DATA, env=ENV)
    assert result.exit_code == 0, result.stderr
    m = Manifest.model_validate_json(result.stdout)
    assert m.tables == manifest.tables and signature_ok(m, KEY)


def test_cli_manifest_build_incomplete_dump_exits_1(tmp_path: Path) -> None:
    out = tmp_path / "k.json"
    result = runner.invoke(
        app, ["manifest-build", "--out", str(out)], input=pgdump.killed_at(300, 120), env=ENV
    )
    assert result.exit_code == 1
    m = load(out)
    assert isinstance(m, Manifest) and not m.dump_complete and m.tables[0].count == 120
    assert "incomplete" in result.stderr


def test_cli_manifest_build_without_key_is_tool_error() -> None:
    result = runner.invoke(app, ["manifest-build"], input=DATA, env={"MANIFEST_HMAC_KEY": ""})
    assert result.exit_code == 3
    assert "MANIFEST_HMAC_KEY" in result.stderr


def test_cli_manifest_build_warns_on_placeholder_key(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["manifest-build", "--out", str(tmp_path / "m.json")],
        input=DATA,
        env={"MANIFEST_HMAC_KEY": "change-me"},
    )
    assert result.exit_code == 0
    assert "placeholder" in result.stderr
