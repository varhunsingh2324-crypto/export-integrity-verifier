import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from eguard.cli import app
from eguard.models import VerifyReport
from tests import pgdump
from tests.gzutil import member

# Hermetic: the Makefile exports SCRATCH_DSN from .env; these tests do not use a database.
runner = CliRunner(env={"SCRATCH_DSN": ""})
DATA = pgdump.dump_bytes(500)


def _file(tmp_path: Path, blob: bytes) -> Path:
    path = tmp_path / "export.gz"
    path.write_bytes(blob)
    return path


def test_verify_healthy_is_suspect_until_l4_l5(tmp_path: Path) -> None:
    result = runner.invoke(app, ["verify", str(_file(tmp_path, member(DATA)))])
    assert result.exit_code == 1, result.stdout
    assert "SUSPECT" in result.stdout and "l1_integrity" in result.stdout
    assert "RAL 3" in result.stdout


def test_verify_killed_export_names_table_and_row(tmp_path: Path) -> None:
    blob = member(pgdump.killed_at(500, 321))
    result = runner.invoke(app, ["verify", "--json", str(_file(tmp_path, blob))])
    assert result.exit_code == 2
    report = VerifyReport.model_validate_json(result.stdout)
    (c,) = [c for c in report.checks if c.name == "l2_complete"]
    assert "inside COPY public.transactions after row 321" in c.message


def test_verify_truncated_is_corrupt(tmp_path: Path) -> None:
    blob = member(DATA)
    result = runner.invoke(app, ["verify", "--json", str(_file(tmp_path, blob[:-20]))])
    assert result.exit_code == 2
    report = VerifyReport.model_validate_json(result.stdout)
    assert report.verdict == "CORRUPT"


def test_verify_missing_file_is_tool_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["verify", "--json", str(tmp_path / "nope.gz")])
    assert result.exit_code == 3
    assert json.loads(result.stdout)["verdict"] == "TOOL_ERROR"


def _signed_manifest(tmp_path: Path, key: str) -> Path:
    out = tmp_path / "m.json"
    result = runner.invoke(
        app, ["manifest-build", "--out", str(out)], input=DATA, env={"MANIFEST_HMAC_KEY": key}
    )
    assert result.exit_code == 0, result.stderr
    return out


def test_verify_with_manifest_reaches_ral_4(tmp_path: Path) -> None:
    env = {"MANIFEST_HMAC_KEY": "k1"}
    m = _signed_manifest(tmp_path, "k1")
    path = str(_file(tmp_path, member(DATA)))
    seal = ["manifest-seal", str(m), "--compressed", path, "--snapshot", "00000003-00000001-1"]
    seal += ["--taken-at", "2026-10-29 10:00:00+00", "--db-count", "public.transactions=500"]
    assert runner.invoke(app, seal, env=env).exit_code == 0
    result = runner.invoke(app, ["verify", "--manifest", str(m), path], env=env)
    assert result.exit_code == 1, result.stdout  # SUSPECT only because L5 has no scratch DB
    assert "RAL 4" in result.stdout and "l4_fingerprint" in result.stdout


def test_verify_with_tampered_manifest_is_corrupt(tmp_path: Path) -> None:
    m = _signed_manifest(tmp_path, "k1")
    doc = json.loads(m.read_text())
    doc["tables"][0]["count"] += 1
    m.write_text(json.dumps(doc))
    path = str(_file(tmp_path, member(DATA)))
    result = runner.invoke(
        app, ["verify", "--json", "--manifest", str(m), path], env={"MANIFEST_HMAC_KEY": "k1"}
    )
    assert result.exit_code == 2
    report = VerifyReport.model_validate_json(result.stdout)
    (c,) = [c for c in report.checks if c.name == "l4_manifest_signature"]
    assert c.status == "FAIL"


def test_verify_manifest_without_key_is_tool_error(tmp_path: Path) -> None:
    m = _signed_manifest(tmp_path, "k1")
    path = str(_file(tmp_path, member(DATA)))
    result = runner.invoke(
        app, ["verify", "--json", "--manifest", str(m), path], env={"MANIFEST_HMAC_KEY": ""}
    )
    assert result.exit_code == 3
    assert "MANIFEST_HMAC_KEY" in json.loads(result.stdout)["error"]


@pytest.mark.db
def test_verify_cli_with_scratch_reaches_ral_5(tmp_path: Path) -> None:
    scratch = os.environ.get("SCRATCH_DSN")
    if not scratch:
        pytest.skip("SCRATCH_DSN not set (copy .env.example to .env and run `make up`)")
    env = {"MANIFEST_HMAC_KEY": "k1"}
    m = _signed_manifest(tmp_path, "k1")
    path = str(_file(tmp_path, member(DATA)))
    seal = ["manifest-seal", str(m), "--compressed", path, "--snapshot", "00000003-00000001-1"]
    seal += ["--taken-at", "2026-10-29 10:00:00+00", "--db-count", "public.transactions=500"]
    assert runner.invoke(app, seal, env=env).exit_code == 0
    args = ["verify", "--manifest", str(m), "--scratch-dsn", scratch, "--seed", "3", path]
    result = runner.invoke(app, args, env=env)
    assert result.exit_code == 0, result.stdout
    assert "VERIFIED" in result.stdout and "RAL 5" in result.stdout
    assert "confidence:" in result.stdout and "All 500 rows" in result.stdout


def test_verify_without_manifest_explains_missing_evidence(tmp_path: Path) -> None:
    result = runner.invoke(app, ["verify", str(_file(tmp_path, member(DATA)))])
    assert result.exit_code == 1
    assert "missing evidence:" in result.stdout
    assert "L4 l4_manifest SKIP: no manifest" in result.stdout
    assert "L5 l5_restore SKIP: no scratch database" in result.stdout


# -- rule 7 on every command --------------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [["verify", "--nope", "x.gz"], ["verify"], ["no-such-command"], ["manifest-seal"]],
)
def test_usage_errors_are_tool_errors_not_corrupt(args: list[str]) -> None:
    assert runner.invoke(app, args).exit_code == 3  # click alone would exit 2 (= CORRUPT)


def test_crash_is_tool_error_not_suspect(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr("eguard.verify.verify_file", boom)
    result = runner.invoke(app, ["verify", str(_file(tmp_path, member(DATA)))])
    assert result.exit_code == 3  # an uncaught exception would exit 1 (= SUSPECT)


def test_verify_json_has_layers_and_exit_code(tmp_path: Path) -> None:
    blob = member(pgdump.killed_at(500, 321))
    result = runner.invoke(app, ["verify", "--json", str(_file(tmp_path, blob))])
    report = VerifyReport.model_validate_json(result.stdout)
    assert report.exit_code == result.exit_code == 2
    assert [(lr.layer, lr.status) for lr in report.layers][:2] == [(1, "PASS"), (2, "FAIL")]
    assert "l2_complete FAIL" in report.layers[1].reason


# -- verify-all ---------------------------------------------------------------------------------


def _gallery(tmp_path: Path) -> tuple[Path, Path, Path]:
    exports, manifests = tmp_path / "exports", tmp_path / "manifests"
    (exports / "sub").mkdir(parents=True)
    manifests.mkdir()
    healthy = exports / "sub" / "good.sql.gz"
    healthy.write_bytes(member(DATA))
    (exports / "cut.sql.gz").write_bytes(member(DATA)[:-20])
    (exports / "left.sql.gz.FAILED").write_bytes(b"ignored")
    m = _signed_manifest(tmp_path, "k1")
    gallery = tmp_path / "faults.json"
    gallery.write_text(
        json.dumps({"faults": [{"fault": "F0", "path": str(healthy), "manifest": str(m)}]})
    )
    return exports, manifests, gallery


def test_verify_all_matrix_and_worst_exit(tmp_path: Path) -> None:
    exports, manifests, gallery = _gallery(tmp_path)
    out = tmp_path / "all.json"
    args = ["verify-all", str(exports), "--gallery", str(gallery), "--manifests", str(manifests)]
    result = runner.invoke(
        app, [*args, "--json", "--out", str(out)], env={"MANIFEST_HMAC_KEY": "k1"}
    )
    assert result.exit_code == 2  # worst row: the truncated file
    body = json.loads(result.stdout)
    assert body == json.loads(out.read_text()) and body["exit_code"] == 2
    rows = {Path(r["path"]).name: r for r in body["rows"]}
    assert set(rows) == {"cut.sql.gz", "good.sql.gz"}  # .FAILED leftovers are not exports
    good, cut = rows["good.sql.gz"], rows["cut.sql.gz"]
    assert good["label"] == "F0" and good["manifest"] and good["gzip_t"] == 0
    # Unsealed manifest: no snapshot counts / compressed sha (SKIP) next to PASSes -> L4 WARN.
    assert [lr["status"] for lr in good["report"]["layers"]][:4] == ["PASS"] * 3 + ["WARN"]
    assert cut["label"] == "cut.sql.gz" and cut["manifest"] is None and cut["gzip_t"] != 0
    assert cut["report"]["verdict"] == "CORRUPT"
    human = runner.invoke(app, args, env={"MANIFEST_HMAC_KEY": "k1"})
    assert human.exit_code == 2 and "F0" in human.stdout and "CORRUPT" in human.stdout


def test_verify_all_manifest_without_key_is_row_tool_error(tmp_path: Path) -> None:
    exports, manifests, gallery = _gallery(tmp_path)
    args = ["verify-all", str(exports), "--gallery", str(gallery), "--manifests", str(manifests)]
    result = runner.invoke(app, [*args, "--json"], env={"MANIFEST_HMAC_KEY": ""})
    assert result.exit_code == 3
    rows = {Path(r["path"]).name: r for r in json.loads(result.stdout)["rows"]}
    assert rows["good.sql.gz"]["error"] and rows["cut.sql.gz"]["report"]["verdict"] == "CORRUPT"


def test_verify_all_empty_dir_is_tool_error(tmp_path: Path) -> None:
    assert runner.invoke(app, ["verify-all", str(tmp_path)]).exit_code == 3
