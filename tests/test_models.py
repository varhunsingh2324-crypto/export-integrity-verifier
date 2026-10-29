import pytest
from pydantic import ValidationError

from eguard.models import CheckResult, Severity, Status, Verdict


@pytest.mark.parametrize(
    ("verdict", "code"),
    [
        (Verdict.VERIFIED, 0),
        (Verdict.SUSPECT, 1),
        (Verdict.CORRUPT, 2),
        (Verdict.TOOL_ERROR, 3),
    ],
)
def test_verdict_exit_codes(verdict: Verdict, code: int) -> None:
    assert verdict.exit_code == code


def _check(**overrides: object) -> CheckResult:
    fields: dict[str, object] = {
        "layer": 1,
        "name": "gzip_crc",
        "status": Status.PASS,
        "severity": Severity.CRITICAL,
        "evidence": {"crc32": "0x1234abcd"},
        "message": "CRC32 matches trailer",
    }
    fields.update(overrides)
    return CheckResult(**fields)


def test_check_result_valid() -> None:
    check = _check()
    assert check.evidence["crc32"] == "0x1234abcd"


@pytest.mark.parametrize("message", ["", "   "])
def test_check_result_requires_message(message: str) -> None:
    with pytest.raises(ValidationError):
        _check(message=message)


@pytest.mark.parametrize("layer", [0, 6])
def test_check_result_layer_range(layer: int) -> None:
    with pytest.raises(ValidationError):
        _check(layer=layer)
