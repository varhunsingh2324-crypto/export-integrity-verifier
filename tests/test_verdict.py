import pytest

from eguard.config import load_policy
from eguard.models import CheckResult, Severity, Status, Verdict
from eguard.verdict import build_report, decide, layer_results

POLICY = load_policy()


def chk(layer: int, status: Status, severity: Severity = Severity.CRITICAL) -> CheckResult:
    return CheckResult(
        layer=layer,
        name=f"l{layer}_{status.lower()}",
        status=status,
        severity=severity,
        evidence={},
        message=f"{status} at L{layer}",
    )


def all_pass() -> list[CheckResult]:
    return [chk(layer, Status.PASS) for layer in range(1, 6)]


def statuses(checks: list[CheckResult]) -> list[Status]:
    return [lr.status for lr in layer_results(checks)]


def test_all_pass_is_verified_ral_5() -> None:
    assert decide(all_pass(), POLICY) == (Verdict.VERIFIED, 5)
    assert statuses(all_pass()) == [Status.PASS] * 5


def test_layer_status_folding() -> None:
    checks = [
        chk(1, Status.PASS),
        chk(1, Status.FAIL),  # any FAIL wins
        chk(2, Status.PASS),
        chk(2, Status.SKIP),  # PASS + SKIP: partial evidence
        chk(3, Status.WARN, Severity.MAJOR),
        chk(3, Status.SKIP),
        chk(4, Status.SKIP),  # nothing ran but skips
    ]  # L5: no check at all
    assert statuses(checks) == [Status.FAIL, Status.WARN, Status.WARN, Status.SKIP, Status.SKIP]
    layers = layer_results(checks)
    assert layers[4].reason == "no check ran" and layers[4].checks == 0
    assert "l2_skip SKIP" in layers[1].reason and "l2_pass" not in layers[1].reason
    assert [lr.full_evidence for lr in layers] == [False] * 5


def test_critical_fail_is_corrupt_lesser_fail_is_suspect() -> None:
    critical = [*all_pass(), chk(4, Status.FAIL)]
    assert decide(critical, POLICY) == (Verdict.CORRUPT, 4)
    major = [*all_pass(), chk(4, Status.FAIL, Severity.MAJOR)]
    assert decide(major, POLICY) == (Verdict.SUSPECT, 4)


def test_warn_or_skip_is_suspect_and_lowers_ral() -> None:
    assert decide([*all_pass(), chk(1, Status.WARN, Severity.MAJOR)], POLICY) == (
        Verdict.SUSPECT,
        4,
    )
    assert decide(all_pass()[:4], POLICY) == (Verdict.SUSPECT, 4)  # L5 never ran


def test_policy_drives_corrupt_severities() -> None:
    major = [*all_pass(), chk(3, Status.FAIL, Severity.MAJOR)]
    strict = POLICY | {"verdict": {"corrupt_on_fail": ["CRITICAL", "MAJOR"]}}
    assert decide(major, strict)[0] == Verdict.CORRUPT


def test_unknown_severity_in_policy_is_an_error() -> None:
    with pytest.raises(ValueError):
        decide(all_pass(), POLICY | {"verdict": {"corrupt_on_fail": ["FATAL"]}})


def test_report_carries_layers_exit_code_and_reasons() -> None:
    report = build_report("x.gz", [*all_pass(), chk(2, Status.FAIL)], POLICY)
    assert report.verdict == Verdict.CORRUPT and report.exit_code == 2
    assert report.tool.startswith("eguard ")
    assert [lr.layer for lr in report.layers] == [1, 2, 3, 4, 5]
    assert report.reasons == ["L2 l2_fail FAIL: FAIL at L2"]
    assert build_report("x.gz", all_pass(), POLICY).exit_code == 0
