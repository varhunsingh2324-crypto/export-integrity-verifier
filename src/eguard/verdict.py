"""Verdict engine (IMPLEMENTATION_PLAN §4): checks -> per-layer status -> VERIFIED / SUSPECT /
CORRUPT + RAL 0-5. The rules come from config/policy.yaml `verdict`.

    CORRUPT   a check FAILed whose severity is in `verdict.corrupt_on_fail`
    SUSPECT   no such FAIL, but a layer lacks full evidence (WARN, SKIP, lesser FAIL, no check)
    VERIFIED  every check of every layer PASSed
RAL = number of layers whose checks all PASS (full evidence).
"""

from typing import Any

from eguard import __version__
from eguard.models import CheckResult, LayerResult, Severity, Status, Verdict, VerifyReport

LAYERS = range(1, 6)
LAYER_NAMES = {
    1: "container",
    2: "structure",
    3: "rows",
    4: "reconciliation",
    5: "restore drill",
}


def _corrupt_severities(policy: dict[str, Any]) -> set[Severity]:
    """Policy severities as enum values; an unknown name is a config error, never ignored."""
    return {Severity(s) for s in policy["verdict"]["corrupt_on_fail"]}


def _layer_status(mine: list[CheckResult]) -> Status:
    statuses = {c.status for c in mine}
    if Status.FAIL in statuses:
        return Status.FAIL
    if not mine or statuses == {Status.SKIP}:
        return Status.SKIP
    if statuses != {Status.PASS}:
        return Status.WARN  # a WARN, or PASS mixed with SKIP: partial evidence
    return Status.PASS


def layer_results(checks: list[CheckResult]) -> list[LayerResult]:
    out = []
    for layer in LAYERS:
        mine = [c for c in checks if c.layer == layer]
        status = _layer_status(mine)
        if not mine:
            reason = "no check ran"
        elif status == Status.PASS:
            reason = f"{len(mine)} check(s) PASS"
        else:
            reason = "; ".join(
                f"{c.name} {c.status}: {c.message}" for c in mine if c.status != Status.PASS
            )
        out.append(
            LayerResult(
                layer=layer,
                name=LAYER_NAMES[layer],
                status=status,
                full_evidence=status == Status.PASS,
                checks=len(mine),
                reason=reason,
            )
        )
    return out


def _critical(checks: list[CheckResult], policy: dict[str, Any]) -> list[CheckResult]:
    severities = _corrupt_severities(policy)
    return [c for c in checks if c.status == Status.FAIL and c.severity in severities]


def decide(checks: list[CheckResult], policy: dict[str, Any]) -> tuple[Verdict, int]:
    layers = layer_results(checks)
    level = sum(1 for lr in layers if lr.full_evidence)
    if _critical(checks, policy):
        return Verdict.CORRUPT, level
    if level < len(LAYERS):
        return Verdict.SUSPECT, level
    return Verdict.VERIFIED, level


def explain(checks: list[CheckResult], verdict: Verdict, policy: dict[str, Any]) -> list[str]:
    """Why the verdict is not VERIFIED: the critical failures (CORRUPT), or per layer the checks
    that did not PASS, i.e. the evidence that is missing (SUSPECT)."""
    if verdict == Verdict.CORRUPT:
        return [f"L{c.layer} {c.name} FAIL: {c.message}" for c in _critical(checks, policy)]
    if verdict != Verdict.SUSPECT:
        return []
    reasons: list[str] = []
    for layer in LAYERS:
        mine = [c for c in checks if c.layer == layer]
        if not mine:
            reasons.append(f"L{layer}: no check ran")
        reasons += [
            f"L{layer} {c.name} {c.status}: {c.message}" for c in mine if c.status != Status.PASS
        ]
    return reasons


def build_report(path: str, checks: list[CheckResult], policy: dict[str, Any]) -> VerifyReport:
    verdict, level = decide(checks, policy)
    return VerifyReport(
        path=path,
        tool=f"eguard {__version__}",
        verdict=verdict,
        ral=level,
        exit_code=verdict.exit_code,
        layers=layer_results(checks),
        checks=checks,
        reasons=explain(checks, verdict, policy),
    )
