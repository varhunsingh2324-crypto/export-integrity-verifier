"""Verdict engine (IMPLEMENTATION_PLAN §4): checks -> VERIFIED / SUSPECT / CORRUPT + RAL 0-5.

Minimal rules from §4; phase 6 adds policy-driven refinements.
"""

from eguard.models import CheckResult, Severity, Status, Verdict

LAYERS = range(1, 6)


def ral(checks: list[CheckResult]) -> int:
    """Recoverability Assurance Level: layers whose checks all PASS (full evidence)."""
    return sum(
        1
        for layer in LAYERS
        if (mine := [c for c in checks if c.layer == layer])
        and all(c.status == Status.PASS for c in mine)
    )


def decide(checks: list[CheckResult]) -> tuple[Verdict, int]:
    if any(c.status == Status.FAIL and c.severity == Severity.CRITICAL for c in checks):
        return Verdict.CORRUPT, ral(checks)
    covered = {c.layer for c in checks}
    if any(c.status != Status.PASS for c in checks) or not set(LAYERS) <= covered:
        return Verdict.SUSPECT, ral(checks)
    return Verdict.VERIFIED, ral(checks)


def explain(checks: list[CheckResult], verdict: Verdict) -> list[str]:
    """Why the verdict is not VERIFIED: the critical failures (CORRUPT), or per layer the checks
    that did not PASS, i.e. the evidence that is missing (SUSPECT)."""
    if verdict == Verdict.CORRUPT:
        return [
            f"L{c.layer} {c.name} FAIL: {c.message}"
            for c in checks
            if c.status == Status.FAIL and c.severity == Severity.CRITICAL
        ]
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
