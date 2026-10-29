"""`eguard verify`: one streaming pass over the export; every layer subscribes to that stream."""

from pathlib import Path
from typing import Any

from eguard.container import check_container
from eguard.models import CheckResult, Severity, Status, StreamEnd, VerifyReport
from eguard.stream import Consumer, FanOut, open_decoder
from eguard.verdict import decide

# Layers not built yet are reported as SKIP, so the verdict can never exceed SUSPECT without them.
PENDING_LAYERS = {
    2: ("structure (dump grammar)", 3),
    3: ("row validity", 3),
    4: ("reconciliation", 4),
    5: ("restore drill", 5),
}


class StreamStats(Consumer):
    """Counts decompressed lines; also keeps the line fan-out path exercised end to end."""

    def __init__(self) -> None:
        self.end: StreamEnd | None = None

    def on_line(self, line: bytes, lineno: int) -> None:
        pass

    def on_end(self, end: StreamEnd) -> None:
        self.end = end


def _pending_checks() -> list[CheckResult]:
    return [
        CheckResult(
            layer=layer,
            name=f"l{layer}_pending",
            status=Status.SKIP,
            severity=Severity.INFO,
            evidence={"phase": phase},
            message=f"L{layer} {what} not implemented yet (phase {phase})",
        )
        for layer, (what, phase) in PENDING_LAYERS.items()
    ]


def verify_file(path: Path, policy: dict[str, Any]) -> VerifyReport:
    decoder = open_decoder(path, policy["stream"]["chunk_bytes"])
    fan = FanOut(policy["stream"]["max_line_bytes"])
    fan.subscribe(StreamStats())
    end = fan.run(decoder, is_clean=lambda: decoder.info.error is None)
    checks = check_container(decoder.info, policy)
    checks[0].evidence["decompressed_lines"] = end.lines
    checks += _pending_checks()
    verdict, level = decide(checks)
    return VerifyReport(path=str(path), verdict=verdict, ral=level, checks=checks)
